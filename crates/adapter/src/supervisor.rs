use anyhow::{bail, Context, Result};
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};

/// Lifecycle management for a sing-box child process: validate the config
/// before applying it, hot-reload via SIGHUP after revalidation, and shut the
/// core down cleanly. Spawning is only exercised against a real binary; the
/// command construction and validation failure paths are unit-tested.
pub struct Supervisor {
    binary: PathBuf,
    config_path: PathBuf,
    child: Option<Child>,
}

impl Supervisor {
    pub fn new(binary: impl Into<PathBuf>, config_path: impl Into<PathBuf>) -> Self {
        Self {
            binary: binary.into(),
            config_path: config_path.into(),
            child: None,
        }
    }

    pub fn config_path(&self) -> &std::path::Path {
        &self.config_path
    }

    fn check_command(&self) -> Command {
        let mut command = Command::new(&self.binary);
        command
            .arg("check")
            .arg("-c")
            .arg(&self.config_path)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        command
    }

    /// Runs `sing-box check` on the current config. This is the gate that
    /// prevents a bad swap from ever reaching the live process.
    pub fn validate_config(&self) -> Result<()> {
        let output = self
            .check_command()
            .output()
            .with_context(|| {
                format!(
                    "failed to run `{} check -c {}`",
                    self.binary.display(),
                    self.config_path.display()
                )
            })?;
        if !output.status.success() {
            bail!(
                "sing-box rejected the config: {}",
                String::from_utf8_lossy(&output.stderr).trim()
            );
        }
        Ok(())
    }

    /// Validates the config, then spawns the core with `run -c <config>`.
    pub fn start(&mut self) -> Result<()> {
        self.validate_config()?;
        let child = Command::new(&self.binary)
            .arg("run")
            .arg("-c")
            .arg(&self.config_path)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::inherit())
            .spawn()
            .with_context(|| format!("failed to spawn `{}`", self.binary.display()))?;
        self.child = Some(child);
        Ok(())
    }

    /// Revalidates and then requests an in-place reload with SIGHUP, which
    /// sing-box honors by reloading outbounds without dropping the process.
    pub fn reload(&mut self) -> Result<()> {
        self.validate_config()?;
        let Some(child) = self.child.as_mut() else {
            bail!("core is not running");
        };
        let pid = child.id() as libc::pid_t;
        let rc = unsafe { libc::kill(pid, libc::SIGHUP) };
        if rc != 0 {
            bail!(
                "failed to signal SIGHUP to pid {pid}: {}",
                std::io::Error::last_os_error()
            );
        }
        Ok(())
    }

    pub fn stop(&mut self) -> Result<()> {
        if let Some(mut child) = self.child.take() {
            let _ = unsafe { libc::kill(child.id() as libc::pid_t, libc::SIGTERM) };
            let _ = child.wait();
        }
        Ok(())
    }

    pub fn is_running(&self) -> bool {
        self.child.is_some()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validation_fails_loudly_when_binary_is_missing() {
        let supervisor = Supervisor::new(
            "/nonexistent/sing-box",
            std::env::temp_dir().join("myproxy-adapter").join("config.json"),
        );
        assert!(supervisor.validate_config().is_err());
    }

    #[test]
    fn reload_requires_a_running_child() {
        let mut supervisor = Supervisor::new(
            "/nonexistent/sing-box",
            std::env::temp_dir().join("myproxy-adapter").join("config.json"),
        );
        assert!(!supervisor.is_running());
        assert!(supervisor.reload().is_err());
    }
}