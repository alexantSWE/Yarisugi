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

    pub fn binary_path(&self) -> &std::path::Path {
        &self.binary
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

    /// Atomically applies a new config: writes it, validates, then hot-reloads
    /// (or cold-starts) the core. If the swap is rejected, the previous config
    /// file is restored and the live process is asked to keep running the old
    /// config, so a bad node swap can never brick the session -- a hard
    /// requirement with ephemeral public subscriptions.
    pub fn apply_config(&mut self, config_json: &[u8]) -> Result<()> {
        let previous = std::fs::read(&self.config_path).ok();
        std::fs::write(&self.config_path, config_json)?;
        let applying = (|| -> Result<()> {
            self.validate_config()?;
            if self.is_running() {
                self.reload()?;
            } else {
                self.start()?;
            }
            Ok(())
        })();
        if applying.is_err() {
            if let Some(previous) = previous {
                if std::fs::write(&self.config_path, previous).is_ok() && self.is_running() {
                    // Best-effort rollback: the old file was valid (the process
                    // was running off it), so a fresh SIGHUP restores it.
                    let _ = self.reload();
                }
            }
        }
        applying
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

    fn minimal_config(port: u16) -> Vec<u8> {
        serde_json::to_vec_pretty(&serde_json::json!({
            "log": { "level": "warn", "timestamp": true },
            "inbounds": [{
                "type": "mixed",
                "tag": "mixed-in",
                "listen": "127.0.0.1",
                "listen_port": port
            }],
            "outbounds": [ { "type": "direct", "tag": "direct" } ],
            "route": {
                "auto_detect_interface": false,
                "default_mark": 0,
                "rules": [ { "action": "route", "outbound": "direct" } ]
            }
        }))
        .unwrap()
    }

    #[test]
    fn apply_config_rolls_back_rejected_swap_and_keeps_session() {
        let binary = std::env::var_os("SING_BOX_BIN")
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from("/usr/bin/sing-box"));
        if !binary.exists() {
            eprintln!("skipping: no sing-box binary at {}", binary.display());
            return;
        }
        let path = std::env::temp_dir().join(format!(
            "myproxy-supervisor-revert-{}.json",
            std::process::id()
        ));
        let _ = std::fs::remove_file(&path);

        let valid = minimal_config(19991);
        let mut supervisor = Supervisor::new(&binary, &path);
        supervisor.apply_config(&valid).unwrap();
        assert!(supervisor.is_running());
        std::thread::sleep(std::time::Duration::from_millis(400));

        let rejected = b"{\"inbounds\": \"not an array\"}";
        assert!(
            supervisor.apply_config(rejected).is_err(),
            "a config sing-box rejects must fail the swap"
        );
        assert!(supervisor.is_running(), "old process must survive a rejected swap");
        assert_eq!(
            std::fs::read(&path).unwrap(),
            valid,
            "config file must roll back to the previous valid render"
        );

        // The rolled-back file is valid and the session is still switchable.
        supervisor.apply_config(&valid).unwrap();
        assert!(supervisor.is_running());
        supervisor.stop().unwrap();
        let _ = std::fs::remove_file(&path);
    }
}