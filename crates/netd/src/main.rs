use anyhow::{bail, Context, Result};
use futures_util::{SinkExt, StreamExt};
use ipnet::Ipv4Net;
use myproxy_netd_proto::{
    NetdRequest, NetdResponse, DEFAULT_SOCKET_PATH, HEARTBEAT_INTERVAL_SECS, MAX_FRAME_BYTES,
    PROTOCOL_VERSION, WATCHDOG_TIMEOUT_SECS,
};
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;
use tokio::net::{UnixListener, UnixStream};
use tokio::sync::Mutex;
use tokio::time::Instant;
use tokio_util::codec::{FramedRead, FramedWrite, LengthDelimitedCodec};
use tracing::{error, info, warn};

#[derive(Debug, Clone, PartialEq, Eq)]
struct RoutingConfig {
    tproxy_port: u16,
    proxy_fwmark: u32,
    table_id: u32,
    dns_ipv4: Option<std::net::Ipv4Addr>,
    bypass_subnets: Vec<Ipv4Net>,
}

#[derive(Debug)]
struct DaemonState {
    active_session: Option<u64>,
    routing_active: bool,
    last_heartbeat: Instant,
    routing_config: Option<RoutingConfig>,
}

#[derive(Clone, Default)]
struct NoopBackend;

impl NoopBackend {
    async fn enable(&self, _config: &RoutingConfig) -> Result<()> {
        Ok(())
    }

    async fn disable(&self, _config: Option<&RoutingConfig>) -> Result<()> {
        Ok(())
    }
}

#[derive(Clone)]
struct AppState {
    state: Arc<Mutex<DaemonState>>,
    backend: NoopBackend,
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter("info")
        .try_init()
        .ok();

    if !nix_is_root() {
        bail!("myproxy-netd must run as root or with equivalent network capabilities");
    }

    let socket_path = socket_path();
    prepare_socket(&socket_path)?;
    let listener = UnixListener::bind(&socket_path)
        .with_context(|| format!("failed to bind {}", socket_path.display()))?;
    std::fs::set_permissions(&socket_path, std::fs::Permissions::from_mode(0o660))?;

    let app = AppState {
        state: Arc::new(Mutex::new(DaemonState {
            active_session: None,
            routing_active: false,
            last_heartbeat: Instant::now(),
            routing_config: None,
        })),
        backend: NoopBackend,
    };

    info!(socket = %socket_path.display(), "myproxy-netd control plane ready");
    spawn_watchdog(app.clone());

    loop {
        let (stream, _) = listener.accept().await.context("accept failed")?;
        let client = app.clone();
        tokio::spawn(async move {
            if let Err(error) = handle_client(stream, client).await {
                warn!(?error, "client session ended with an error");
            }
        });
    }
}

fn spawn_watchdog(app: AppState) {
    tokio::spawn(async move {
        let interval = Duration::from_secs(HEARTBEAT_INTERVAL_SECS.min(1));
        loop {
            tokio::time::sleep(interval).await;
            let expired = {
                let state = app.state.lock().await;
                state.routing_active
                    && state.last_heartbeat.elapsed() > Duration::from_secs(WATCHDOG_TIMEOUT_SECS)
            };
            if expired {
                warn!("heartbeat watchdog expired; rolling back routing");
                if let Err(error) = rollback(&app).await {
                    error!(?error, "watchdog rollback failed");
                }
            }
        }
    });
}

async fn handle_client(stream: UnixStream, app: AppState) -> Result<()> {
    let credentials = stream
        .peer_cred()
        .context("could not read peer credentials")?;
    authorize_uid(credentials.uid())?;

    let (reader, writer) = stream.into_split();
    let mut reader = FramedRead::new(reader, bounded_codec());
    let mut writer = FramedWrite::new(writer, bounded_codec());

    let first = reader
        .next()
        .await
        .ok_or_else(|| anyhow::anyhow!("client closed before handshake"))??;
    let request: NetdRequest = bincode::deserialize(&first).context("invalid handshake frame")?;
    let session_id = match request {
        NetdRequest::Handshake { client_version } if client_version == PROTOCOL_VERSION => {
            allocate_session(&app).await?
        }
        NetdRequest::Handshake { .. } => bail!("protocol version mismatch"),
        _ => bail!("handshake is required before other requests"),
    };
    send_response(
        &mut writer,
        NetdResponse::HandshakeOk {
            daemon_version: PROTOCOL_VERSION,
            session_id,
        },
    )
    .await?;

    while let Some(frame) = reader.next().await {
        let frame = frame?;
        let request: NetdRequest = bincode::deserialize(&frame).context("invalid request frame")?;
        let response = match process_request(request, session_id, &app).await {
            Ok(response) => response,
            Err(error) => NetdResponse::Error(error.to_string()),
        };
        send_response(&mut writer, response).await?;
    }

    let should_rollback = {
        let state = app.state.lock().await;
        state.active_session == Some(session_id) && state.routing_active
    };
    if should_rollback {
        warn!(session_id, "controller disconnected; rolling back routing");
        rollback(&app).await?;
    } else {
        release_session(&app, session_id).await;
    }
    Ok(())
}

async fn process_request(
    request: NetdRequest,
    session_id: u64,
    app: &AppState,
) -> Result<NetdResponse> {
    match request {
        NetdRequest::EnableRouting {
            session_id: request_session,
            tproxy_port,
            proxy_fwmark,
            table_id,
            dns_ipv4,
            bypass_subnets,
        } => {
            require_controller(request_session, session_id)?;
            let config = validate_config(
                tproxy_port,
                proxy_fwmark,
                table_id,
                dns_ipv4,
                bypass_subnets,
            )?;
            claim_controller(app, session_id).await?;
            if let Err(error) = app.backend.enable(&config).await {
                release_session(app, session_id).await;
                return Err(error);
            }
            let mut state = app.state.lock().await;
            state.routing_active = true;
            state.last_heartbeat = Instant::now();
            state.routing_config = Some(config);
            Ok(NetdResponse::RoutingEnabled)
        }
        NetdRequest::DisableRouting {
            session_id: request_session,
        } => {
            require_controller(request_session, session_id)?;
            rollback(app).await?;
            Ok(NetdResponse::RoutingDisabled)
        }
        NetdRequest::Heartbeat {
            session_id: request_session,
            sequence,
        } => {
            require_controller(request_session, session_id)?;
            let mut state = app.state.lock().await;
            state.last_heartbeat = Instant::now();
            Ok(NetdResponse::HeartbeatAck { sequence })
        }
        NetdRequest::Handshake { .. } => bail!("handshake may only be sent once"),
    }
}

async fn rollback(app: &AppState) -> Result<()> {
    let config = {
        let state = app.state.lock().await;
        state.routing_config.clone()
    };
    app.backend.disable(config.as_ref()).await?;
    let mut state = app.state.lock().await;
    state.routing_active = false;
    state.routing_config = None;
    state.active_session = None;
    Ok(())
}

async fn allocate_session(_app: &AppState) -> Result<u64> {
    Ok(next_session_id())
}

async fn claim_controller(app: &AppState, session_id: u64) -> Result<()> {
    let mut state = app.state.lock().await;
    if state.active_session.is_some() && state.active_session != Some(session_id) {
        bail!("another controller session is already active");
    }
    state.active_session = Some(session_id);
    state.last_heartbeat = Instant::now();
    Ok(())
}

async fn release_session(app: &AppState, session_id: u64) {
    let mut state = app.state.lock().await;
    if state.active_session == Some(session_id) {
        state.active_session = None;
    }
}

fn require_controller(request_session: u64, connection_session: u64) -> Result<()> {
    if request_session != connection_session {
        bail!("session does not own the controller");
    }
    Ok(())
}

fn validate_config(
    tproxy_port: u16,
    proxy_fwmark: u32,
    table_id: u32,
    dns_ipv4: Option<std::net::Ipv4Addr>,
    bypass_subnets: Vec<String>,
) -> Result<RoutingConfig> {
    if !(1024..=65535).contains(&tproxy_port) {
        bail!("tproxy port must be between 1024 and 65535");
    }
    if proxy_fwmark == 0 || proxy_fwmark == u32::MAX {
        bail!("proxy firewall mark is outside the supported range");
    }
    if !(1..=252).contains(&table_id) {
        bail!("routing table must be between 1 and 252");
    }
    if let Some(address) = dns_ipv4 {
        if address.is_unspecified() || address.is_multicast() || address.is_broadcast() {
            bail!("DNS address is not routable");
        }
    }
    if bypass_subnets.len() > 256 {
        bail!("too many bypass subnets");
    }
    let mut parsed = Vec::with_capacity(bypass_subnets.len());
    for subnet in bypass_subnets {
        let network: Ipv4Net = subnet
            .parse()
            .with_context(|| format!("invalid IPv4 subnet: {subnet}"))?;
        if network.prefix_len() == 0 {
            bail!("the default route cannot be a bypass subnet");
        }
        parsed.push(network);
    }
    Ok(RoutingConfig {
        tproxy_port,
        proxy_fwmark,
        table_id,
        dns_ipv4,
        bypass_subnets: parsed,
    })
}

fn authorize_uid(uid: u32) -> Result<()> {
    if uid == 0 {
        return Ok(());
    }
    let configured = std::env::var("MYPROXY_NETD_ALLOWED_UID")
        .context("MYPROXY_NETD_ALLOWED_UID must be configured for non-root clients")?;
    let allowed: u32 = configured
        .parse()
        .context("MYPROXY_NETD_ALLOWED_UID is not numeric")?;
    if uid != allowed {
        bail!("client UID is not authorized");
    }
    Ok(())
}

fn bounded_codec() -> LengthDelimitedCodec {
    let mut codec = LengthDelimitedCodec::new();
    codec.set_max_frame_length(MAX_FRAME_BYTES);
    codec
}

async fn send_response(
    writer: &mut FramedWrite<tokio::net::unix::OwnedWriteHalf, LengthDelimitedCodec>,
    response: NetdResponse,
) -> Result<()> {
    writer.send(bincode::serialize(&response)?.into()).await?;
    Ok(())
}

fn prepare_socket(path: &Path) -> Result<()> {
    if path.exists() {
        std::fs::remove_file(path)
            .with_context(|| format!("failed to remove {}", path.display()))?;
    }
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
        std::fs::set_permissions(parent, std::fs::Permissions::from_mode(0o750))?;
    }
    Ok(())
}

fn socket_path() -> PathBuf {
    std::env::var_os("MYPROXY_NETD_SOCKET")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(DEFAULT_SOCKET_PATH))
}

fn next_session_id() -> u64 {
    use std::sync::atomic::{AtomicU64, Ordering};
    static NEXT: AtomicU64 = AtomicU64::new(1);
    NEXT.fetch_add(1, Ordering::Relaxed)
}

fn nix_is_root() -> bool {
    unsafe { libc::geteuid() == 0 }
}

#[cfg(test)]
mod tests {
    use super::validate_config;

    #[test]
    fn rejects_default_bypass() {
        let result = validate_config(12345, 1, 100, None, vec!["0.0.0.0/0".into()]);
        assert!(result.is_err());
    }

    #[test]
    fn accepts_bounded_config() {
        let result = validate_config(12345, 0x1, 100, None, vec!["192.168.0.0/16".into()]);
        assert!(result.is_ok());
    }
}
