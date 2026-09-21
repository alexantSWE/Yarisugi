//! Blocking client for the netd daemon protocol. The daemon speaks the
//! `myproxy_netd_proto` message set over a unix stream framed with
//! `tokio_util::codec::LengthDelimitedCodec` (u32 big-endian length prefix) and
//! bincode payloads; this client mirrors that framing with plain sockets so it
//! needs no async runtime in the GUI/controller process.
//!
//! A `NetdClient` holds a single connection and transparently re-establishes it
//! (new handshake, new session id) when the daemon restarts, which keeps the
//! firewall ruleset tied to the live daemon session.

use anyhow::{bail, Context, Result};
use myproxy_netd_proto::{
    NetdRequest, NetdResponse, HEARTBEAT_INTERVAL_SECS, MAX_FRAME_BYTES,
};
use std::io::{Read, Write};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Duration;

const CONNECT_TIMEOUT: Duration = Duration::from_secs(2);
const RESPONSE_TIMEOUT: Duration = Duration::from_secs(3);

/// The routing parameters for a single `EnableRouting` round trip. Session id
/// is supplied by the client; everything else comes from user configuration.
#[derive(Debug, Clone)]
pub struct RoutingSpec {
    pub tproxy_port: u16,
    pub fwmark: u32,
    pub table_id: u32,
    pub dns_ipv4: Option<std::net::Ipv4Addr>,
    pub bypass_subnets: Vec<String>,
    pub bypass_subnets_v6: Vec<String>,
    pub core_uid: Option<u32>,
}

struct ClientInner {
    stream: Option<UnixStream>,
    session_id: u64,
    sequence: u64,
}

pub struct NetdClient {
    socket_path: PathBuf,
    version: u32,
    inner: Mutex<ClientInner>,
}

impl NetdClient {
    /// Connects and completes the version handshake. Fails only if the daemon
    /// is unreachable or speaks an incompatible protocol.
    pub fn new(socket_path: impl Into<PathBuf>, client_version: u32) -> Result<Self> {
        let client = Self {
            socket_path: socket_path.into(),
            version: client_version,
            inner: Mutex::new(ClientInner {
                stream: None,
                session_id: 0,
                sequence: 0,
            }),
        };
        client.reconnect()?;
        Ok(client)
    }

    pub fn session_id(&self) -> Result<u64> {
        Ok(self.lock().session_id)
    }

    /// (Re)establishes the connection and performs a fresh handshake. The old
    /// stream, if any, is discarded and a new session id is adopted from the
    /// daemon.
    pub fn reconnect(&self) -> Result<()> {
        let mut guard = self.lock();
        let mut attempt = 0;
        let (stream, session_id) = loop {
            match handshake(&self.socket_path, self.version, CONNECT_TIMEOUT) {
                Ok(handshake) => break handshake,
                Err(error) => {
                    attempt += 1;
                    if attempt >= 3 {
                        return Err(error.context("reconnect + handshake failed"));
                    }
                    std::thread::sleep(Duration::from_millis(250));
                }
            }
        };
        guard.stream = Some(stream);
        guard.session_id = session_id;
        Ok(())
    }

    pub fn enable_routing(&self, spec: &RoutingSpec) -> Result<()> {
        let guard = self.lock();
        let request = NetdRequest::EnableRouting {
            session_id: guard.session_id,
            tproxy_port: spec.tproxy_port,
            proxy_fwmark: spec.fwmark,
            table_id: spec.table_id,
            dns_ipv4: spec.dns_ipv4,
            bypass_subnets: spec.bypass_subnets.clone(),
            bypass_subnets_v6: spec.bypass_subnets_v6.clone(),
            core_uid: spec.core_uid,
        };
        match self.send_locked(&guard, request) {
            Ok(NetdResponse::RoutingEnabled) => Ok(()),
            Ok(NetdResponse::Error(message)) => bail!("netd: {message}"),
            Ok(other) => bail!("unexpected netd reply to EnableRouting: {other:?}"),
            Err(error) => Err(error.context("netd enable_routing")),
        }
    }

    pub fn disable_routing(&self) -> Result<()> {
        let guard = self.lock();
        let request = NetdRequest::DisableRouting {
            session_id: guard.session_id,
        };
        match self.send_locked(&guard, request) {
            Ok(NetdResponse::RoutingDisabled) => Ok(()),
            Ok(NetdResponse::Error(message)) => bail!("netd: {message}"),
            Ok(other) => bail!("unexpected netd reply to DisableRouting: {other:?}"),
            Err(error) => Err(error.context("netd disable_routing")),
        }
    }

    /// Sends a heartbeat and returns the sequence the daemon acknowledged.
    pub fn heartbeat(&self) -> Result<u64> {
        let mut guard = self.lock();
        let sequence = guard.sequence;
        let counted = guard.sequence.wrapping_add(1);
        let request = NetdRequest::Heartbeat {
            session_id: guard.session_id,
            sequence,
        };
        let result = self.send_locked(&guard, request);
        if result.is_ok() {
            guard.sequence = counted;
        }
        match result {
            Ok(NetdResponse::HeartbeatAck { sequence: acked }) => Ok(acked),
            Ok(NetdResponse::Error(message)) => bail!("netd: {message}"),
            Ok(other) => bail!("unexpected netd reply to Heartbeat: {other:?}"),
            Err(error) => Err(error.context("netd heartbeat")),
        }
    }

    /// Background heartbeat task: keeps the daemon watchdog fed while the
    /// connection is healthy, and reconnects when the daemon restarts. Runs
    /// until the returned handle is dropped.
    pub fn start_heartbeat(self: &Arc<Self>) -> std::thread::JoinHandle<()> {
        let client = Arc::clone(self);
        std::thread::spawn(move || loop {
            std::thread::sleep(Duration::from_secs(HEARTBEAT_INTERVAL_SECS));
            if client.heartbeat().is_err() && client.reconnect().is_err() {
                // Daemon still down; retry on the next interval.
            }
        })
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, ClientInner> {
        self.inner.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    fn send_locked(
        &self,
        guard: &std::sync::MutexGuard<'_, ClientInner>,
        request: NetdRequest,
    ) -> Result<NetdResponse> {
        let Some(stream) = guard.stream.as_ref() else {
            bail!("netd connection is closed");
        };
        let mut stream = stream.try_clone().context("clone netd stream")?;
        stream.set_read_timeout(Some(RESPONSE_TIMEOUT))?;
        stream.set_write_timeout(Some(RESPONSE_TIMEOUT))?;
        write_frame(&mut stream, &request).context("send request")?;
        read_response(&mut stream).context("read response")
    }
}

/// Connects, sends the handshake, and returns `(stream, session_id)`.
fn handshake(
    socket_path: &Path,
    client_version: u32,
    timeout: Duration,
) -> Result<(UnixStream, u64)> {
    let mut stream = UnixStream::connect(socket_path)?;
    stream.set_read_timeout(Some(timeout))?;
    stream.set_write_timeout(Some(timeout))?;
    write_frame(&mut stream, &NetdRequest::Handshake { client_version })?;
    match read_response(&mut stream)? {
        NetdResponse::HandshakeOk {
            session_id,
            ..
        } => Ok((stream, session_id)),
        NetdResponse::Error(message) => bail!("netd rejected handshake: {message}"),
        other => bail!("unexpected handshake reply: {other:?}"),
    }
}

fn write_frame(stream: &mut UnixStream, request: &NetdRequest) -> Result<()> {
    let payload = bincode::serialize(request)?;
    let length = if payload.len() > MAX_FRAME_BYTES {
        bail!("request frame too large: {} bytes", payload.len());
    } else {
        payload.len()
    };
    stream.write_all(&(length as u32).to_be_bytes())?;
    stream.write_all(&payload)?;
    stream.flush()?;
    Ok(())
}

fn read_response(stream: &mut UnixStream) -> Result<NetdResponse> {
    let mut length = [0u8; 4];
    stream.read_exact(&mut length)?;
    let length = u32::from_be_bytes(length) as usize;
    if length == 0 || length > MAX_FRAME_BYTES {
        bail!("invalid netd frame length {length}");
    }
    let mut payload = vec![0u8; length];
    stream.read_exact(&mut payload)?;
    bincode::deserialize(&payload).context("invalid netd response payload")
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};
    use myproxy_netd_proto::{
        DEFAULT_SOCKET_PATH, PROTOCOL_VERSION, WATCHDOG_TIMEOUT_SECS,
    };
    use std::os::unix::net::UnixListener;
    use std::sync::mpsc;

    /// A minimal in-process netd daemon handling one connection: handshake,
    /// then EnableRouting with the exact spec forwarded from the caller.
    fn fake_netd(
        socket_path: &Path,
        forwarded: mpsc::Sender<NetdRequest>,
        max_connections: u32,
    ) -> std::thread::JoinHandle<()> {
        let socket_path = socket_path.to_path_buf();
        std::thread::spawn(move || {
            if let Some(path) = socket_path.parent() {
                std::fs::create_dir_all(path).unwrap();
            }
            let _ = std::fs::remove_file(&socket_path);
            let listener = UnixListener::bind(&socket_path).unwrap();
            let mut served: u32 = 0;
            loop {
                let Ok((stream, _)) = listener.accept() else { break };
                thread_stream(stream, &forwarded);
                served += 1;
                if served >= max_connections {
                    break;
                }
            }
        })
    }

    fn thread_stream(mut stream: UnixStream, forwarded: &mpsc::Sender<NetdRequest>) {
        loop {
            let Ok(Some(request)) = read_request(&mut stream) else { break };
            let _ = forwarded.send(request.clone());
            let response = match request {
                NetdRequest::Handshake { .. } => NetdResponse::HandshakeOk {
                    daemon_version: PROTOCOL_VERSION,
                    session_id: 42,
                },
                NetdRequest::EnableRouting { .. } => NetdResponse::RoutingEnabled,
                NetdRequest::DisableRouting { .. } => NetdResponse::RoutingDisabled,
                NetdRequest::Heartbeat { sequence, .. } => {
                    NetdResponse::HeartbeatAck { sequence }
                }
            };
            if write_response(&mut stream, &response).is_err() {
                break;
            }
        }
    }

    fn read_request(stream: &mut UnixStream) -> Result<Option<NetdRequest>> {
        let mut length = [0u8; 4];
        match stream.read_exact(&mut length) {
            Ok(()) => {
                let length = u32::from_be_bytes(length) as usize;
                if length == 0 || length > MAX_FRAME_BYTES {
                    bail!("bad frame length");
                }
                let mut payload = vec![0u8; length];
                stream.read_exact(&mut payload)?;
                Ok(Some(bincode::deserialize(&payload)?))
            }
            Err(_) => Ok(None),
        }
    }

    fn write_response(stream: &mut UnixStream, response: &NetdResponse) -> Result<()> {
        let payload = bincode::serialize(response)?;
        stream.write_all(&(payload.len() as u32).to_be_bytes())?;
        stream.write_all(&payload)?;
        stream.flush()?;
        Ok(())
    }

    fn temp_socket() -> PathBuf {
        std::env::temp_dir().join(format!(
            "myproxy-netd-test-{}-{:03}.sock",
            std::process::id(),
            rand_seq()
        ))
    }

    fn rand_seq() -> u32 {
        static COUNTER: AtomicU64 = AtomicU64::new(0);
        COUNTER.fetch_add(1, Ordering::Relaxed) as u32
    }

    #[test]
    fn client_handshakes_and_routes_with_fake_daemon() {
        let socket = temp_socket();
        let (server_requests, received) = mpsc::channel();
        let handle = fake_netd(&socket, server_requests, 1u32);

        let client = NetdClient::new(&socket, PROTOCOL_VERSION).unwrap();
        assert_eq!(client.session_id().unwrap(), 42, "session id from handshake");

        let spec = RoutingSpec {
            tproxy_port: 12345,
            fwmark: 0x1,
            table_id: 100,
            dns_ipv4: Some("1.1.1.1".parse().unwrap()),
            bypass_subnets: vec!["192.168.0.0/16".into()],
            bypass_subnets_v6: vec![],
            core_uid: None,
        };
        client.enable_routing(&spec).unwrap();
        client.disable_routing().unwrap();
        let acked = client.heartbeat().unwrap();
        assert_eq!(acked, 0, "first heartbeat sequence");

        drop(client);
        handle.join().unwrap();

        let requests = received.iter().collect::<Vec<_>>();
        assert!(matches!(&requests[0], NetdRequest::Handshake { client_version } if *client_version == PROTOCOL_VERSION));
        let NetdRequest::EnableRouting {
            session_id,
            tproxy_port,
            proxy_fwmark,
            dns_ipv4,
            bypass_subnets,
            ..
        } = &requests[1]
        else {
            panic!("expected EnableRouting, got {:?}", requests[1]);
        };
        assert_eq!(*session_id, 42);
        assert_eq!(*tproxy_port, 12345);
        assert_eq!(*proxy_fwmark, 0x1);
        assert_eq!(*dns_ipv4, Some("1.1.1.1".parse().unwrap()));
        assert_eq!(bypass_subnets, &vec!["192.168.0.0/16".to_string()]);
        let _ = WATCHDOG_TIMEOUT_SECS;
        let _ = DEFAULT_SOCKET_PATH;
    }

    #[test]
    fn new_fails_loudly_when_daemon_is_down() {
        let socket = temp_socket();
        let error = NetdClient::new(&socket, PROTOCOL_VERSION).err().expect("must fail");
        assert!(
            format!("{error:#}").to_lowercase().contains("connect") ||
                format!("{error:#}").contains("handshake"),
            "error: {error:#}"
        );
    }
}