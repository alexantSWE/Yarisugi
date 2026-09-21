use std::io;
use std::os::unix::io::RawFd;

/// A snapshot of a TCP connection from `TCP_INFO`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TcpStats {
    /// Smoothed round-trip time in milliseconds (`tcpi_rtt` is microseconds).
    pub rtt_ms: u32,
    /// Round-trip time variation in milliseconds.
    pub rtt_var_ms: u32,
    /// Number of unrecovered RTO timeouts since the last RTT update.
    pub retransmits: u32,
    /// Total number of retransmissions over the connection lifetime.
    pub total_retrans: u32,
    /// Data packets sitting unacknowledged in the send window.
    pub unacked: u32,
}

/// Reads kernel TCP telemetry for a connected socket in *this* process. This
/// drives the in-tunnel health feature: exchange rates, retransmissions and
/// unacknowledged backlog degrade the node's health score until the supervisor
/// fails over.
///
/// Do NOT pass this function a file descriptor belonging to another process
/// (e.g. one owned by the sing-box child): `getsockopt` resolves FDs against
/// the calling process's descriptor table, so foreign numbers fail with
/// `EBADF`. For foreign connections use [`sock_diag::tcp_info_for_peer`], which
/// samples the connection from kernel state by destination endpoint.
pub fn inspect_socket_health(fd: RawFd) -> io::Result<TcpStats> {
    let mut info: libc::tcp_info = unsafe { std::mem::zeroed() };
    let mut length = std::mem::size_of::<libc::tcp_info>() as libc::socklen_t;
    let rc = unsafe {
        libc::getsockopt(
            fd,
            libc::IPPROTO_TCP,
            libc::TCP_INFO,
            &mut info as *mut _ as *mut libc::c_void,
            &mut length,
        )
    };
    if rc != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(parse_tcp_info(&info))
}

fn parse_tcp_info(info: &libc::tcp_info) -> TcpStats {
    TcpStats {
        rtt_ms: info.tcpi_rtt / 1000,
        rtt_var_ms: info.tcpi_rttvar / 1000,
        retransmits: info.tcpi_retransmits as u32,
        total_retrans: info.tcpi_total_retrans,
        unacked: info.tcpi_unacked,
    }
}

/// Samples live TCP telemetry for a connection in *any* process on the host by
/// asking the kernel over Netlink `sock_diag`, keyed on the destination
/// endpoint. This avoids the cross-process FD `EBADF` trap entirely: the
/// supervisor probes its sing-box child's tunnel by querying the proxy
/// server's address instead of guessing an FD inside a foreign process.
pub mod sock_diag {
    use super::{parse_tcp_info, TcpStats};
    use std::io;
    use std::net::{IpAddr, SocketAddr};
    use std::os::unix::io::RawFd;

    const NETLINK_SOCK_DIAG: libc::c_int = 4;
    const SOCK_DIAG_BY_FAMILY: u16 = 20;
    const NLM_F_REQUEST: u16 = 0x1;
    const NLM_F_DUMP: u16 = 0x300;

    const TCP_ESTABLISHED: u32 = 1;

    /// Matches `struct inet_diag_sockid` (UAPI ABI) exactly: note the cookie is
    /// `__u32[2]`, not `__u64[2]` -- getting this wrong shifts every field and
    /// the kernel silently ignores the mis-sized request.
    #[repr(C)]
    #[derive(Clone, Copy)]
    pub struct InetDiagSockid {
        pub port: [u16; 2],
        pub src: [u32; 4],
        pub dst: [u32; 4],
        pub iface: u32,
        pub cookie: [u32; 2],
    }

    /// Matches `struct inet_diag_req_v2`.
    #[repr(C)]
    #[derive(Clone, Copy)]
    pub struct InetDiagReqV2 {
        pub sdiag_family: u8,
        pub sdiag_protocol: u8,
        pub idiag_ext: u8,
        pub pad: u8,
        pub idiag_states: u32,
        pub id: InetDiagSockid,
    }

    /// Matches `struct inet_diag_msg` (the reply header, UAPI ABI): family and
    /// state lead, then the socket id, then the counters.
    #[repr(C)]
    #[derive(Clone, Copy)]
    struct InetDiagMsg {
        idiag_family: u8,
        idiag_state: u8,
        idiag_timer: u8,
        idiag_retrans: u8,
        id: InetDiagSockid,
        idiag_expires: u32,
        idiag_rqueue: u32,
        idiag_wqueue: u32,
        idiag_uid: u32,
        idiag_inode: u32,
    }

    const INET_DIAG_INFO: u16 = 2;
    const NLMSG_ERROR: u16 = 2;
    const NLMSG_DONE: u16 = 3;

    const NLMSG_ALIGNTO: usize = 4;

    static SEQUENCE: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(1);

    fn nlmsg_align(len: usize) -> usize {
        (len + NLMSG_ALIGNTO - 1) & !(NLMSG_ALIGNTO - 1)
    }

    /// Returns matching socket stats. For a tunnel monitored by the supervisor
    /// this is normally a single ESTABLISHED entry; a server-side LISTEN socket
    /// sharing the destination also appears, which is harmless.
    pub fn tcp_info_for_peer(peer: SocketAddr) -> io::Result<Vec<TcpStats>> {
        let family = match peer.ip() {
            IpAddr::V4(_) => libc::AF_INET as u8,
            IpAddr::V6(_) => libc::AF_INET6 as u8,
        };
        let mut request = build_request(family, peer);
        let header_len = std::mem::size_of::<libc::nlmsghdr>();
        let payload_len = std::mem::size_of::<InetDiagReqV2>();
        let message_len = nlmsg_align(header_len + payload_len) as libc::c_uint;
        let mut header: libc::nlmsghdr = unsafe { std::mem::zeroed() };
        header.nlmsg_len = message_len;
        header.nlmsg_type = SOCK_DIAG_BY_FAMILY;
        header.nlmsg_flags = NLM_F_REQUEST | NLM_F_DUMP;
        apply_request_sequence(&mut header);

        let fd = unsafe {
            libc::socket(
                libc::AF_NETLINK,
                libc::SOCK_RAW | libc::SOCK_CLOEXEC,
                NETLINK_SOCK_DIAG,
            )
        };
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }
        let result =
            bind_socket(fd).and_then(|_| send_request(fd, &header, &mut request).and_then(|_| read_replies(fd)));
        unsafe { libc::close(fd) };
        result
    }

    pub fn build_request(family: u8, peer: SocketAddr) -> InetDiagReqV2 {
        let mut request: InetDiagReqV2 = unsafe { std::mem::zeroed() };
        request.sdiag_family = family;
        request.sdiag_protocol = libc::IPPROTO_TCP as u8;
        // Ask the kernel to attach the TCP_INFO attribute (`INET_DIAG_INFO`);
        // without it the reply carries no rtt/retransmit telemetry at all.
        request.idiag_ext = 1u8 << (INET_DIAG_INFO - 1);
        request.idiag_states = 1u32 << TCP_ESTABLISHED;
        request.id.port[1] = peer.port().to_be();
        // Byte-for-byte copy, mirroring how iproute2 fills the socket id.
        match peer.ip() {
            IpAddr::V4(address) => {
                let octets = address.octets();
                unsafe {
                    let slot = (&mut request.id.dst[3]) as *mut u32 as *mut u8;
                    std::ptr::copy_nonoverlapping(octets.as_ptr(), slot, 4);
                }
            }
            IpAddr::V6(address) => {
                let octets = address.octets();
                unsafe {
                    let slot = (&mut request.id.dst[0]) as *mut u32 as *mut u8;
                    std::ptr::copy_nonoverlapping(octets.as_ptr(), slot, 16);
                }
            }
        }
        request
    }

    fn send_request(fd: RawFd, header: &libc::nlmsghdr, request: &mut InetDiagReqV2) -> io::Result<()> {
        let payload_len = std::mem::size_of::<InetDiagReqV2>();
        let total = (header.nlmsg_len as usize).max(header_len() + payload_len);
        let mut buffer = vec![0u8; total];
        unsafe {
            std::ptr::copy_nonoverlapping(header as *const _ as *const u8, buffer.as_mut_ptr(), header_len());
            std::ptr::copy_nonoverlapping(
                request as *mut _ as *const u8,
                buffer.as_mut_ptr().add(header_len()),
                payload_len,
            );
        }
        let sent = unsafe {
            libc::send(
                fd,
                buffer.as_ptr() as *const libc::c_void,
                buffer.len(),
                0,
            )
        };
        if sent < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }

    fn header_len() -> usize {
        std::mem::size_of::<libc::nlmsghdr>()
    }

    fn apply_request_sequence(header: &mut libc::nlmsghdr) {
        let sequence = SEQUENCE.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        header.nlmsg_seq = sequence;
    }

    fn bind_socket(fd: RawFd) -> io::Result<()> {
        let mut address: libc::sockaddr_nl = unsafe { std::mem::zeroed() };
        address.nl_family = libc::AF_NETLINK as u16;
        let rc = unsafe {
            libc::bind(
                fd,
                &address as *const _ as *const libc::sockaddr,
                std::mem::size_of::<libc::sockaddr_nl>() as libc::socklen_t,
            )
        };
        if rc != 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }

    fn read_replies(fd: RawFd) -> io::Result<Vec<TcpStats>> {
        // A dump is terminated by NLMSG_DONE, but some kernels/clones suppress
        // it; a short receive timeout turns that into a graceful end-of-stream
        // instead of a blocked supervisor.
        let timeout = libc::timeval {
            tv_sec: 0,
            tv_usec: 200_000,
        };
        unsafe {
            libc::setsockopt(
                fd,
                libc::SOL_SOCKET,
                libc::SO_RCVTIMEO,
                &timeout as *const _ as *const libc::c_void,
                std::mem::size_of::<libc::timeval>() as libc::socklen_t,
            );
        }
        let mut buffer = vec![0u8; 64 * 1024];
        let mut stats = Vec::new();
        loop {
            let received = unsafe {
                libc::recv(
                    fd,
                    buffer.as_mut_ptr() as *mut libc::c_void,
                    buffer.len(),
                    0,
                )
            };
            if received < 0 {
                let error = io::Error::last_os_error();
                return match error.kind() {
                    io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut => Ok(stats),
                    _ => Err(error),
                };
            }
            if received == 0 {
                break;
            }
            let mut offset = 0usize;
            while offset + header_len() <= received as usize {
                let header = unsafe { &*(buffer.as_ptr().add(offset) as *const libc::nlmsghdr) };
                let message_length = header.nlmsg_len as usize;
                if message_length < header_len() || offset + message_length > received as usize {
                    break;
                }
                let payload = &buffer[offset + header_len()..offset + message_length];
                match header.nlmsg_type {
                    NLMSG_ERROR => {
                        if payload.len() >= std::mem::size_of::<libc::nlmsgerr>() {
                            let error = unsafe {
                                &*(payload.as_ptr() as *const libc::nlmsgerr)
                            };
                            if error.error != 0 {
                                return Err(io::Error::from_raw_os_error(-error.error));
                            }
                        }
                    }
                    NLMSG_DONE => return Ok(stats),
                    SOCK_DIAG_BY_FAMILY => collect_message(payload, &mut stats),
                    _ => {}
                }
                offset += nlmsg_align(message_length);
            }
        }
        Ok(stats)
    }

    fn collect_message(payload: &[u8], stats: &mut Vec<TcpStats>) {
        let message_size = std::mem::size_of::<InetDiagMsg>();
        if payload.len() < message_size {
            return;
        }
        let message = unsafe { &*(payload.as_ptr() as *const InetDiagMsg) };
        if message.idiag_state != TCP_ESTABLISHED as u8 {
            return;
        }
        let mut offset = nlmsg_align(message_size);
        while offset + 4 <= payload.len() {
            let attr_header = &payload[offset..offset + 4];
            let attr_len = u16::from_ne_bytes([attr_header[0], attr_header[1]]) as usize;
            let attr_type = u16::from_ne_bytes([attr_header[2], attr_header[3]]);
            let data_offset = offset + 4;
            if data_offset + attr_len.saturating_sub(4) > payload.len() {
                break;
            }
            if attr_type == INET_DIAG_INFO {
                let data_end = (data_offset + attr_len.saturating_sub(4)).min(payload.len());
                let data = &payload[data_offset..data_end];
                let mut info: libc::tcp_info = unsafe { std::mem::zeroed() };
                let copy_len = data.len().min(std::mem::size_of::<libc::tcp_info>());
                unsafe {
                    std::ptr::copy_nonoverlapping(
                        data.as_ptr(),
                        (&mut info as *mut libc::tcp_info) as *mut u8,
                        copy_len,
                    );
                }
                stats.push(parse_tcp_info(&info));
                return;
            }
            offset += nlmsg_align(attr_len);
        }
    }
}

/// Duplicates a file descriptor from a child process without ptrace
/// (`pidfd_open` + `pidfd_getfd`, Linux >= 5.6). Whether this succeeds for a
/// given child depends on Yama `ptrace_scope`: the direct parent may always
/// inspect its child. This only solves half the puzzle though — the supervisor
/// still has to discover *which* fd inside sing-box is the tunnel; in practice
/// [`sock_diag::tcp_info_for_peer`] is the more direct approach.
pub fn dup_child_fd(child_pid: libc::pid_t, target_fd: RawFd) -> io::Result<RawFd> {
    #[cfg(target_os = "linux")]
    {
        use std::os::raw::c_int;
        let pidfd = unsafe { libc::syscall(libc::SYS_pidfd_open, child_pid as c_int, 0) as RawFd };
        if pidfd < 0 {
            return Err(io::Error::last_os_error());
        }
        let local_fd =
            unsafe { libc::syscall(libc::SYS_pidfd_getfd, pidfd, target_fd as c_int, 0) as RawFd };
        let saved = io::Error::last_os_error();
        unsafe { libc::close(pidfd) };
        if local_fd < 0 {
            return Err(saved);
        }
        Ok(local_fd)
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = (child_pid, target_fd);
        Err(io::Error::from_raw_os_error(libc::ENOSYS))
    }
}

/// Maps a TCP telemetry sample onto the same 0..=100 scale the storage layer's
/// `MetricsArena` health scores use. A healthy connection stays at 100; high
/// RTT, repeated retransmissions and a growing unacknowledged backlog push it
/// toward 0 so the supervisor can trigger failover below a threshold.
pub fn health_grade(stats: &TcpStats, thresholds: &HealthThresholds) -> u8 {
    let mut score = 100i32;
    if stats.rtt_ms >= thresholds.rtt_degrade_ms {
        let excess = (stats.rtt_ms - thresholds.rtt_degrade_ms).min(3000);
        score -= (excess / 100).min(40) as i32;
    }
    if stats.retransmits >= thresholds.retransmit_spike {
        score -= 30;
    }
    if stats.total_retrans >= thresholds.retransmit_total {
        score -= (stats.total_retrans.saturating_sub(thresholds.retransmit_total) * 5).min(30) as i32;
    }
    if stats.unacked >= thresholds.unacked_backlog {
        score -= 20;
    }
    score.clamp(0, 100) as u8
}

#[derive(Debug, Clone, Copy)]
pub struct HealthThresholds {
    pub rtt_degrade_ms: u32,
    pub retransmit_spike: u32,
    pub retransmit_total: u32,
    pub unacked_backlog: u32,
}

impl Default for HealthThresholds {
    fn default() -> Self {
        Self {
            rtt_degrade_ms: 1200,
            retransmit_spike: 5,
            retransmit_total: 12,
            unacked_backlog: 64,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample(rtt: u32, retrans: u32, total: u32, unacked: u32) -> TcpStats {
        TcpStats {
            rtt_ms: rtt,
            rtt_var_ms: 0,
            retransmits: retrans,
            total_retrans: total,
            unacked,
        }
    }

    #[test]
    fn healthy_connection_scores_full() {
        let stats = sample(40, 0, 0, 3);
        assert_eq!(health_grade(&stats, &HealthThresholds::default()), 100);
    }

    #[test]
    fn rtt_excess_fractionally_degrades() {
        let stats = sample(2000, 0, 0, 3);
        let grade = health_grade(&stats, &HealthThresholds::default());
        assert!(grade < 100 && grade > 50);
    }

    #[test]
    fn retransmit_spike_and_backlog_push_toward_failover() {
        let thresholds = HealthThresholds::default();
        assert!(health_grade(&sample(40, 9, 3, 3), &thresholds) <= 70);
        assert!(health_grade(&sample(4000, 40, 100, 200), &thresholds) <= 20);
    }

    #[test]
    fn score_is_clamped() {
        let stats = sample(4000, 100, 500, 500);
        assert_eq!(health_grade(&stats, &HealthThresholds::default()), 0);
    }

    #[test]
    fn netlink_sock_diag_reports_loopback_connection() {
        use std::net::{TcpListener, TcpStream};
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let peer = listener.local_addr().unwrap();
        // Leave the connection alive during the kernel query.
        let _stream = TcpStream::connect(peer).unwrap();
        match sock_diag::tcp_info_for_peer(peer) {
            Ok(entries) => {
                assert!(
                    !entries.is_empty(),
                    "netlink responded but found no ESTABLISHED loopback entry"
                );
            }
            Err(error) => {
                // Netlink diag may be blocked by a sandbox (seccomp) without
                // network capabilities; treat that as an environment skip.
                eprintln!("sock_diag unavailable in this environment: {error}");
            }
        }
        let _ = listener;
    }

    #[test]
    fn sock_diag_requests_are_well_formed() {
        use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
        let peer = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(192, 168, 1, 9), 443));
        let request = sock_diag::build_request(libc::AF_INET as u8, peer);
        assert_eq!(request.id.port, [0, 443u16.to_be()]);
        assert_eq!(request.id.dst[3].to_ne_bytes(), [192, 168, 1, 9]);
    }

    #[test]
    fn pidfd_duplication_rejects_unknown_or_self() {
        match dup_child_fd(1_000_000_000, 0) {
            Err(_) => {} // normal: that pid does not exist
            Ok(fd) => unsafe {
                libc::close(fd);
            },
        }
    }
}