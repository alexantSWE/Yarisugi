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

/// Reads kernel TCP telemetry for a connected socket. This drives the in-tunnel
/// health feature: exchange rates, retransmissions and unacknowledged backlog
/// degrade the node's health score until the supervisor fails over.
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
    Ok(TcpStats {
        rtt_ms: info.tcpi_rtt / 1000,
        rtt_var_ms: info.tcpi_rttvar / 1000,
        retransmits: info.tcpi_retransmits as u32,
        total_retrans: info.tcpi_total_retrans,
        unacked: info.tcpi_unacked,
    })
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
}