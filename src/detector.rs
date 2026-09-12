//! Turns raw journal lines into ban decisions: regex-match known auth-failure
//! patterns, extract the source IP, track a sliding per-IP failure window,
//! and decide when a threshold's been crossed. No I/O here — `nft`
//! shell-outs and journal tailing live in their own modules so this stays
//! trivially unit-testable.

use regex::Regex;
use std::collections::{HashMap, VecDeque};
use std::net::IpAddr;
use std::sync::OnceLock;
use std::time::{Duration, Instant};

/// sshd log lines that indicate a failed/rejected auth attempt, each with
/// one capture group named `ip`. More patterns (more services) can be
/// added here without touching anything else.
fn patterns() -> &'static [Regex] {
    static PATTERNS: OnceLock<Vec<Regex>> = OnceLock::new();
    PATTERNS.get_or_init(|| {
        [
            r"Failed password for .* from (?P<ip>[0-9a-fA-F:.]+) port \d+",
            r"Invalid user .* from (?P<ip>[0-9a-fA-F:.]+) port \d+",
            r"Connection closed by (?:invalid user .* |authenticating user .* )?(?P<ip>[0-9a-fA-F:.]+) port \d+ \[preauth\]",
            r"Received disconnect from (?P<ip>[0-9a-fA-F:.]+) port \d+:\d+:.*\[preauth\]",
        ]
        .iter()
        .map(|p| Regex::new(p).expect("hardcoded regex must compile"))
        .collect()
    })
}

/// Extract a source IP from one journal line, if it matches a known
/// auth-failure pattern. `None` for lines that don't indicate a failure
/// (successful logins, informational lines, anything else).
pub fn extract_offender(line: &str) -> Option<IpAddr> {
    for re in patterns() {
        if let Some(caps) = re.captures(line) {
            if let Some(ip_str) = caps.name("ip") {
                if let Ok(ip) = ip_str.as_str().parse::<IpAddr>() {
                    return Some(ip);
                }
            }
        }
    }
    None
}

/// True for loopback and every RFC1918/RFC4193 private range. These can
/// never be banned, full stop, regardless of what's in the config —
/// they're the ranges every LAN this box has ever been on (home, a
/// neighbor's, a library) uses, so banning one is banning a network you're
/// physically on right now.
pub fn is_never_bannable(ip: &IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => v4.is_loopback() || v4.is_private() || v4.is_link_local(),
        IpAddr::V6(v6) => v6.is_loopback() || (v6.segments()[0] & 0xfe00) == 0xfc00, // fc00::/7 (ULA)
    }
}

/// Sliding-window per-IP failure tracker. `record()` returns `true` the
/// moment an IP crosses the threshold — the caller bans on that edge, not
/// on every subsequent failure from an already-banned IP.
pub struct FailureTracker {
    window: Duration,
    threshold: usize,
    history: HashMap<IpAddr, VecDeque<Instant>>,
}

impl FailureTracker {
    pub fn new(window: Duration, threshold: usize) -> Self {
        Self { window, threshold, history: HashMap::new() }
    }

    /// Record one failure for `ip` at `now`. Returns `true` exactly once
    /// per ban-worthy streak — the transition from "under threshold" to
    /// "at or over threshold" within the window.
    pub fn record(&mut self, ip: IpAddr, now: Instant) -> bool {
        let entry = self.history.entry(ip).or_default();
        entry.push_back(now);
        while let Some(&front) = entry.front() {
            if now.duration_since(front) > self.window {
                entry.pop_front();
            } else {
                break;
            }
        }
        entry.len() == self.threshold
    }

    /// Drop tracking state for an IP — call this once it's actually been
    /// banned, so a stale count doesn't linger after the ban itself
    /// expires in nftables.
    pub fn forget(&mut self, ip: &IpAddr) {
        self.history.remove(ip);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extracts_ip_from_failed_password() {
        let line = "sshd[1234]: Failed password for root from 198.51.100.7 port 51422 ssh2";
        assert_eq!(extract_offender(line), Some("198.51.100.7".parse().unwrap()));
    }

    #[test]
    fn extracts_ip_from_invalid_user() {
        let line = "sshd[1234]: Invalid user admin from 203.0.113.9 port 33000";
        assert_eq!(extract_offender(line), Some("203.0.113.9".parse().unwrap()));
    }

    #[test]
    fn extracts_ip_from_preauth_disconnect() {
        let line = "sshd[1234]: Connection closed by invalid user test 192.0.2.5 port 44000 [preauth]";
        assert_eq!(extract_offender(line), Some("192.0.2.5".parse().unwrap()));
    }

    // Captured verbatim from this system's real journal (Arch Linux,
    // openssh's sshd-session split, 2026-09-12) — not a synthetic guess at
    // the format. sshd-session's actual output differs slightly from
    // classic monolithic sshd (e.g. omits "port"'s preceding "from" on the
    // preauth-disconnect line), which is exactly the kind of drift a
    // memory-written regex can miss.
    #[test]
    fn matches_real_invalid_user_line() {
        let line = "Invalid user nonexistentuser123 from 127.0.0.1 port 51164";
        assert_eq!(extract_offender(line), Some("127.0.0.1".parse().unwrap()));
    }

    #[test]
    fn matches_real_preauth_disconnect_line() {
        let line = "Connection closed by invalid user nonexistentuser123 127.0.0.1 port 51164 [preauth]";
        assert_eq!(extract_offender(line), Some("127.0.0.1".parse().unwrap()));
    }

    #[test]
    fn ignores_unrelated_lines() {
        let line = "sshd[1234]: Accepted publickey for raven from 198.51.100.7 port 51422 ssh2";
        assert_eq!(extract_offender(line), None);
    }

    #[test]
    fn loopback_and_private_ranges_never_bannable() {
        for ip in ["127.0.0.1", "10.1.2.3", "172.16.5.5", "192.168.1.50", "169.254.1.1", "::1"] {
            let ip: IpAddr = ip.parse().unwrap();
            assert!(is_never_bannable(&ip), "{ip} should be protected");
        }
        for ip in ["198.51.100.7", "203.0.113.9", "8.8.8.8"] {
            let ip: IpAddr = ip.parse().unwrap();
            assert!(!is_never_bannable(&ip), "{ip} should NOT be protected");
        }
    }

    #[test]
    fn tracker_fires_exactly_once_at_threshold() {
        let mut tracker = FailureTracker::new(Duration::from_secs(600), 3);
        let ip: IpAddr = "198.51.100.7".parse().unwrap();
        let t0 = Instant::now();
        assert!(!tracker.record(ip, t0));
        assert!(!tracker.record(ip, t0));
        assert!(tracker.record(ip, t0)); // 3rd failure crosses threshold=3
        assert!(!tracker.record(ip, t0)); // 4th: already over, no re-fire
    }

    #[test]
    fn tracker_prunes_outside_window() {
        let mut tracker = FailureTracker::new(Duration::from_secs(10), 2);
        let ip: IpAddr = "198.51.100.7".parse().unwrap();
        let t0 = Instant::now();
        assert!(!tracker.record(ip, t0));
        // second failure long after the window closed — should NOT combine
        // with the first to cross the threshold
        let t1 = t0 + Duration::from_secs(30);
        assert!(!tracker.record(ip, t1));
    }

    #[test]
    fn forget_resets_the_count() {
        let mut tracker = FailureTracker::new(Duration::from_secs(600), 2);
        let ip: IpAddr = "198.51.100.7".parse().unwrap();
        let t0 = Instant::now();
        assert!(!tracker.record(ip, t0)); // 1st, under threshold=2
        assert!(tracker.record(ip, t0)); // 2nd, crosses threshold=2
        tracker.forget(&ip);
        assert!(!tracker.record(ip, t0)); // restarted from zero -> back to 1, under threshold
    }
}
