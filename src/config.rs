use serde::Deserialize;
use std::path::PathBuf;

fn default_threshold() -> usize {
    5
}
fn default_window_secs() -> u64 {
    600
}
fn default_ban_secs() -> u64 {
    3600
}

/// One log source to watch. Just `sshd` for now — an array, not a single
/// field, so adding a second watched service later (a web server's auth
/// log, say) doesn't need a schema change.
#[derive(Deserialize, Debug, Clone)]
pub struct WatchConfig {
    pub service: String,
}

#[derive(Deserialize, Debug, Clone)]
pub struct AppConfig {
    /// Failures within `window_secs` before an IP gets banned.
    #[serde(default = "default_threshold")]
    pub threshold: usize,
    /// The sliding window, in seconds, failures are counted over.
    #[serde(default = "default_window_secs")]
    pub window_secs: u64,
    /// How long a ban lasts, in seconds, before nftables auto-expires it.
    #[serde(default = "default_ban_secs")]
    pub ban_secs: u64,
    /// Extra IPs/CIDRs to never ban, on top of the hardcoded loopback and
    /// private-range exclusion (see `detector::is_never_bannable`, which
    /// cannot be overridden by this config either way).
    #[serde(default)]
    pub allowlist: Vec<String>,
    #[serde(default = "default_watch")]
    pub watch: Vec<WatchConfig>,
}

fn default_watch() -> Vec<WatchConfig> {
    vec![WatchConfig {
        service: "sshd".to_string(),
    }]
}

pub fn default_config_path() -> Option<PathBuf> {
    let config_home = std::env::var("XDG_CONFIG_HOME")
        .map(PathBuf::from)
        .or_else(|_| std::env::var("HOME").map(|h| PathBuf::from(h).join(".config")))
        .ok()?;
    let candidates = [
        config_home.join("vortexwall").join("config.toml"),
        PathBuf::from("config.toml"),
    ];
    candidates.into_iter().find(|p| p.exists())
}

pub fn load(path: &std::path::Path) -> Result<AppConfig, String> {
    let raw = std::fs::read_to_string(path)
        .map_err(|e| format!("failed to read {}: {}", path.display(), e))?;
    toml::from_str(&raw).map_err(|e| format!("failed to parse {}: {}", path.display(), e))
}

/// Fail fast on config problems that would otherwise silently do nothing
/// at runtime, with no error or warning anywhere. `threshold: 0` is the
/// real trap: `FailureTracker::record` always pushes a failure before
/// checking `entry.len() == self.threshold`, so `entry.len()` is never
/// `0` after a call -- `threshold = 0` doesn't ban on every failure, it
/// silently never bans anything at all. `window_secs`/`ban_secs` of `0`
/// are the equivalent silent no-ops (a window that closes instantly
/// never accumulates failures; a ban that expires instantly is never
/// really a ban).
pub fn validate(cfg: &AppConfig) -> Result<(), String> {
    if cfg.threshold == 0 {
        return Err("threshold must be at least 1 (0 silently never bans anything)".to_string());
    }
    if cfg.window_secs == 0 {
        return Err(
            "window_secs must be at least 1 (0 silently never accumulates failures)".to_string(),
        );
    }
    if cfg.ban_secs == 0 {
        return Err("ban_secs must be at least 1 (0 silently expires a ban instantly)".to_string());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn valid_config() -> AppConfig {
        AppConfig {
            threshold: 5,
            window_secs: 600,
            ban_secs: 3600,
            allowlist: vec![],
            watch: default_watch(),
        }
    }

    #[test]
    fn validate_accepts_a_normal_config() {
        assert!(validate(&valid_config()).is_ok());
    }

    #[test]
    fn validate_rejects_zero_threshold() {
        let mut cfg = valid_config();
        cfg.threshold = 0;
        assert!(validate(&cfg).is_err());
    }

    #[test]
    fn validate_rejects_zero_window_secs() {
        let mut cfg = valid_config();
        cfg.window_secs = 0;
        assert!(validate(&cfg).is_err());
    }

    #[test]
    fn validate_rejects_zero_ban_secs() {
        let mut cfg = valid_config();
        cfg.ban_secs = 0;
        assert!(validate(&cfg).is_err());
    }
}
