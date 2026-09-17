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
