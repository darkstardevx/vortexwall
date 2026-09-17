mod config;
mod detector;
mod nft;

use clap::Parser;
use std::net::IpAddr;
use std::process::ExitCode;
use std::time::{Duration, Instant};
use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::process::Command as TokioCommand;
use tokio::sync::mpsc;

#[derive(Parser, Debug)]
#[command(
    name = "vortexwall",
    version = "0.1.0",
    about = "Watches auth logs and actively blackholes offending IPs via nftables"
)]
struct Args {
    /// Path to config.toml. Defaults to $XDG_CONFIG_HOME/vortexwall/config.toml,
    /// then ~/.config/vortexwall/config.toml, then ./config.toml.
    #[arg(short, long)]
    config: Option<std::path::PathBuf>,

    /// Detect and log what *would* be banned without ever touching nftables.
    /// Always start here on a new box or after changing thresholds.
    #[arg(long)]
    dry_run: bool,

    // --- systemd service control ---
    #[arg(long)]
    admin: bool,
    #[arg(long, requires = "admin")]
    start: bool,
    #[arg(long, requires = "admin")]
    stop: bool,
    #[arg(long, requires = "admin")]
    restart: bool,
    #[arg(long, requires = "admin")]
    status: bool,

    // --- nftables management, independent of the systemd service ---
    /// List currently banned IPs and exit.
    #[arg(long)]
    bans: bool,
    /// Remove one IP's ban immediately and exit.
    #[arg(long, value_name = "IP")]
    unban: Option<String>,
    /// Remove the entire vortexwall nftables table — every rule, every
    /// ban, gone — and exit. This is the "kill it" command.
    #[arg(long)]
    teardown: bool,

    /// Create the nftables table/set/chain (idempotent) and exit, without
    /// starting the log-watching loop. For testing the firewall mechanism
    /// in isolation.
    #[arg(long)]
    setup: bool,

    /// Ban one IP immediately and exit, bypassing log detection entirely.
    /// For testing the ban mechanism against a safe, non-real address —
    /// refuses anything in detector::is_never_bannable (loopback/private).
    #[arg(long, value_name = "IP")]
    test_ban: Option<String>,
}

/// Exactly one of `start`/`stop`/`restart`/`status` must be set. Split out
/// from `run_admin` so this selection logic is testable without touching
/// `Command`/process spawning.
fn resolve_admin_action(
    start: bool,
    stop: bool,
    restart: bool,
    status: bool,
) -> Result<&'static str, &'static str> {
    match (start, stop, restart, status) {
        (true, false, false, false) => Ok("start"),
        (false, true, false, false) => Ok("stop"),
        (false, false, true, false) => Ok("restart"),
        (false, false, false, true) => Ok("status"),
        (false, false, false, false) => {
            Err("--admin needs exactly one of --start, --stop, --restart, --status")
        }
        _ => Err("--admin takes exactly one of --start, --stop, --restart, --status, not several at once"),
    }
}

fn run_admin(args: &Args) -> std::io::Result<i32> {
    let action = match resolve_admin_action(args.start, args.stop, args.restart, args.status) {
        Ok(action) => action,
        Err(msg) => {
            eprintln!("{msg}");
            return Ok(1);
        }
    };

    let mut cmd = if action == "status" {
        let mut c = std::process::Command::new("systemctl");
        c.arg("status");
        c
    } else {
        let mut c = std::process::Command::new("sudo");
        c.args(["systemctl", action]);
        c
    };
    cmd.arg("vortexwall");

    use std::io::Write;
    let prefix = if action == "status" { "" } else { "sudo " };
    println!("[admin] running: {}systemctl {} vortexwall", prefix, action);
    std::io::stdout().flush()?;
    let status = cmd.status()?;
    Ok(status.code().unwrap_or(1))
}

/// Tails one systemd unit's journal, sending each detected offender IP
/// down `tx`. Runs until the journalctl process itself exits (which
/// shouldn't happen under `-f` short of the process being killed).
async fn watch_service(service: String, tx: mpsc::Sender<IpAddr>) {
    loop {
        println!("[watch] tailing journal for {service}");
        let child = TokioCommand::new("journalctl")
            .args(["-f", "-u", &service, "-o", "cat", "--since", "now"])
            .stdout(std::process::Stdio::piped())
            .spawn();

        let mut child = match child {
            Ok(c) => c,
            Err(e) => {
                eprintln!("[watch] failed to spawn journalctl for {service}: {e}");
                tokio::time::sleep(Duration::from_secs(10)).await;
                continue;
            }
        };

        let stdout = child.stdout.take().expect("journalctl stdout was piped");
        let mut lines = BufReader::new(stdout).lines();

        while let Ok(Some(line)) = lines.next_line().await {
            if let Some(ip) = detector::extract_offender(&line) {
                let _ = tx.send(ip).await;
            }
        }

        eprintln!("[watch] journalctl for {service} exited — restarting in 10s");
        tokio::time::sleep(Duration::from_secs(10)).await;
    }
}

async fn run_daemon(args: Args) -> std::io::Result<()> {
    let config_path = args.config.or_else(config::default_config_path).ok_or_else(|| {
        std::io::Error::new(std::io::ErrorKind::NotFound, "No config found (checked --config, $XDG_CONFIG_HOME/vortexwall, ~/.config/vortexwall, ./config.toml) — using built-in defaults")
    });

    let cfg = match config_path {
        Ok(path) => config::load(&path)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?,
        Err(_) => {
            println!("[Configuration] No config file found — running with built-in defaults");
            config::AppConfig {
                threshold: 5,
                window_secs: 600,
                ban_secs: 3600,
                allowlist: vec![],
                watch: vec![config::WatchConfig {
                    service: "sshd".to_string(),
                }],
            }
        }
    };

    config::validate(&cfg).map_err(|e| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("Config error: {e}"),
        )
    })?;

    println!(
        "[Configuration] threshold={} window={}s ban_duration={}s dry_run={} watching={:?}",
        cfg.threshold,
        cfg.window_secs,
        cfg.ban_secs,
        args.dry_run,
        cfg.watch.iter().map(|w| &w.service).collect::<Vec<_>>()
    );

    if args.dry_run {
        println!("[nftables] dry-run — skipping table setup, nothing will be touched");
    } else {
        nft::setup()?;
        println!("[nftables] table ready (inet vortexwall)");
    }

    let allowlist: Vec<IpAddr> = cfg
        .allowlist
        .iter()
        .filter_map(|s| s.parse().ok())
        .collect();
    if allowlist.len() != cfg.allowlist.len() {
        eprintln!("[Configuration] warning: some allowlist entries didn't parse as plain IPs (CIDR ranges aren't supported yet) and were ignored");
    }

    let (tx, mut rx) = mpsc::channel::<IpAddr>(256);
    for w in &cfg.watch {
        tokio::spawn(watch_service(w.service.clone(), tx.clone()));
    }
    drop(tx); // the loop below exits if all watchers die AND drop their senders

    let mut tracker =
        detector::FailureTracker::new(Duration::from_secs(cfg.window_secs), cfg.threshold);
    let ban_duration = Duration::from_secs(cfg.ban_secs);

    while let Some(ip) = rx.recv().await {
        if detector::is_never_bannable(&ip) {
            // Doesn't even enter the tracker — a private/loopback address
            // failing auth repeatedly is noise (or you, fat-fingering a
            // password on your own LAN), never a ban candidate.
            println!("[protected] {ip} had an auth failure but is loopback/private — never a ban candidate");
            continue;
        }
        if allowlist.contains(&ip) {
            continue;
        }

        if tracker.record(ip, Instant::now()) {
            if args.dry_run {
                println!(
                    "[DRY-RUN] would ban {ip} for {}s (threshold {} reached)",
                    cfg.ban_secs, cfg.threshold
                );
            } else {
                match nft::ban(ip, ban_duration) {
                    Ok(()) => println!(
                        "[BANNED] {ip} for {}s (threshold {} reached)",
                        cfg.ban_secs, cfg.threshold
                    ),
                    Err(e) => eprintln!("[ERROR] failed to ban {ip}: {e}"),
                }
            }
            tracker.forget(&ip);
        }
    }

    Ok(())
}

#[tokio::main]
async fn main() -> ExitCode {
    let args = Args::parse();

    if args.admin {
        return match run_admin(&args) {
            Ok(code) => ExitCode::from(code as u8),
            Err(e) => {
                eprintln!("[admin] error: {e}");
                ExitCode::FAILURE
            }
        };
    }

    if args.teardown {
        return match nft::teardown() {
            Ok(()) => {
                println!("[teardown] inet vortexwall table removed — every rule and ban is gone");
                ExitCode::SUCCESS
            }
            Err(e) => {
                eprintln!("[teardown] failed: {e}");
                ExitCode::FAILURE
            }
        };
    }

    if args.setup {
        return match nft::setup() {
            Ok(()) => {
                println!("[setup] inet vortexwall table ready");
                ExitCode::SUCCESS
            }
            Err(e) => {
                eprintln!("[setup] failed: {e}");
                ExitCode::FAILURE
            }
        };
    }

    if let Some(ip_str) = &args.test_ban {
        let ip: IpAddr = match ip_str.parse() {
            Ok(ip) => ip,
            Err(_) => {
                eprintln!("[test-ban] not a valid IP address: {ip_str}");
                return ExitCode::FAILURE;
            }
        };
        if detector::is_never_bannable(&ip) {
            eprintln!("[test-ban] refusing — {ip} is loopback or a private range, never bannable");
            return ExitCode::FAILURE;
        }
        return match nft::ban(ip, Duration::from_secs(60)) {
            Ok(()) => {
                println!("[test-ban] {ip} banned for 60s — check with --bans, or `nft list set inet vortexwall blackhole`");
                ExitCode::SUCCESS
            }
            Err(e) => {
                eprintln!("[test-ban] failed: {e}");
                ExitCode::FAILURE
            }
        };
    }

    if args.bans {
        return match nft::list_banned() {
            Ok(ips) if ips.is_empty() => {
                println!("No IPs currently banned.");
                ExitCode::SUCCESS
            }
            Ok(ips) => {
                for ip in ips {
                    println!("{ip}");
                }
                ExitCode::SUCCESS
            }
            Err(e) => {
                eprintln!("[bans] failed to list: {e}");
                ExitCode::FAILURE
            }
        };
    }

    if let Some(ip_str) = &args.unban {
        let ip: IpAddr = match ip_str.parse() {
            Ok(ip) => ip,
            Err(_) => {
                eprintln!("[unban] not a valid IP address: {ip_str}");
                return ExitCode::FAILURE;
            }
        };
        return match nft::unban(ip) {
            Ok(()) => {
                println!("[unban] {ip} removed");
                ExitCode::SUCCESS
            }
            Err(e) => {
                eprintln!("[unban] failed: {e}");
                ExitCode::FAILURE
            }
        };
    }

    match run_daemon(args).await {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("[Critical Failure] {e}");
            ExitCode::FAILURE
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resolve_admin_action_maps_each_single_flag() {
        assert_eq!(resolve_admin_action(true, false, false, false), Ok("start"));
        assert_eq!(resolve_admin_action(false, true, false, false), Ok("stop"));
        assert_eq!(
            resolve_admin_action(false, false, true, false),
            Ok("restart")
        );
        assert_eq!(
            resolve_admin_action(false, false, false, true),
            Ok("status")
        );
    }

    #[test]
    fn resolve_admin_action_rejects_no_flags_and_multiple_flags() {
        assert!(resolve_admin_action(false, false, false, false).is_err());
        assert!(resolve_admin_action(true, true, false, false).is_err());
    }
}
