# 🌀 VortexWall

`Rust` · `nftables` · `systemd`

**Active-blackholing firewall.** Tails auth logs, tracks per-IP failures in
a sliding window, and drops the offender at the network level — before
connection tracking even runs — once a threshold is crossed. Not a
replacement for a real firewall (`ufw` handles that baseline); this is the
"actively respond to bad behavior" layer on top of it.

## 🚀 What it does

- Tails `journalctl -f -u <service>` for auth-failure patterns (v1: `sshd` only)
- Sliding-window per-IP failure tracking — N failures within a window, not just a raw count
- Bans via a dedicated `inet vortexwall` nftables table — separate from `ufw`'s own tables, no conflict
- Bans **auto-expire** via nftables' native set timeouts — no cleanup thread, no orphaned rules if the daemon dies
- **Loopback and every private range (RFC1918 + link-local + IPv6 ULA) are hardcoded-unbannable**, regardless of config — can't be overridden, can't accidentally lock out a LAN you're on
- `--dry-run`: full detection pipeline, zero nftables writes, zero root required — the way to validate real-traffic behavior with no risk

## 🧩 Why a separate nftables table, not `ufw` rules

This box's `iptables` is actually the `nf_tables` kernel backend already
(`iptables v1.8.13 (nf_tables)`), so `ufw`'s rules and VortexWall's rules
both ultimately run through nftables — as two independent tables, evaluated
by hook priority. VortexWall's `prerouting` chain runs at priority `-300`
(the "raw" tier), ahead of `ufw`'s filter-tier rules — a banned IP is
dropped before it's even connection-tracked.

## ⚙️ Configuration

`~/.config/vortexwall/config.toml`:

```toml
threshold = 5        # failures within window_secs before a ban
window_secs = 600    # sliding window
ban_secs = 3600      # ban duration — nftables auto-expires it
allowlist = []        # exact IPs to never ban (no CIDR yet), on top of the
                      # hardcoded loopback/private exclusion

[[watch]]
service = "sshd"
```

## ▶️ Running

```bash
cargo build --release
vortexwall --dry-run              # detect + log only, no root needed, no nftables writes
vortexwall                        # real enforcement — needs CAP_NET_ADMIN (or root)
```

### CLI reference

| Flag | What it does |
|---|---|
| `--dry-run` | Run the daemon, log what *would* be banned, never touch nftables |
| `--setup` | Create the nftables table/set/chain and exit (idempotent) |
| `--test-ban <ip>` | Ban one IP immediately, bypassing log detection — refuses loopback/private ranges. For testing the mechanism against a safe address (RFC 5737 documentation ranges: `192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24`) |
| `--bans` | List currently-banned IPs |
| `--unban <ip>` | Remove one ban immediately |
| `--teardown` | **Remove the entire table** — every rule, every ban, gone |
| `--admin --start/--stop/--restart/--status` | Wraps `systemctl`, same pattern as WraithFlow |

### As a service

```bash
systemctl status vortexwall
journalctl -u vortexwall -f
```

Ships **starting in `--dry-run`** (see the unit's `ExecStart`) — watch it
against real traffic for a while before enabling real bans. To flip to
real enforcement: edit `/etc/systemd/system/vortexwall.service`, remove
`--dry-run` from `ExecStart`, then `daemon-reload` + `restart`.

## 🛑 How to fully kill this

Since this is explicitly a learning project ahead of setting up `fail2ban`
for real:

```bash
sudo vortexwall --teardown          # removes every rule + ban immediately
sudo systemctl disable --now vortexwall
sudo rm /etc/systemd/system/vortexwall.service
sudo systemctl daemon-reload
```

`--teardown` alone is enough to make it inert (no rules left in nftables);
the rest fully removes the service. No manual nftables cleanup needed
either way — it's all in the one table `--teardown` deletes.

## 🗺 Roadmap / known limitations

- [x] sshd log watching, sliding-window bans, nftables blackhole with auto-expiry
- [x] Hardcoded loopback/private-range protection (not configurable, by design)
- [x] `--dry-run` for zero-risk validation
- [ ] CIDR ranges in `allowlist` (currently exact IPs only)
- [ ] Watch additional services beyond `sshd` (schema already supports it — `[[watch]]` is an array)
- [ ] Persistent ban history across restarts (currently in-memory only — a restart forgets in-progress failure counts, though active *bans* survive since they live in nftables, not the daemon's memory)

## 📄 License

MIT
