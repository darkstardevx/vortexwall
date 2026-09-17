# Security Policy

## Threat model

What VortexWall's design actually defends against, and what it
doesn't — read this before ever turning off `--dry-run`.

### What's defended

- **No network listener at all.** VortexWall only reads the local
  systemd journal (`journalctl -f`) and shells out to `nft` — nothing
  in this daemon ever binds a socket. There's no remote attack surface
  to exploit in the first place.
- **Loopback and private ranges can never be banned, regardless of
  config.** `detector::is_never_bannable` hardcodes this exclusion for
  every RFC1918/RFC4193 range and loopback — it isn't a config
  setting, so a typo'd or missing `allowlist` entry can't accidentally
  let you ban your own LAN (home, a neighbor's, a library — any
  network this box has ever been physically on).
- **`--dry-run` is real, not cosmetic.** In dry-run mode, `nft::setup`/
  `nft::ban` are never called — every would-be ban is logged
  (`[DRY-RUN] would ban ...`) with nothing touching the actual
  firewall state. The deployed unit starts in `--dry-run` by design;
  switching to real bans is a deliberate `ExecStart` edit, not a flag
  flip that's easy to do by accident.
- **Config is validated before anything else happens.**
  `config::validate` rejects `threshold`/`window_secs`/`ban_secs` of
  `0` at startup — these would otherwise silently disable banning
  entirely with no error or warning, discovered only much later when
  an attack that should have triggered a ban simply never does.

### What's NOT defended (by design, or by necessity)

- **`config.toml`'s `watch`/`allowlist` are trusted input**, same as
  every other project in this workspace — the config is written by the
  same person who runs the daemon, not by an untrusted or remote
  party. Treat it like a shell script you'd run yourself.
- **A compromised `nft` binary, or a local attacker who already has
  `CAP_NET_ADMIN`-equivalent access.** This hardening pass narrows what
  a *compromised vortexwall process* could do to the rest of the
  system (no home write access beyond reading config, no unnecessary
  kernel/module/cgroup access, no realtime scheduling) — it isn't
  protection for vortexwall against a host-level compromise that
  happens some other way. Same framing GhostPort's own `SECURITY.md`
  uses for the identical caveat.
- **The host it runs on.** Like every other daemon in this workspace,
  VortexWall assumes the machine it runs on isn't already compromised.
- **CIDR ranges in `allowlist`.** Only plain IPs parse today — a CIDR
  entry is silently ignored with a startup warning
  (`some allowlist entries didn't parse as plain IPs`), not rejected
  outright. Not a security gap in the sense of banning something that
  shouldn't be banned, but worth knowing if you expect a CIDR range to
  actually be protected.

## Supported deployment model

A single box's own sshd journal, actively administered by the person
running it — the same "a handful of things you personally administer"
model as the rest of this workspace. Not designed for multi-tenant use
or for watching a log source you don't control.

## Reporting a vulnerability

Email **darkstardevx@gmail.com** (primary) or, as a backup,
**cybercore.sh@gmail.com**. Include:

- the affected file/commit and a minimal repro or PoC
- what you'd expect to happen instead
- how you'd rate the impact (your best guess is fine)

Expect an acknowledgement within a few days. Please don't include
exploit details in a public GitHub issue or PR until a fix has
shipped.

## Supported versions

Only the latest commit on `main` is supported — there's no tagged
release yet.
