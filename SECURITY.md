# Security Policy

Please read "What the server does not provide" before you deploy Attacca
anywhere other people can reach.

## Supported versions

Only the latest `0.5.x` release receives fixes. There are no long-term support
branches, and older `0.5.x` patch releases are not backported to.

| Version          | Supported |
| ---------------- | --------- |
| latest `0.5.x`   | Yes       |
| any older `0.5.x`| No — upgrade to the latest `0.5.x` |
| `0.4.x` and older| No        |

Check what you are running with:

```bash
python3 attacca.py --version
```

## Reporting a vulnerability

**Please do not open a public GitHub issue for a security problem.**

Use **GitHub private vulnerability reporting** on the repository —
<https://github.com/jdevgy/attacca-ai> → **Security** tab → **Report a
vulnerability**. This keeps the report private until a fix is published.

Useful things to include: the Attacca version (`python3 attacca.py --version`),
whether the server was running with authentication enforcement on or off, how
the server was exposed (loopback, LAN, reverse proxy), and the smallest
reproduction you have. Please do not include real API keys, session cookies, or
a copy of a live database — describe them instead.

### In scope

Anything that breaks a boundary Attacca claims to enforce, for example:

- reading or writing another workspace's ledger, room, tasks, or handoffs;
- acting as an AI actor or human operator you do not own, or escalating past the
  registered workspace role (Director / Advisor / Worker);
- bypassing browser session expiry, `SameSite`/`HttpOnly` handling, or CSRF
  protection on a state-changing request;
- recovering an API key from stored state (only a prefix and a hash are meant to
  be persisted), or using a revoked key;
- forging or silently rewriting append-only ledger history so the hash chain
  still verifies;
- causing the offline mirror/outbox to accept a projection bound to a different
  server, workspace, actor, role, checkout, or device, or to replay a mutation
  more than once;
- leaking a secret into an export, a plugin archive, `project.json`, or the
  managed blocks of `AGENTS.md` / `CLAUDE.md`.

### Out of scope (already documented limits, not vulnerabilities)

The items under "What the server does not provide" are documented behaviour.
Reports that only restate them will be closed as documented limits — though a
report showing they are *worse than documented* is very welcome.

## What the server does not provide

Attacca does **not** currently provide:

- **TLS termination.** The server speaks plain HTTP. Anything in front of it
  must supply TLS.
- **SSO or MFA.** Authentication is an account sign-in plus per-installation
  API keys, nothing more.
- **Login rate limiting.** Account sign-in is not throttled. (Browser lookups of
  an unknown client-pairing code *are* rate-limited.)
- **Encrypted database storage.** The SQLite database is **plaintext on disk**,
  in WAL mode. Anyone who can read the file can read every ledger event, room
  message, task, decision, handoff, and Cloud Context record in it. There is no
  key hierarchy and no end-to-end encryption.
- **Hardened hostile-host isolation.** Attacca assumes the machine it runs on,
  and the coding clients connected to it, are trusted. It is not a sandbox and
  is not hardened against a hostile local user or a hostile MCP client.
- **A signed ledger.** The per-project hash chain makes tampering and sequence
  gaps **evident**, not **impossible**. There are no signatures, so an attacker
  who can write the database can rewrite history *and* recompute the chain. Treat
  ledger verification as an integrity check against accident and drift, not as
  cryptographic proof.

Related properties worth knowing:

- Coordination leases on tasks are **soft locks** for humans and agents. They do
  not lock Git, files, or branches.
- The portable administrative export is an audit/backup artifact. It carries
  project-authored content verbatim and **never** grants a client any authority,
  so it must never be treated as an offline credential.
- **Local no-login mode is a trust choice, not authentication.** The first-run
  console offers no-login local use or login-protected use. Without protection,
  reachable clients are trusted: an actor name, role, or owner label is
  attribution, not proof of a person's identity. Do not treat workspace
  separation or agent naming as an access-control boundary against an untrusted
  client in this mode.
- First-run setup can be completed only through a loopback connection (or an
  SSH tunnel). Choosing protected use creates the administrator and enables
  enforcement together. A network bind recommends protection and requires an
  additional explicit acknowledgement to choose no-login use instead. This
  warning does not make no-login remote access safe.
- Restarts and upgrades preserve an existing installation's account and
  protection settings. A local no-login installation can enable protection in
  Settings; changing a bind address never enables or disables it implicitly.
- Disabling login in Settings opens both the console and API to reachable
  clients. It preserves accounts, passwords, and client keys; their existence
  does not keep the console protected. Sign in optionally with the existing
  server owner account to re-enable protection. Anonymous visitors are
  not treated as that authenticated owner. Keep protection enabled for
  network access, even when the interface offers a warning and confirmation.

## Deployment guidance

**Run Attacca on your own machine, or behind your own network and TLS controls.
Never expose the server directly to the internet.**

- Default to loopback (`127.0.0.1`). No-login use is intended for a computer
  whose local users and coding clients you trust. Binding `0.0.0.0` publishes an
  unencrypted, unthrottled admin surface to every host that can route to you.
- If you need remote access, put it behind something you already trust: a
  VPN/WireGuard/Tailscale network, an SSH tunnel, or a reverse proxy that
  terminates TLS and does its own authentication and rate limiting.
- No-login access accepts localhost or an IP-literal host, not an arbitrary
  DNS name. Use login-protected mode for a named reverse-proxy deployment;
  do not disable the host check to make an unprotected proxy work.
- Choose login protection in first-run setup, or enable it later in Control
  Panel → Settings from the server's local browser, before any second machine
  or untrusted local user can reach the server. If setting up remotely, use an
  SSH tunnel first rather than leaving initial ownership open over the network.
  Keep the API key per installation so a single revocation is meaningful.
- Treat the SQLite database, its `-wal`/`-shm` sidecars, and any export as
  secrets at rest: back them up encrypted, and never commit them. `.gitignore`
  already excludes database files, logs, and the entire local `.attacca/`
  state directory in this source repository.
- Never put a credential into content Attacca stores or distributes: ledger
  events, room messages, tasks, decisions, rules, Cloud Context, `AGENTS.md` /
  `CLAUDE.md`, `.attacca/project.json`, command arguments, logs, plugin
  archives, or exports. Those are copied, synced, and exported verbatim.
- A consumer project may choose to share `.attacca/project.json` in its own
  repository: it holds only a schema version and a stable non-secret project
  ID. This source repository intentionally ignores its private workspace link.
  Server URL, client installation, and credentials stay machine-local and
  are never committed.
