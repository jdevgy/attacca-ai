# Security Policy

Attacca is a **pre-production dogfood/prototype**. It is built to demonstrate a
complete continuity workflow with strong correctness boundaries, and it is
deliberately *not* described as production-ready security or operations
infrastructure. Please read "Prototype status and known limits" before you
deploy it anywhere other people can reach.

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

1. Preferred: use **GitHub private vulnerability reporting** on the repository —
   <https://github.com/jdevgy/attacca-ai> → **Security** tab → **Report a
   vulnerability**. This keeps the report private until a fix is published.
2. Alternative: a private security contact address: to be set by the
   maintainer before publishing. Until that line names a real address,
   use GitHub private vulnerability reporting above.

Useful things to include: the Attacca version (`python3 attacca.py --version`),
whether the server was running with authentication enforcement on or off, how
the server was exposed (loopback, LAN, reverse proxy), and the smallest
reproduction you have. Please do not include real API keys, session cookies, or
a copy of a live database — describe them instead.

Because this is a prototype maintained without a support rotation, responses are
best-effort and there is no committed response or fix SLA.

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

The items in the next section are known and intentional for a prototype. Reports
that only restate them will be closed as documented limits — though a report
showing they are *worse than documented* is very welcome.

## Prototype status and known limits

Attacca does **not** currently provide:

- **TLS termination.** The server speaks plain HTTP. Anything in front of it
  must supply TLS.
- **SSO or MFA.** Authentication is a first-owner account plus per-installation
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
- Authentication enforcement is **off by default** until an owner explicitly
  enables it in the Control Panel. An unenforced server trusts whatever
  connects to it.

## Deployment guidance

**Run Attacca on your own machine, or behind your own network and TLS controls.
Never expose the server directly to the internet.**

- Default to loopback (`127.0.0.1`). Binding `0.0.0.0` publishes an
  unencrypted, unthrottled admin surface to every host that can route to you.
- If you need remote access, put it behind something you already trust: a
  VPN/WireGuard/Tailscale network, an SSH tunnel, or a reverse proxy that
  terminates TLS and does its own authentication and rate limiting.
- Enable authentication enforcement in Control Panel → Settings before any
  second machine or second person can reach the server, and keep the API key
  per installation so a single revocation is meaningful.
- Treat the SQLite database, its `-wal`/`-shm` sidecars, and any export as
  secrets at rest: back them up encrypted, and never commit them. `.gitignore`
  already excludes `*.db`, `*.db-wal`, `*.db-shm`, `server.log`, and `.attacca/`
  (except the non-secret `project.json`).
- Never put a credential into content Attacca stores or distributes: ledger
  events, room messages, tasks, decisions, rules, Cloud Context, `AGENTS.md` /
  `CLAUDE.md`, `.attacca/project.json`, command arguments, logs, plugin
  archives, or exports. Those are copied, synced, and exported verbatim.
- Keep `.attacca/project.json` in Git if you like — it holds only a schema
  version and a stable non-secret project ID. Server URL, client installation,
  and credentials stay machine-local and are never committed.
