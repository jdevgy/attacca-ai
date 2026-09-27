# Contributing to Attacca

Attacca is a self-hosted project-continuity layer for humans and AI coding
tools. Contributions can be bug reports, documentation improvements, tests,
or focused code changes. You do not need an Attacca account, access to a
private workspace, or machine-specific configuration to contribute.

For security issues, follow [SECURITY.md](SECURITY.md) instead of posting
sensitive details in a public issue.

## Prepare a development checkout

Clone the repository, or clone your fork if you plan to submit a pull request.
The repository root contains `attacca.py`, `tests/`, and `.github/`; there is
no additional package directory to enter.

Attacca requires **Python 3.8+ and the standard library only**. There is no
build step or third-party runtime dependency. `requirements.txt` is
intentionally empty. Propose substantial dependency or architecture changes
in an issue before implementing them.

Use syntax and standard-library APIs supported by Python 3.8. For example,
avoid `match`, runtime `X | Y` unions, `str.removeprefix`, and
`functools.cache`. This command checks syntax against that floor:

```bash
python3 -c "import ast; ast.parse(open('attacca.py').read(), feature_version=(3,8))"
```

It does not validate API availability; the Python 3.8 CI job covers that.

## Run an isolated development server

Use a scratch database and a free loopback port, separate from any server you
or other people depend on:

```bash
ATTACCA_DB=/tmp/attacca-dev.db python3 attacca.py serve --host 127.0.0.1 --port 8799
```

Choose a different scratch path if that file already contains data you want
to preserve. Open `http://127.0.0.1:8799/` to complete the first-run guide. A
fresh installation offers local use without login or login protection with a
first administrator. Existing installations retain their access policy.

Useful surfaces are:

- `/` — the Control Panel; `/app` is an alias.
- `/healthz` — health and the running version.
- `/mcp` — the streamable HTTP MCP endpoint.
- `/v1/...` — REST resources.
- `/install.sh` and `/plugin.zip` — the installer and plugin distribution.

Use `python3 attacca.py serve --help` for server options. `--auth` requests
authentication readiness; it does not activate enforcement by itself. Stay
on loopback for development, and read [deployment guidance](SECURITY.md#deployment-guidance)
before exposing a server beyond your computer.

Never point tests or an experimental migration at a shared database or server.
Local databases, credentials, logs, workspace links, and personal coding-tool
configuration are excluded from the public repository by `.gitignore`.

### Source, running server, and installed plugin are separate

At startup the server captures an immutable distribution snapshot: the
Control Panel, installer, plugin archive, version, and managed protocol.
Editing source does not replace that snapshot. Restart only your isolated
development server to test new distribution bytes. Never interrupt a shared
server just to run tests.

An installed plugin is a separate copy again. Verification should identify
whether it covered source, a served download, an installed plugin, or a
running client. A client may need a fresh session to load an updated plugin.

### Test plugin installation carefully

The universal installer configures coding tools on the machine where it
runs. Use a disposable environment for installer changes. Run it from a
directory **outside the Attacca source checkout**, and use the URL of your
isolated test server. Do not point installation tests at an existing personal
coding-tool configuration.

For normal user installation and project linking, follow the
[README quick start](README.md#quick-start-local-server).

## Run tests

From the repository root:

```bash
python3 -m unittest $(cd tests && ls test_*.py | sed 's/\.py$//; s/^/tests./')
```

This explicit module list is also used by CI. Plain discovery from the root
can run no tests because `tests/` is a namespace package. Discovery with
`-s tests` can load modules under different names from their cross-test
imports, so use the command above.

For a focused change, run the relevant modules while developing:

```bash
python3 -m unittest tests.test_store tests.test_http -v
```

Run the full suite before submitting a pull request. Include relevant
authentication, concurrency, lifecycle, sync, export, or panel coverage when
those areas change. Panel tests that execute JavaScript need Node.js; this is
a test tool, not an Attacca runtime dependency.

Tests must use temporary databases, temporary homes and configurations, and
ephemeral loopback ports. They must not restart, reconfigure, authenticate,
migrate, or write to a configured shared server or a real user configuration.
Reuse the existing fixtures, such as `ServerFixture` in `tests/test_http.py`,
and clean up test processes and temporary resources.

Test modules must also import on Python 3.8. Guard newer optional test APIs and
skip only the affected tests. For example:

```python
try:
    import tomllib
except ImportError:  # Python < 3.11
    tomllib = None

@unittest.skipUnless(tomllib is not None, "tomllib requires Python 3.11+")
def test_toml_parsing(self):
    ...
```

## Submit a change

1. Open an issue for a bug or a substantial proposed change. Include expected
   behavior, actual behavior, reproduction steps, and relevant versions.
   Remove credentials, personal paths, and private project data from examples.
2. Make a focused change on a branch in your fork. Preserve unrelated work in
   a shared checkout rather than reverting or committing it with your patch.
3. Add regression coverage and update public documentation when behavior
   changes. Describe user-visible changes under `Unreleased` in
   [CHANGELOG.md](CHANGELOG.md), or the release section being prepared.
4. Submit a pull request explaining the change, the problem it solves, and
   the exact verification performed. Mention limitations or untested cases.

Keep commits focused and describe the change plainly. Do not include generated
attribution trailers or personal development notes. Do not rewrite published
history or force-push the shared main branch as part of normal contribution.

Never commit credentials, databases, private agent instructions, personal
configuration, or logs. Check the staged diff before committing. Sanitized
test fixtures should use fictional identities and deliberately non-secret
values.

## Public documentation

| File | Purpose |
| --- | --- |
| [README.md](README.md) | Installation, architecture, current behavior, and API/CLI usage. |
| [SECURITY.md](SECURITY.md) | Security reporting and deployment guidance. |
| [CONTRIBUTING.md](CONTRIBUTING.md) | Development and contribution workflow. |
| [CHANGELOG.md](CHANGELOG.md) | User-visible release history. |

Describe implemented behavior, not private plans or future features. Current
source and tests are the implementation reference. All instructions needed
to build and test a public checkout belong in these public files.
