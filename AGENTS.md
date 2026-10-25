# AGENTS.md — notes for coding agents working on msad

This file is for AI coding agents. It covers things that aren't in the
README (install/usage/config) but matter when *changing code* here.

## What this repo is

Core library + CLI. `src/msad/` is organized by domain:

- `search.py` — low-level `search()` + all `find_*` / `get_*` functions and
  `DEFAULT_*_ATTRIBUTES` lists (one list per object type: user/group/
  computer/OU). Most new read-only query functions belong here.
- `audit.py` — higher-level, read-only security/compliance helpers (domain
  info, password policy, privileged groups, FSMO, trusts, sites, GPOs, PSOs).
- `group.py` / `user.py` — group-membership and per-user account operations
  (including the only write operations: `add_member`, `remove_member`,
  `change_password`, `unlock_user`).
- `connection.py` — builds/binds the `ldap3.Connection` (user/password or
  Kerberos/SASL-GSSAPI).
- `decode.py` — pure decoders for raw AD attributes (userAccountControl,
  groupType, FILETIME, SID, GUID) into human-readable companion fields.
- `config.py` — TOML config resolution (`~/.msad.toml`, multi-domain).
- `main.py` — the Typer CLI; thin wrappers around the library functions.
- `__init__.py` — the public API surface. **Every new public function must
  be imported and added to `__all__` here**, or downstream consumers
  (restAD, graphqlAD, mcpAD) can't use it.

## Downstream consumers — keep them in sync

`restAD`, `graphqlAD` and `mcpAD` are separate repos that each wrap this
library 1:1 (a REST router, a GraphQL field, an MCP tool per msad function).
When you add or change a public function here:

- Add it to `src/msad/__init__.py` (`__all__` too).
- Consider whether it needs a new CLI command in `main.py`.
- Flag it clearly in your summary — the user will want it mirrored in the
  three downstream repos. Don't assume that happens automatically.

## Versioning — do not hand-edit

Version comes from the Git tag via `hatch-vcs` (`[tool.hatch.version] source
= "vcs"` in `pyproject.toml`). `src/msad/_version.py` is generated at build
time and is gitignored — never create/commit it, never hand-edit the version
anywhere. Releases are just `git tag vX.Y.Z && git push --tags`; CI builds
and publishes to PyPI via Trusted Publishing (OIDC, no token).

Gotcha: the CI `build` job's checkout step needs `fetch-depth: 0` (hatch-vcs
needs full tag history). If a tag publish produces the wrong version, check
that first.

## Kerberos is an optional extra

`gssapi` lives under `[project.optional-dependencies] kerberos`, not in the
base `dependencies`. It's a native extension that needs system Kerberos dev
headers to build — do not move it back to a hard dependency. If you add code
that imports `gssapi` directly (rather than relying on `ldap3`'s lazy
import), guard it and raise a clear `MsadConnectionError` pointing at
`msad[kerberos]`, matching the existing pattern in `connection.py`.

## Testing conventions

- `tests/conftest.py` provides a fake `ldap3`-like connection fixture
  (`conn`) that records the search filter/base/attributes it was called
  with — tests assert on the *generated LDAP filter string*, not on a real
  directory. Follow this pattern for new `find_*`/`get_*` functions: queue a
  canned response, call the function, assert on `conn.last_filter`.
- Run `make lint` (ruff check + format check + pyrefly strict) and `make
  test` (pytest + coverage) before considering a change done.
- `uv.lock` / dependency bumps: if `uv lock --upgrade-package msad` (from a
  downstream repo) doesn't pick up a just-published version, uv's own
  package-metadata cache is usually the cause — add `--refresh-package msad`.
