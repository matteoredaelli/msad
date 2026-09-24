# msAD

*msad* is a library and command line tool for working with an Active Directory / LDAP
server from Unix, Linux and macOS systems.

It supports authentication with user/password and Kerberos, and pagination (it can
retrieve more than 2000 objects, a limit of AD).

Features:

- [X] search objects (users, groups, computers, ...) with a raw LDAP filter
- [X] search users by field (name, surname, mail, sAMAccountName, department)
- [X] search groups by name / cn / sAMAccountName / displayName
- [X] get a single user or group
- [X] list group members (direct or recursive/nested)
- [X] list a user's groups (direct or recursive/nested)
- [X] check whether a user is a (nested) member of a group
- [X] add/remove members to/from AD groups using DN or sAMAccountName
- [X] change AD passwords
- [X] check if a user is disabled, locked, or has an expired/never-expiring password
- [X] LDAP filter escaping to prevent injection

## Prerequisites

Python >= 3.11

For Kerberos authentication:

- krb5 library and tools (like `kinit`, ...)
- a keytab file or `krb5.conf` configured

## Installation

### With uv (recommended)

Install as an isolated tool on your `PATH`:

```bash
uv tool install msad
```

Run it directly without installing (ephemeral, great for one-off use):

```bash
uvx msad --help
# uvx is shorthand for: uv tool run msad
```

Upgrade or uninstall the installed tool:

```bash
uv tool upgrade msad
uv tool uninstall msad
```

### With pipx

```bash
pipx install msad
```

## Configuration

Create a configuration file at `$HOME/.msad.toml`. Print a sample to start from:

```bash
msad get-sample-config
```

Example `~/.msad.toml`:

```toml
[defaults]
domain = "mydomain"

[domains.mydomain]
host = "dc.example.com"
search_base = "dc=example,dc=com"
port = 636
use_ssl = true

# Omit user/password to authenticate with Kerberos (SASL).
# Set both to authenticate with user/password:
# user = "svc_account"
# password = "..."
```

You can keep multiple domains under `[domains.<name>]` and select one at runtime
with `--domain <name>`, or point to another file with `--config-file <path>`.

## Usage

```bash
msad --help
python -m msad --help
```

For Kerberos authentication, first obtain a ticket:

```bash
kinit            # or: kinit myaduser
```

### Searching

```bash
# Raw LDAP filter (all attributes as JSON)
msad search "(samaccountname=matteo)" --out-format json

# Restrict returned attributes
msad search "(cn=redaelli*)" --attributes mail --attributes sAMAccountName --out-format json

# Find users by field (criteria are ANDed; values may contain *)
msad user-search --surname "Rossi" --department "IT"

# Get a single user (exact match on sAMAccountName / UPN / mail / cn)
msad user-get matteo

# Find groups (supports * wildcards)
msad group-search "qlik_*"

# Get a single group
msad group-get qlik_analyzer_users
```

### Groups and membership

```bash
# Direct members of a group
msad group-members qlik_analyzer_users

# All (nested) members
msad group-members qlik_analyzer_users --nested

# A user's groups (direct, or nested)
msad user-groups matteo
msad user-groups matteo --nested

# Is a user a (nested) member of a group? Prints true/false
msad is-member qlik_analyzer_users matteo

# Add / remove a member (by DN or sAMAccountName)
msad group-add-member qlik_analyzer_users matteo
msad group-remove-member qlik_analyzer_users matteo
```

### Account checks

```bash
# Individual checks (print true / false / not found)
msad is-disabled matteo
msad is-locked matteo
msad has-expired-password matteo --max-age 90
msad has-never-expires-password matteo

# Run all checks at once, optionally checking group memberships
msad check-user matteo --group qlik_analyzer_users --group domain_admins
```

### Passwords

```bash
# Change a user's password (prompts interactively)
msad change-password matteo
```

### Output formats

Most commands accept `--out-format`:

- `jsonl` (default): one JSON object per line (JSON Lines / NDJSON)
- `json`: a single JSON array
- `csv`: tab-separated, list values joined with `|`

## Development

This project uses [uv](https://docs.astral.sh/uv/). A `Makefile` wraps the common
tasks:

```bash
make sync       # install/refresh the dev environment
make test       # run the test suite with coverage
make lint       # ruff check + format check + pyrefly (strict)
make format     # apply ruff autofixes and formatting
make build      # build wheel and sdist into dist/
make publish    # upload to the package index (needs credentials)
make clean      # remove build artifacts and caches
```

Equivalent raw commands:

```bash
uv sync --group dev
uv run pytest
uv run ruff check src/ tests/
uv run pyrefly check
uv build
```

The library ships type hints (`py.typed`) and its public API is declared in
`msad.__all__`, so it can be imported and type-checked by downstream projects.

## License

Copyright © 2021 - 2025 Matteo Redaelli

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.
