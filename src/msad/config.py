# msad - Active Directory tool
# Copyright (C) 2025 - matteo.redaelli@gmail.com
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
"""Configuration models and loader for msad.

The TOML file (``~/.msad.toml`` by default) looks like::

    [defaults]
    domain = "mydomain"

    [domains.mydomain]
    host = "example.com"
    base = "dc=example,dc=com"
    port = 636
    use_ssl = true
    # user = "..."      # optional, enables user/password bind
    # password = "..."  # optional

:func:`resolve_domain_config` additionally layers ``MSAD_*`` environment
variable overrides on top of the TOML file (env always wins), so downstream
services (restAD, graphqlAD, mcpAD) share one implementation instead of each
reimplementing the same env-parsing logic.
"""

from __future__ import annotations

import os
import tomllib
from collections.abc import Mapping
from contextlib import contextmanager
from pathlib import Path

from pydantic import BaseModel, ValidationError
from pydantic_settings import BaseSettings, SettingsConfigDict

from .exceptions import MsadConfigError


class DomainConfig(BaseModel):
    """Connection settings for a single AD domain."""

    host: str
    base: str
    port: int = 389
    use_ssl: bool = False
    user: str | None = None
    password: str | None = None
    query_timeout: int | None = None

    @property
    def uses_kerberos(self) -> bool:
        """True when no user/password is set, i.e. SASL/Kerberos bind."""
        return self.user is None or self.password is None


class Defaults(BaseModel):
    """The ``[defaults]`` section."""

    domain: str


class MsadConfig(BaseModel):
    """Full parsed configuration file."""

    defaults: Defaults
    domains: dict[str, DomainConfig]

    def get_domain(self, domain: str | None = None) -> DomainConfig:
        """Return the config for ``domain`` (or the default one).

        Raises:
            MsadConfigError: if the requested/default domain is missing.
        """
        name = domain or self.defaults.domain
        try:
            return self.domains[name]
        except KeyError as exc:
            raise MsadConfigError(f"Domain '{name}' not found in section [domains]") from exc


DEFAULT_CONFIG_PATH = Path.home() / ".msad.toml"

# A ready-to-edit sample configuration. Kept next to the models above so it
# stays in sync with them; a test parses it through load_config to guarantee
# it is always valid TOML matching the current schema.
SAMPLE_CONFIG = """\
# msad configuration file (default location: ~/.msad.toml)

[defaults]
# Domain used when --domain is not passed on the command line (CLI) or when
# MSAD_DOMAIN is not set (MCP server).
domain = "mydomain"

[domains.mydomain]
host = "dc.example.com"
base = "dc=example,dc=com"

# LDAPS (recommended). For plain LDAP use port 389 and use_ssl = false.
port = 636
use_ssl = true

# Optional: abort an LDAP operation that gets no response within N seconds
# (ldap3 receive_timeout). Omit to keep ldap3's default (no timeout).
# query_timeout = 30

# Authentication:
#   - Omit both user and password to authenticate with Kerberos (SASL).
#     Get a ticket first with: kinit
#   - Set BOTH to authenticate with user/password:
# user = "svc_account"
# password = "s3cr3t"

# Declare as many domains as you need and pick one at runtime with
# `--domain <name>` (CLI) or the `domain` argument / MSAD_DOMAIN env (MCP).
# This second domain uses user/password authentication instead of Kerberos:
[domains.otherdomain]
host = "dc.other.example.com"
base = "dc=other,dc=example,dc=com"
port = 636
use_ssl = true
user = "svc_reader"
password = "s3cr3t"
"""


def load_config(config_file: str | Path | None = None) -> MsadConfig:
    """Load and validate the msad configuration file.

    Args:
        config_file: path to the TOML file. Defaults to ``~/.msad.toml``.

    Returns:
        A validated :class:`MsadConfig`.

    Raises:
        MsadConfigError: if the file is missing, unreadable or invalid.
    """
    path = Path(config_file) if config_file else DEFAULT_CONFIG_PATH

    if not path.is_file():
        raise MsadConfigError(f"Config file not found: {path}")

    try:
        raw = path.read_bytes()
    except OSError as exc:
        raise MsadConfigError(f"Config file is not readable: {path}") from exc

    try:
        data = tomllib.loads(raw.decode("utf-8"))
    except (tomllib.TOMLDecodeError, UnicodeDecodeError) as exc:
        raise MsadConfigError(f"Invalid TOML in {path}: {exc}") from exc

    try:
        return MsadConfig.model_validate(data)
    except ValidationError as exc:
        raise MsadConfigError(f"Invalid configuration in {path}:\n{exc}") from exc


def load_domain_config(
    domain: str | None = None, config_file: str | Path | None = None
) -> DomainConfig:
    """Convenience helper: load the file and return one domain's config."""
    return load_config(config_file).get_domain(domain)


#: Env var selecting which ``[domains.<name>]`` section to use.
ENV_DOMAIN = "MSAD_DOMAIN"
#: Env var holding the path to the msad TOML config file.
ENV_CONFIG_FILE = "MSAD_CONFIG_FILE"


class _DomainEnvOverrides(BaseSettings):
    """``MSAD_*`` environment overrides for a single domain's connection.

    All fields are optional so that an unset env var leaves the corresponding
    field untouched (``None``) rather than overwriting a TOML-provided value
    with a default. Reuses pydantic's own lax type coercion (e.g. ``"636"`` ->
    ``636``, ``"true"``/``"yes"``/``"on"`` -> ``True``) instead of hand-rolled
    bool/int parsing.
    """

    model_config = SettingsConfigDict(env_prefix="MSAD_", extra="ignore")

    host: str | None = None
    base: str | None = None
    port: int | None = None
    use_ssl: bool | None = None
    user: str | None = None
    password: str | None = None
    query_timeout: int | None = None


@contextmanager
def _environ_override(env: Mapping[str, str]):
    """Temporarily replace ``os.environ`` with ``env`` for the ``with`` block.

    ``pydantic_settings.BaseSettings`` always reads the real process
    environment; this lets :func:`resolve_domain_config` accept an injected
    mapping (mainly for tests) without changing that. Restores the original
    environment afterwards, even on error.
    """
    original = dict(os.environ)
    os.environ.clear()
    os.environ.update(env)
    try:
        yield
    finally:
        os.environ.clear()
        os.environ.update(original)


def _read_env_overrides(env: Mapping[str, str] | None) -> dict[str, object]:
    """Return the ``MSAD_*`` overrides present in ``env`` as a plain dict.

    Only keys whose env var was actually set are included. ``env=None`` reads
    the real ``os.environ``.
    """
    try:
        if env is None:
            overrides = _DomainEnvOverrides()
        else:
            with _environ_override(env):
                overrides = _DomainEnvOverrides()
    except ValidationError as exc:
        raise MsadConfigError(f"Invalid MSAD_* environment variable: {exc}") from exc
    return {k: v for k, v in overrides.model_dump().items() if v is not None}


def resolve_domain_config(
    domain: str | None = None,
    config_file: str | Path | None = None,
    env: Mapping[str, str] | None = None,
) -> DomainConfig:
    """Resolve the effective :class:`DomainConfig`: TOML file, then env overrides.

    This is the one place the whole msad ecosystem (the CLI's siblings
    restAD, graphqlAD and mcpAD) should go through when connection settings
    may come from the environment. It layers two sources, with the second
    always winning over the first:

    1. An optional msad TOML file (see :func:`load_config`) — ``config_file``
       if given, else the ``MSAD_CONFIG_FILE`` env var, else
       ``~/.msad.toml`` if it exists. The ``domain`` argument (or the
       ``MSAD_DOMAIN`` env var) selects which ``[domains.<name>]`` section to
       use.
    2. ``MSAD_HOST``, ``MSAD_BASE``, ``MSAD_PORT``, ``MSAD_USE_SSL``,
       ``MSAD_USER``, ``MSAD_PASSWORD`` and ``MSAD_QUERY_TIMEOUT`` override
       whatever the TOML file provided.

    If no TOML file is found (and none was explicitly requested), the
    configuration is built entirely from the environment: at minimum
    ``MSAD_HOST``/``MSAD_BASE`` (or a TOML-provided ``host``/``base``) must
    resolve to a value.

    Args:
        domain: domain name; falls back to the ``MSAD_DOMAIN`` env var, then
            the TOML file's ``[defaults]`` section.
        config_file: path to the TOML file; falls back to the
            ``MSAD_CONFIG_FILE`` env var, then ``~/.msad.toml`` if present.
        env: environment mapping to read ``MSAD_*`` values from (including
            ``MSAD_DOMAIN``/``MSAD_CONFIG_FILE`` when ``domain``/
            ``config_file`` are not passed explicitly). Defaults to the real
            process environment (``os.environ``); mainly injectable for
            tests.

    Returns:
        A validated :class:`DomainConfig`.

    Raises:
        MsadConfigError: if required fields are missing, an env var has an
            invalid value, or the TOML file (when one is resolved) is
            missing/invalid.
    """
    environ: Mapping[str, str] = os.environ if env is None else env

    resolved_domain = domain or environ.get(ENV_DOMAIN)
    resolved_config_file = config_file or environ.get(ENV_CONFIG_FILE)

    path = Path(resolved_config_file) if resolved_config_file else None
    if path is None and DEFAULT_CONFIG_PATH.is_file():
        path = DEFAULT_CONFIG_PATH

    data: dict[str, object] = {}
    if path is not None:
        data = load_config(path).get_domain(resolved_domain).model_dump()

    data.update(_read_env_overrides(env))

    missing = [key for key in ("host", "base") if not data.get(key)]
    if missing:
        raise MsadConfigError(
            "Missing required configuration: "
            + ", ".join(missing)
            + ". Provide them via the msad TOML file or the MSAD_HOST / MSAD_BASE "
            "environment variables."
        )

    try:
        return DomainConfig.model_validate(data)
    except ValidationError as exc:
        raise MsadConfigError(f"Invalid configuration: {exc}") from exc
