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
    search_base = "dc=example,dc=com"
    port = 636
    use_ssl = true
    # user = "..."      # optional, enables user/password bind
    # password = "..."  # optional
"""

from __future__ import annotations

import tomllib
from pathlib import Path

from pydantic import BaseModel, ValidationError

from .exceptions import MsadConfigError


class DomainConfig(BaseModel):
    """Connection settings for a single AD domain."""

    host: str
    search_base: str
    port: int = 389
    use_ssl: bool = False
    user: str | None = None
    password: str | None = None

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
