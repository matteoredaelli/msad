"""Tests for msad.config (Pydantic models + loader)."""

from __future__ import annotations

from pathlib import Path

import pytest

from msad.config import DomainConfig, load_config, load_domain_config
from msad.exceptions import MsadConfigError

VALID = """
[defaults]
domain = "d1"

[domains.d1]
host = "dc1.example.com"
search_base = "dc=example,dc=com"
port = 636
use_ssl = true

[domains.d2]
host = "dc2.example.com"
search_base = "dc=other,dc=com"
port = 389
use_ssl = false
user = "svc"
password = "secret"
"""


def _write(tmp_path: Path, content: str) -> Path:
    p = tmp_path / ".msad.toml"
    p.write_text(content)
    return p


def test_load_valid_config(tmp_path: Path) -> None:
    cfg = load_config(_write(tmp_path, VALID))
    assert set(cfg.domains) == {"d1", "d2"}
    assert cfg.defaults.domain == "d1"


def test_default_domain_selected(tmp_path: Path) -> None:
    d = load_domain_config(None, _write(tmp_path, VALID))
    assert d.host == "dc1.example.com"
    assert d.port == 636
    assert d.use_ssl is True


def test_explicit_domain_selected(tmp_path: Path) -> None:
    d = load_domain_config("d2", _write(tmp_path, VALID))
    assert d.host == "dc2.example.com"
    assert d.user == "svc"


def test_uses_kerberos() -> None:
    krb = DomainConfig(host="h", search_base="dc=x")
    assert krb.uses_kerberos is True

    userpwd = DomainConfig(host="h", search_base="dc=x", user="u", password="p")
    assert userpwd.uses_kerberos is False

    # user without password -> still kerberos (both required)
    partial = DomainConfig(host="h", search_base="dc=x", user="u")
    assert partial.uses_kerberos is True


def test_defaults_port_and_ssl() -> None:
    d = DomainConfig(host="h", search_base="dc=x")
    assert d.port == 389
    assert d.use_ssl is False


def test_missing_file_raises() -> None:
    with pytest.raises(MsadConfigError, match="not found"):
        load_config("/no/such/file-msad.toml")


def test_unknown_domain_raises(tmp_path: Path) -> None:
    with pytest.raises(MsadConfigError, match="nope"):
        load_domain_config("nope", _write(tmp_path, VALID))


def test_missing_defaults_section_raises(tmp_path: Path) -> None:
    content = """
[domains.d1]
host = "h"
search_base = "dc=x"
"""
    with pytest.raises(MsadConfigError):
        load_config(_write(tmp_path, content))


def test_missing_required_field_raises(tmp_path: Path) -> None:
    content = """
[defaults]
domain = "d1"

[domains.d1]
host = "h"
"""  # missing search_base
    with pytest.raises(MsadConfigError):
        load_config(_write(tmp_path, content))


def test_invalid_toml_raises(tmp_path: Path) -> None:
    with pytest.raises(MsadConfigError, match="Invalid TOML"):
        load_config(_write(tmp_path, "this is = = not toml"))
