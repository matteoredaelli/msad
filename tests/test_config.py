"""Tests for msad.config (Pydantic models + loader)."""

from __future__ import annotations

from pathlib import Path

import pytest

from msad.config import (
    SAMPLE_CONFIG,
    DomainConfig,
    load_config,
    load_domain_config,
    resolve_domain_config,
)
from msad.exceptions import MsadConfigError

VALID = """
[defaults]
domain = "d1"

[domains.d1]
host = "dc1.example.com"
base = "dc=example,dc=com"
port = 636
use_ssl = true

[domains.d2]
host = "dc2.example.com"
base = "dc=other,dc=com"
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
    krb = DomainConfig(host="h", base="dc=x")
    assert krb.uses_kerberos is True

    userpwd = DomainConfig(host="h", base="dc=x", user="u", password="p")
    assert userpwd.uses_kerberos is False

    # user without password -> still kerberos (both required)
    partial = DomainConfig(host="h", base="dc=x", user="u")
    assert partial.uses_kerberos is True


def test_defaults_port_and_ssl() -> None:
    d = DomainConfig(host="h", base="dc=x")
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
base = "dc=x"
"""
    with pytest.raises(MsadConfigError):
        load_config(_write(tmp_path, content))


def test_missing_required_field_raises(tmp_path: Path) -> None:
    content = """
[defaults]
domain = "d1"

[domains.d1]
host = "h"
"""  # missing base
    with pytest.raises(MsadConfigError):
        load_config(_write(tmp_path, content))


def test_invalid_toml_raises(tmp_path: Path) -> None:
    with pytest.raises(MsadConfigError, match="Invalid TOML"):
        load_config(_write(tmp_path, "this is = = not toml"))


def test_sample_config_is_valid(tmp_path: Path) -> None:
    """The shipped sample must always parse and validate against the schema."""
    cfg = load_config(_write(tmp_path, SAMPLE_CONFIG))
    # The default domain declared in [defaults] must exist under [domains].
    d = cfg.get_domain()
    assert d.host
    assert d.base
    # Sample ships with Kerberos auth (user/password commented out).
    assert d.uses_kerberos is True


def test_query_timeout_defaults_to_none() -> None:
    d = DomainConfig(host="h", base="dc=x")
    assert d.query_timeout is None


def test_query_timeout_parsed_from_toml(tmp_path: Path) -> None:
    content = """
[defaults]
domain = "d1"

[domains.d1]
host = "dc1.example.com"
base = "dc=example,dc=com"
query_timeout = 30
"""
    cfg = load_config(_write(tmp_path, content))
    assert cfg.get_domain("d1").query_timeout == 30


# --- resolve_domain_config: TOML + MSAD_* env overrides ---------------------


@pytest.fixture
def no_default_toml(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Point DEFAULT_CONFIG_PATH at a file that does not exist.

    Without this, tests that expect "no TOML resolvable" would silently pick
    up a real ``~/.msad.toml`` on a developer's own machine, making the test
    outcome depend on whatever is configured there.
    """
    monkeypatch.setattr("msad.config.DEFAULT_CONFIG_PATH", tmp_path / "unused-.msad.toml")


def test_resolve_pure_env_no_toml(no_default_toml: None) -> None:
    """With no TOML file resolvable, env vars alone are enough."""
    cfg = resolve_domain_config(env={"MSAD_HOST": "dc.x", "MSAD_BASE": "dc=x"})
    assert cfg.host == "dc.x"
    assert cfg.base == "dc=x"
    assert cfg.port == 389  # model default, nothing overrode it
    assert cfg.uses_kerberos is True


def test_resolve_env_overrides_types(no_default_toml: None) -> None:
    """MSAD_PORT / MSAD_USE_SSL / MSAD_QUERY_TIMEOUT coerce to int/bool."""
    cfg = resolve_domain_config(
        env={
            "MSAD_HOST": "dc.x",
            "MSAD_BASE": "dc=x",
            "MSAD_PORT": "636",
            "MSAD_USE_SSL": "true",
            "MSAD_QUERY_TIMEOUT": "30",
        }
    )
    assert cfg.port == 636
    assert cfg.use_ssl is True
    assert cfg.query_timeout == 30


def test_resolve_missing_required_raises(no_default_toml: None) -> None:
    with pytest.raises(MsadConfigError, match="Missing required"):
        resolve_domain_config(env={})


def test_resolve_invalid_env_value_raises(no_default_toml: None) -> None:
    with pytest.raises(MsadConfigError):
        resolve_domain_config(env={"MSAD_HOST": "dc.x", "MSAD_BASE": "dc=x", "MSAD_PORT": "nope"})


def test_resolve_env_overrides_toml(tmp_path: Path) -> None:
    """Env always wins over the TOML file, field by field."""
    path = _write(tmp_path, VALID)
    cfg = resolve_domain_config(
        config_file=str(path),
        env={"MSAD_DOMAIN": "d1", "MSAD_HOST": "dc-override.example.com"},
    )
    assert cfg.host == "dc-override.example.com"  # overridden
    assert cfg.base == "dc=example,dc=com"  # still from the TOML file
    assert cfg.port == 636


def test_resolve_explicit_domain_wins_over_env_domain(tmp_path: Path) -> None:
    path = _write(tmp_path, VALID)
    cfg = resolve_domain_config("d2", str(path), env={"MSAD_DOMAIN": "d1"})
    assert cfg.user == "svc"  # d2, not d1


def test_resolve_explicit_config_file_missing_raises(no_default_toml: None) -> None:
    with pytest.raises(MsadConfigError, match="not found"):
        resolve_domain_config(env={"MSAD_CONFIG_FILE": "/no/such/file-msad.toml"})


def test_resolve_restores_real_environ(
    no_default_toml: None, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A custom `env` mapping must not leak into (or clobber) os.environ."""
    import os

    monkeypatch.setenv("MSAD_HOST", "real-process-env")
    resolve_domain_config(env={"MSAD_HOST": "dc.x", "MSAD_BASE": "dc=x"})
    assert os.environ["MSAD_HOST"] == "real-process-env"


def test_resolve_defaults_to_real_os_environ(
    no_default_toml: None, monkeypatch: pytest.MonkeyPatch
) -> None:
    """env=None (the default) reads the real process environment."""
    monkeypatch.setenv("MSAD_HOST", "dc.from-process-env")
    monkeypatch.setenv("MSAD_BASE", "dc=x")
    monkeypatch.delenv("MSAD_CONFIG_FILE", raising=False)
    monkeypatch.delenv("MSAD_DOMAIN", raising=False)
    cfg = resolve_domain_config()
    assert cfg.host == "dc.from-process-env"
