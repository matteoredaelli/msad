"""Shared pytest fixtures: a fake ldap3 connection.

The fake mimics only the tiny slice of the ldap3 API that msad uses:

- ``conn.extend.standard.paged_search(...)``  (used by search())
- ``conn.extend.microsoft.add_members_to_groups(...)``
- ``conn.extend.microsoft.remove_members_from_groups(...)``
- ``conn.extend.microsoft.modify_password(...)``

It records every call (so tests can assert on the LDAP filters we build)
and returns programmable, canned responses. No real LDAP server is used.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

import pytest


@dataclass
class RecordedSearch:
    """A single recorded paged_search call."""

    search_base: str
    search_filter: str
    size_limit: int
    attributes: Any


def _entry(attributes: dict[str, Any], dn: str = "CN=x,DC=example,DC=com") -> dict[str, Any]:
    """Build an ldap3-style response entry (has 'dn' and 'attributes')."""
    return {"dn": dn, "attributes": attributes}


class _Standard:
    def __init__(self, conn: FakeConnection) -> None:
        self._conn = conn

    def paged_search(
        self,
        search_base: str,
        search_filter: str,
        size_limit: int = 0,
        attributes: Any = None,
    ):
        self._conn.searches.append(
            RecordedSearch(search_base, search_filter, size_limit, attributes)
        )
        # Pop the next canned response, or return [] if none queued.
        if self._conn.responses:
            return list(self._conn.responses.pop(0))
        empty: list[dict[str, Any]] = []
        return empty


class _Microsoft:
    def __init__(self, conn: FakeConnection) -> None:
        self._conn = conn

    def add_members_to_groups(self, members: list[str], groups: list[str]) -> bool:
        self._conn.calls.append(("add_members_to_groups", members, groups))
        return True

    def remove_members_from_groups(self, members: list[str], groups: list[str]) -> bool:
        self._conn.calls.append(("remove_members_from_groups", members, groups))
        return True

    def modify_password(
        self, user_dn: str, new_password: str, old_password: str | None = None
    ) -> bool:
        self._conn.calls.append(("modify_password", user_dn, new_password, old_password))
        return True


class _Extend:
    def __init__(self, conn: FakeConnection) -> None:
        self.standard = _Standard(conn)
        self.microsoft = _Microsoft(conn)


@dataclass
class FakeConnection:
    """A stand-in for ldap3.Connection recording calls and returning canned data."""

    responses: list[list[dict[str, Any]]] = field(default_factory=list)
    searches: list[RecordedSearch] = field(default_factory=list)
    calls: list[tuple[Any, ...]] = field(default_factory=list)

    def __post_init__(self) -> None:
        self.extend = _Extend(self)

    # --- helpers for tests ---------------------------------------------

    def queue(self, *responses: list[dict[str, Any]]) -> None:
        """Queue one or more responses, consumed in order by paged_search."""
        self.responses.extend(responses)

    @property
    def last_filter(self) -> str:
        return self.searches[-1].search_filter

    @property
    def filters(self) -> list[str]:
        return [s.search_filter for s in self.searches]


@pytest.fixture
def conn() -> FakeConnection:
    return FakeConnection()


@pytest.fixture
def make_entry():
    return _entry
