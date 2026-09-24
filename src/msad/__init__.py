# msad - Active Directory tool
# Copyright (C) 2020 - 2025 - matteo.redaelli@gmail.com
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
"""msad: a library and CLI for querying Active Directory / LDAP."""

from __future__ import annotations

from importlib.metadata import PackageNotFoundError, version

try:
    # Generated at build time by hatch-vcs from the Git tag.
    from ._version import __version__  # type: ignore[import-not-found,unused-ignore]
except ImportError:  # pragma: no cover - only when running from an unbuilt tree
    try:
        __version__ = version("msad")
    except PackageNotFoundError:
        __version__ = "0.0.0.dev0"

from .config import (
    DEFAULT_CONFIG_PATH,
    Defaults,
    DomainConfig,
    MsadConfig,
    load_config,
    load_domain_config,
)
from .exceptions import (
    MsadConfigError,
    MsadConnectionError,
    MsadError,
    MsadNotFoundError,
)
from .group import (
    add_member,
    find_groups,
    get_group,
    group_flat_members,
    group_member,
    group_members,
    is_member,
    remove_member,
)
from .search import (
    DEFAULT_GROUP_ATTRIBUTES,
    DEFAULT_USER_ATTRIBUTES,
    disabled_users,
    escape_exact,
    escape_pattern,
    find_users,
    get_dn,
    get_user,
    locked_users,
    never_expires_password,
    search,
    users,
)
from .types import Attributes, LdapConnection, LdapEntries, LdapEntry
from .user import (
    change_password,
    check_user,
    has_expired_password,
    has_never_expires_password,
    is_disabled,
    is_locked,
    password_changed_in_days,
    user_groups,
)

__all__ = [
    # metadata
    "__version__",
    # types
    "LdapConnection",
    "LdapEntry",
    "LdapEntries",
    "Attributes",
    # config
    "DEFAULT_CONFIG_PATH",
    "Defaults",
    "DomainConfig",
    "MsadConfig",
    "load_config",
    "load_domain_config",
    # exceptions
    "MsadError",
    "MsadConfigError",
    "MsadConnectionError",
    "MsadNotFoundError",
    # search
    "search",
    "users",
    "find_users",
    "get_user",
    "get_dn",
    "disabled_users",
    "locked_users",
    "never_expires_password",
    "escape_exact",
    "escape_pattern",
    "DEFAULT_USER_ATTRIBUTES",
    "DEFAULT_GROUP_ATTRIBUTES",
    # group
    "add_member",
    "remove_member",
    "group_members",
    "is_member",
    "find_groups",
    "get_group",
    # group (deprecated, removed next release)
    "group_flat_members",
    "group_member",
    # user
    "change_password",
    "check_user",
    "is_disabled",
    "is_locked",
    "has_expired_password",
    "has_never_expires_password",
    "password_changed_in_days",
    "user_groups",
]
