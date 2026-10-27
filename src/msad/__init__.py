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

from .audit import (
    DEFAULT_DOMAIN_ATTRIBUTES,
    DEFAULT_GPO_ATTRIBUTES,
    DEFAULT_PASSWORD_POLICY_ATTRIBUTES,
    DEFAULT_PRIVILEGED_GROUPS,
    DEFAULT_PSO_ATTRIBUTES,
    DEFAULT_PWD_VIOLATION_ATTRIBUTES,
    DEFAULT_SITE_ATTRIBUTES,
    DEFAULT_TRUST_ATTRIBUTES,
    get_domain_info,
    get_gpo,
    get_password_policy,
    get_password_policy_violations,
    get_privileged_groups,
    list_fine_grained_password_policies,
    list_fsmo_roles,
    list_gpos,
    list_sites,
    list_trusts,
)
from .config import (
    DEFAULT_CONFIG_PATH,
    SAMPLE_CONFIG,
    Defaults,
    DomainConfig,
    MsadConfig,
    load_config,
    load_domain_config,
    resolve_domain_config,
)
from .connection import check_connection, connect, whoami
from .decode import (
    decode_entries,
    decode_entry,
    decode_filetime,
    decode_group_type,
    decode_guid,
    decode_sid,
    decode_user_account_control,
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
    DEFAULT_COMPUTER_ATTRIBUTES,
    DEFAULT_GROUP_ATTRIBUTES,
    DEFAULT_OU_ATTRIBUTES,
    DEFAULT_USER_ATTRIBUTES,
    disabled_users,
    escape_exact,
    escape_pattern,
    find_admin_count_accounts,
    find_computers,
    find_contacts,
    find_distribution_groups,
    find_empty_ous,
    find_expired_accounts,
    find_inactive_users,
    find_kerberos_preauth_not_required,
    find_must_change_password,
    find_never_expiring_accounts,
    find_not_delegated,
    find_ous,
    find_password_not_required,
    find_recently_created,
    find_recently_modified,
    find_security_groups,
    find_service_accounts,
    find_stale_computers,
    find_users,
    find_users_without_email,
    get_by_dn,
    get_computer,
    get_dn,
    get_ou,
    get_ou_contents,
    get_user,
    list_domain_controllers,
    list_empty_groups,
    locked_users,
    never_expires_password,
    search,
    summarize_computer_os,
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
    unlock_user,
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
    "SAMPLE_CONFIG",
    "Defaults",
    "DomainConfig",
    "MsadConfig",
    "load_config",
    "load_domain_config",
    "resolve_domain_config",
    # connection
    "connect",
    "check_connection",
    "whoami",
    # decode (pure attribute decoders)
    "decode_entry",
    "decode_entries",
    "decode_user_account_control",
    "decode_group_type",
    "decode_filetime",
    "decode_sid",
    "decode_guid",
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
    "find_computers",
    "get_computer",
    "find_ous",
    "get_ou",
    "get_ou_contents",
    "find_empty_ous",
    "find_inactive_users",
    "find_stale_computers",
    "find_contacts",
    "find_security_groups",
    "find_distribution_groups",
    "find_password_not_required",
    "find_kerberos_preauth_not_required",
    "find_not_delegated",
    "find_never_expiring_accounts",
    "find_expired_accounts",
    "find_service_accounts",
    "find_admin_count_accounts",
    "find_must_change_password",
    "find_users_without_email",
    "find_recently_modified",
    "find_recently_created",
    "get_by_dn",
    "get_dn",
    "disabled_users",
    "locked_users",
    "never_expires_password",
    "list_domain_controllers",
    "list_empty_groups",
    "summarize_computer_os",
    "escape_exact",
    "escape_pattern",
    "DEFAULT_USER_ATTRIBUTES",
    "DEFAULT_GROUP_ATTRIBUTES",
    "DEFAULT_COMPUTER_ATTRIBUTES",
    "DEFAULT_OU_ATTRIBUTES",
    # audit (read-only)
    "get_domain_info",
    "get_password_policy",
    "get_password_policy_violations",
    "get_privileged_groups",
    "list_fsmo_roles",
    "list_trusts",
    "list_sites",
    "list_gpos",
    "get_gpo",
    "list_fine_grained_password_policies",
    "DEFAULT_DOMAIN_ATTRIBUTES",
    "DEFAULT_PASSWORD_POLICY_ATTRIBUTES",
    "DEFAULT_PRIVILEGED_GROUPS",
    "DEFAULT_PWD_VIOLATION_ATTRIBUTES",
    "DEFAULT_TRUST_ATTRIBUTES",
    "DEFAULT_SITE_ATTRIBUTES",
    "DEFAULT_GPO_ATTRIBUTES",
    "DEFAULT_PSO_ATTRIBUTES",
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
    "unlock_user",
    "user_groups",
]
