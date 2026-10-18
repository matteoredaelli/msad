# msad - Active Directory tool
# Copyright (C) 2026 - matteo.redaelli@gmail.com
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <https://www.gnu.org/licenses/>.
"""Decode raw Active Directory attribute values into human-/LLM-friendly forms.

AD returns several attributes as opaque numbers or binary blobs:
``userAccountControl`` and ``groupType`` are bit fields, the ``*Time`` /
``accountExpires`` / ``pwdLastSet`` attributes are Windows FILETIME integers,
and ``objectSid`` / ``objectGUID`` are binary. These helpers turn them into
booleans, flag lists, ISO-8601 timestamps and canonical string forms.

Everything here is **pure** (no LDAP connection) and **non-destructive**: the
entry-level :func:`decode_entry` returns a *copy* with extra ``*_decoded`` /
``*_flags`` / ``*_iso`` keys added alongside the original raw values, so
callers that rely on the raw attributes keep working unchanged.
"""

from __future__ import annotations

import datetime
import struct
import uuid
from typing import Any

from .types import LdapEntry

# --- userAccountControl ----------------------------------------------------

#: userAccountControl bit flags (subset in common use).
#: https://learn.microsoft.com/windows/win32/adschema/a-useraccountcontrol
_UAC_FLAGS: list[tuple[str, int]] = [
    ("SCRIPT", 0x0001),
    ("ACCOUNTDISABLE", 0x0002),
    ("HOMEDIR_REQUIRED", 0x0008),
    ("LOCKOUT", 0x0010),
    ("PASSWD_NOTREQD", 0x0020),
    ("PASSWD_CANT_CHANGE", 0x0040),
    ("ENCRYPTED_TEXT_PWD_ALLOWED", 0x0080),
    ("TEMP_DUPLICATE_ACCOUNT", 0x0100),
    ("NORMAL_ACCOUNT", 0x0200),
    ("INTERDOMAIN_TRUST_ACCOUNT", 0x0800),
    ("WORKSTATION_TRUST_ACCOUNT", 0x1000),
    ("SERVER_TRUST_ACCOUNT", 0x2000),
    ("DONT_EXPIRE_PASSWORD", 0x10000),
    ("MNS_LOGON_ACCOUNT", 0x20000),
    ("SMARTCARD_REQUIRED", 0x40000),
    ("TRUSTED_FOR_DELEGATION", 0x80000),
    ("NOT_DELEGATED", 0x100000),
    ("USE_DES_KEY_ONLY", 0x200000),
    ("DONT_REQ_PREAUTH", 0x400000),
    ("PASSWORD_EXPIRED", 0x800000),
    ("TRUSTED_TO_AUTH_FOR_DELEGATION", 0x1000000),
    ("PARTIAL_SECRETS_ACCOUNT", 0x4000000),
]


def _coerce_int(value: Any) -> int | None:
    """Return ``value`` as an int, or None if it cannot be interpreted as one."""
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value
    if isinstance(value, str):
        try:
            return int(value.strip())
        except ValueError:
            return None
    return None


def decode_user_account_control(value: Any) -> dict[str, Any] | None:
    """Decode a ``userAccountControl`` value into flags and useful booleans.

    Returns a dict with ``raw`` (the integer), ``flags`` (the list of set flag
    names) and the most-asked booleans — ``disabled``, ``locked``,
    ``password_never_expires``, ``password_not_required``,
    ``smartcard_required``, ``trusted_for_delegation`` — or None if the value
    is not an integer.
    """
    raw = _coerce_int(value)
    if raw is None:
        return None
    flags = [name for name, bit in _UAC_FLAGS if raw & bit]
    flagset = set(flags)
    return {
        "raw": raw,
        "flags": flags,
        "disabled": "ACCOUNTDISABLE" in flagset,
        "locked": "LOCKOUT" in flagset,
        "password_never_expires": "DONT_EXPIRE_PASSWORD" in flagset,
        "password_not_required": "PASSWD_NOTREQD" in flagset,
        "smartcard_required": "SMARTCARD_REQUIRED" in flagset,
        "trusted_for_delegation": "TRUSTED_FOR_DELEGATION" in flagset,
    }


# --- groupType -------------------------------------------------------------

_GROUP_TYPE_SYSTEM = 0x00000001
_GROUP_TYPE_GLOBAL = 0x00000002
_GROUP_TYPE_DOMAIN_LOCAL = 0x00000004
_GROUP_TYPE_UNIVERSAL = 0x00000008
_GROUP_TYPE_SECURITY = 0x80000000


def decode_group_type(value: Any) -> dict[str, Any] | None:
    """Decode a ``groupType`` value into scope and security/distribution.

    Returns a dict with ``raw``, ``scope`` (``global`` / ``domain_local`` /
    ``universal`` / ``builtin``), ``security`` (bool) and ``system`` (bool), or
    None if the value is not an integer.
    """
    raw = _coerce_int(value)
    if raw is None:
        return None
    if raw & _GROUP_TYPE_GLOBAL:
        scope = "global"
    elif raw & _GROUP_TYPE_DOMAIN_LOCAL:
        scope = "domain_local"
    elif raw & _GROUP_TYPE_UNIVERSAL:
        scope = "universal"
    else:
        scope = "builtin"
    return {
        "raw": raw,
        "scope": scope,
        "security": bool(raw & _GROUP_TYPE_SECURITY),
        "distribution": not (raw & _GROUP_TYPE_SECURITY),
        "system": bool(raw & _GROUP_TYPE_SYSTEM),
    }


# --- FILETIME --------------------------------------------------------------

#: Seconds between the Windows FILETIME epoch (1601-01-01) and the Unix epoch.
_FILETIME_EPOCH_OFFSET = 11644473600

#: Sentinel values meaning "never" for accountExpires / lockoutTime etc.
_FILETIME_NEVER = {0, 0x7FFFFFFFFFFFFFFF}


def decode_filetime(value: Any) -> str | None:
    """Decode a Windows FILETIME integer into an ISO-8601 UTC timestamp.

    FILETIME is the number of 100-nanosecond intervals since 1601-01-01 UTC.
    Returns None for the "never"/"unset" sentinels (0 and 0x7FFFFFFFFFFFFFFF),
    for a non-integer value, or for an out-of-range value. If ``value`` is
    already a ``datetime`` (ldap3 parses some time attributes for us), it is
    returned as an ISO-8601 string unchanged.
    """
    if isinstance(value, datetime.datetime):
        return value.isoformat()
    raw = _coerce_int(value)
    if raw is None or raw in _FILETIME_NEVER:
        return None
    try:
        unix_seconds = raw / 10_000_000 - _FILETIME_EPOCH_OFFSET
        return datetime.datetime.fromtimestamp(unix_seconds, tz=datetime.UTC).isoformat()
    except (OverflowError, OSError, ValueError):
        return None


# --- objectSid / objectGUID ------------------------------------------------


def decode_sid(value: Any) -> str | None:
    """Decode a binary ``objectSid`` into its ``S-1-5-...`` string form.

    Tolerates a value that is already a decoded string (ldap3 sometimes returns
    one) and returns it unchanged. Returns None if the value cannot be decoded.
    """
    if isinstance(value, str):
        return value if value.startswith("S-") else None
    if not isinstance(value, (bytes, bytearray)):
        return None
    data = bytes(value)
    if len(data) < 8:
        return None
    revision = data[0]
    sub_authority_count = data[1]
    # 6-byte big-endian identifier authority.
    identifier_authority = int.from_bytes(data[2:8], byteorder="big")
    expected = 8 + 4 * sub_authority_count
    if len(data) < expected:
        return None
    sub_authorities = [
        struct.unpack("<I", data[8 + 4 * i : 12 + 4 * i])[0] for i in range(sub_authority_count)
    ]
    parts = [f"S-{revision}-{identifier_authority}", *(str(s) for s in sub_authorities)]
    return "-".join(parts)


def decode_guid(value: Any) -> str | None:
    """Decode a binary ``objectGUID`` into its canonical string form.

    Tolerates a value that is already a GUID string and returns it unchanged.
    Returns None if the value cannot be decoded.
    """
    if isinstance(value, str):
        return value.strip("{}") if value else None
    if not isinstance(value, (bytes, bytearray)):
        return None
    data = bytes(value)
    if len(data) != 16:
        return None
    # objectGUID is stored little-endian for the first three fields.
    return str(uuid.UUID(bytes_le=data))


# --- entry-level, non-destructive decode -----------------------------------

#: Attributes that hold a Windows FILETIME and get an ``*_iso`` companion key.
_FILETIME_ATTRIBUTES = (
    "accountExpires",
    "lastLogonTimestamp",
    "lastLogon",
    "pwdLastSet",
    "lockoutTime",
    "badPasswordTime",
)


def decode_entry(entry: LdapEntry) -> LdapEntry:
    """Return a copy of an LDAP entry with decoded companion keys added.

    Non-destructive: every original attribute is preserved. Added keys:

    - ``userAccountControl_decoded`` — the dict from
      :func:`decode_user_account_control` (when present and numeric).
    - ``groupType_decoded`` — the dict from :func:`decode_group_type`.
    - ``objectSid_decoded`` / ``objectGUID_decoded`` — canonical strings.
    - ``<attr>_iso`` for each FILETIME attribute that decodes to a timestamp
      (a "never"/unset sentinel adds no key).

    A value that cannot be decoded simply adds no companion key.
    """
    decoded: LdapEntry = dict(entry)

    if "userAccountControl" in entry:
        uac = decode_user_account_control(entry["userAccountControl"])
        if uac is not None:
            decoded["userAccountControl_decoded"] = uac

    if "groupType" in entry:
        gt = decode_group_type(entry["groupType"])
        if gt is not None:
            decoded["groupType_decoded"] = gt

    if "objectSid" in entry:
        sid = decode_sid(entry["objectSid"])
        if sid is not None:
            decoded["objectSid_decoded"] = sid

    if "objectGUID" in entry:
        guid = decode_guid(entry["objectGUID"])
        if guid is not None:
            decoded["objectGUID_decoded"] = guid

    for attr in _FILETIME_ATTRIBUTES:
        if attr in entry:
            iso = decode_filetime(entry[attr])
            if iso is not None:
                decoded[f"{attr}_iso"] = iso

    return decoded


def decode_entries(entries: list[LdapEntry]) -> list[LdapEntry]:
    """Apply :func:`decode_entry` to every entry in a list."""
    return [decode_entry(e) for e in entries]
