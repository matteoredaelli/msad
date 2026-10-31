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
import ipaddress
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


# --- dnsRecord (AD-integrated DNS DNS_RPC_RECORD blob) ---------------------

#: DNS record type numbers (``wType``) this decoder understands by name.
_DNS_RECORD_TYPES: dict[int, str] = {
    1: "A",
    2: "NS",
    5: "CNAME",
    6: "SOA",
    12: "PTR",
    13: "HINFO",
    15: "MX",
    16: "TXT",
    28: "AAAA",
    33: "SRV",
}


def _read_dns_count_name(data: bytes, offset: int) -> tuple[str, int]:
    """Read a DNS_COUNT_NAME at ``offset``; return (dotted-name, new offset).

    DNS_COUNT_NAME is ``cchNameLength`` (1 byte, total length) + ``cLabelCount``
    (1 byte) + that many length-prefixed labels. Returns the name joined with
    dots (with a trailing dot, matching the on-wire absolute form) and the
    offset just past the structure.
    """
    if offset + 2 > len(data):
        return "", len(data)
    # data[offset] is the total byte length of the name buffer; we drive the
    # parse off the per-label length bytes instead, which is unambiguous.
    label_count = data[offset + 1]
    pos = offset + 2
    labels: list[str] = []
    for _ in range(label_count):
        if pos >= len(data):
            break
        length = data[pos]
        pos += 1
        labels.append(data[pos : pos + length].decode("utf-8", "replace"))
        pos += length
    name = ".".join(labels)
    return (f"{name}." if name else "."), pos


def _decode_dns_txt(data: bytes) -> list[str]:
    """Decode the Data of a TXT record into its list of character-strings."""
    strings: list[str] = []
    pos = 0
    while pos < len(data):
        length = data[pos]
        pos += 1
        strings.append(data[pos : pos + length].decode("utf-8", "replace"))
        pos += length
    return strings


def _decode_dns_data(rtype: int, data: bytes) -> Any:
    """Decode the type-specific Data payload of a DNS_RPC_RECORD."""
    if rtype == 1 and len(data) >= 4:  # A
        return str(ipaddress.IPv4Address(data[:4]))
    if rtype == 28 and len(data) >= 16:  # AAAA
        return str(ipaddress.IPv6Address(data[:16]))
    if rtype in (2, 5, 12):  # NS / CNAME / PTR -> a single target name
        name, _ = _read_dns_count_name(data, 0)
        return name
    if rtype == 16:  # TXT
        return _decode_dns_txt(data)
    if rtype == 15 and len(data) >= 2:  # MX: preference + exchange name
        preference = struct.unpack(">H", data[:2])[0]
        exchange, _ = _read_dns_count_name(data, 2)
        return {"preference": preference, "exchange": exchange}
    if rtype == 33 and len(data) >= 6:  # SRV: priority, weight, port + target
        priority, weight, port = struct.unpack(">HHH", data[:6])
        target, _ = _read_dns_count_name(data, 6)
        return {"priority": priority, "weight": weight, "port": port, "target": target}
    if rtype == 6 and len(data) >= 20:  # SOA
        serial, refresh, retry, expire, minimum = struct.unpack(">IIIII", data[:20])
        primary, pos = _read_dns_count_name(data, 20)
        admin, _ = _read_dns_count_name(data, pos)
        return {
            "serial": serial,
            "refresh": refresh,
            "retry": retry,
            "expire": expire,
            "minimum_ttl": minimum,
            "primary_server": primary,
            "responsible_party": admin,
        }
    # Unknown / unsupported type: surface the raw payload as hex.
    return data.hex()


def decode_dns_record(value: Any) -> dict[str, Any] | None:
    """Decode a single binary ``dnsRecord`` (DNS_RPC_RECORD) value.

    The fixed header is ``wDataLength`` (2), ``wType`` (2), ``dwFlags`` (4),
    ``dwSerial`` (4), ``dwTtlSeconds`` (4, big-endian), ``dwTimeStamp`` (4) and
    ``dwReserved`` (4), all little-endian except the TTL, followed by
    ``wDataLength`` bytes of type-specific data (24-byte header total).

    Returns a dict with ``type`` (name, or ``TYPE<n>`` when unknown),
    ``type_id``, ``ttl`` and ``data`` (the decoded payload: an address string
    for A/AAAA, a target name for NS/CNAME/PTR, a list for TXT, a dict for
    MX/SRV/SOA, or a hex string for unsupported types). Returns None if the
    value is not at least a full 24-byte header.
    """
    if not isinstance(value, (bytes, bytearray)):
        return None
    data = bytes(value)
    if len(data) < 24:
        return None
    data_length = struct.unpack("<H", data[0:2])[0]
    rtype = struct.unpack("<H", data[2:4])[0]
    ttl = struct.unpack(">I", data[12:16])[0]
    payload = data[24 : 24 + data_length]
    return {
        "type": _DNS_RECORD_TYPES.get(rtype, f"TYPE{rtype}"),
        "type_id": rtype,
        "ttl": ttl,
        "data": _decode_dns_data(rtype, payload),
    }


def decode_dns_records(value: Any) -> list[dict[str, Any]]:
    """Decode a ``dnsRecord`` attribute (one value, or a list of values).

    A ``dnsNode`` holds one ``dnsRecord`` value per resource record, so ldap3
    may hand back either a single ``bytes`` or a list of them. Values that
    cannot be decoded are skipped.
    """
    raw_values = value if isinstance(value, list) else [value]
    out: list[dict[str, Any]] = []
    for raw in raw_values:
        decoded = decode_dns_record(raw)
        if decoded is not None:
            out.append(decoded)
    return out


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
    - ``dnsRecord_decoded`` — list of decoded DNS resource records (for
      ``dnsNode`` objects), from :func:`decode_dns_records`.
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

    if "dnsRecord" in entry:
        records = decode_dns_records(entry["dnsRecord"])
        if records:
            decoded["dnsRecord_decoded"] = records

    for attr in _FILETIME_ATTRIBUTES:
        if attr in entry:
            iso = decode_filetime(entry[attr])
            if iso is not None:
                decoded[f"{attr}_iso"] = iso

    return decoded


def decode_entries(entries: list[LdapEntry]) -> list[LdapEntry]:
    """Apply :func:`decode_entry` to every entry in a list."""
    return [decode_entry(e) for e in entries]
