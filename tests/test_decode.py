"""Tests for msad.decode — pure AD attribute decoders."""

from __future__ import annotations

import datetime
import struct
import uuid

from msad.decode import (
    decode_dns_record,
    decode_dns_records,
    decode_entries,
    decode_entry,
    decode_filetime,
    decode_group_type,
    decode_guid,
    decode_sid,
    decode_user_account_control,
)

# --- userAccountControl ----------------------------------------------------


def test_uac_normal_enabled_account() -> None:
    # 512 = NORMAL_ACCOUNT, enabled.
    d = decode_user_account_control(512)
    assert d is not None
    assert d["raw"] == 512
    assert d["disabled"] is False
    assert d["password_never_expires"] is False
    assert "NORMAL_ACCOUNT" in d["flags"]


def test_uac_disabled_and_never_expires() -> None:
    # 512 + 2 (disable) + 65536 (don't expire) = 66050.
    d = decode_user_account_control(66050)
    assert d is not None
    assert d["disabled"] is True
    assert d["password_never_expires"] is True
    assert set(d["flags"]) >= {"NORMAL_ACCOUNT", "ACCOUNTDISABLE", "DONT_EXPIRE_PASSWORD"}


def test_uac_accepts_numeric_string() -> None:
    d = decode_user_account_control("514")
    assert d is not None
    assert d["disabled"] is True


def test_uac_rejects_non_numeric() -> None:
    assert decode_user_account_control("nope") is None
    assert decode_user_account_control(None) is None
    assert decode_user_account_control(True) is None


# --- groupType -------------------------------------------------------------


def test_group_type_global_security() -> None:
    # AD may return the signed (-2147483646) or unsigned (2147483650) form of
    # a global security group; both carry the same low bits we read.
    d_signed = decode_group_type(-2147483646)
    assert d_signed is not None
    assert d_signed["scope"] == "global"
    d2 = decode_group_type(2147483650)
    assert d2 is not None
    assert d2["scope"] == "global"
    assert d2["security"] is True
    assert d2["distribution"] is False


def test_group_type_universal_distribution() -> None:
    d = decode_group_type(8)  # universal, no security bit
    assert d is not None
    assert d["scope"] == "universal"
    assert d["security"] is False
    assert d["distribution"] is True


def test_group_type_domain_local() -> None:
    d = decode_group_type(4)
    assert d is not None
    assert d["scope"] == "domain_local"


def test_group_type_rejects_non_numeric() -> None:
    assert decode_group_type("x") is None


# --- FILETIME --------------------------------------------------------------


def test_filetime_known_value() -> None:
    # 2021-01-01T00:00:00Z as FILETIME.
    dt = datetime.datetime(2021, 1, 1, tzinfo=datetime.UTC)
    filetime = int((dt.timestamp() + 11644473600) * 10_000_000)
    iso = decode_filetime(filetime)
    assert iso is not None
    assert iso.startswith("2021-01-01T00:00:00")


def test_filetime_never_sentinels() -> None:
    assert decode_filetime(0) is None
    assert decode_filetime(0x7FFFFFFFFFFFFFFF) is None


def test_filetime_passthrough_datetime() -> None:
    dt = datetime.datetime(2020, 5, 5, 12, 0, tzinfo=datetime.UTC)
    assert decode_filetime(dt) == dt.isoformat()


def test_filetime_rejects_garbage() -> None:
    assert decode_filetime("abc") is None


# --- SID --------------------------------------------------------------------


def test_decode_sid_binary() -> None:
    # Build S-1-5-21-1-2-3.
    revision = 1
    sub = [21, 1, 2, 3]
    data = struct.pack("B", revision)
    data += struct.pack("B", len(sub))
    data += (5).to_bytes(6, "big")  # identifier authority 5
    for s in sub:
        data += struct.pack("<I", s)
    assert decode_sid(data) == "S-1-5-21-1-2-3"


def test_decode_sid_passthrough_string() -> None:
    assert decode_sid("S-1-5-18") == "S-1-5-18"
    assert decode_sid("not-a-sid") is None


def test_decode_sid_rejects_short() -> None:
    assert decode_sid(b"\x01") is None


# --- GUID -------------------------------------------------------------------


def test_decode_guid_binary() -> None:
    u = uuid.uuid4()
    assert decode_guid(u.bytes_le) == str(u)


def test_decode_guid_passthrough_string() -> None:
    assert decode_guid("{12345678-1234-1234-1234-123456789abc}") == (
        "12345678-1234-1234-1234-123456789abc"
    )


def test_decode_guid_rejects_bad_length() -> None:
    assert decode_guid(b"\x00\x01\x02") is None


# --- entry-level decode (non-destructive) ----------------------------------


def test_decode_entry_is_non_destructive_and_adds_keys() -> None:
    entry = {
        "sAMAccountName": "jdoe",
        "userAccountControl": 66050,
        "accountExpires": 0,  # never -> no iso key
        "lastLogonTimestamp": int(
            (datetime.datetime(2022, 2, 2, tzinfo=datetime.UTC).timestamp() + 11644473600)
            * 10_000_000
        ),
    }
    decoded = decode_entry(entry)
    # Original keys preserved untouched.
    assert decoded["sAMAccountName"] == "jdoe"
    assert decoded["userAccountControl"] == 66050
    # Companion keys added.
    assert decoded["userAccountControl_decoded"]["disabled"] is True
    assert "lastLogonTimestamp_iso" in decoded
    assert decoded["lastLogonTimestamp_iso"].startswith("2022-02-02")
    # "never" sentinel adds no iso key.
    assert "accountExpires_iso" not in decoded
    # The input dict itself is not mutated.
    assert "userAccountControl_decoded" not in entry


def test_decode_entry_group_type() -> None:
    decoded = decode_entry({"cn": "Sales", "groupType": 2147483650})
    assert decoded["groupType_decoded"]["scope"] == "global"
    assert decoded["groupType_decoded"]["security"] is True


def test_decode_entries_maps_all() -> None:
    out = decode_entries([{"userAccountControl": 512}, {"groupType": 8}])
    assert out[0]["userAccountControl_decoded"]["disabled"] is False
    assert out[1]["groupType_decoded"]["scope"] == "universal"


# --- dnsRecord -------------------------------------------------------------


def _dns_record(rtype: int, data: bytes, ttl: int = 3600) -> bytes:
    """Build a DNS_RPC_RECORD blob: 24-byte header + type-specific data.

    Header: wDataLength(LE,2) wType(LE,2) dwFlags(4) dwSerial(4)
    dwTtlSeconds(BE,4) dwTimeStamp(4) dwReserved(4).
    """
    header = (
        struct.pack("<H", len(data))
        + struct.pack("<H", rtype)
        + b"\x00\x00\x00\x00"  # dwFlags
        + b"\x00\x00\x00\x00"  # dwSerial
        + struct.pack(">I", ttl)  # dwTtlSeconds (big-endian)
        + b"\x00\x00\x00\x00"  # dwTimeStamp
        + b"\x00\x00\x00\x00"  # dwReserved
    )
    return header + data


def _dns_count_name(name: str) -> bytes:
    """Encode a dotted name as a DNS_COUNT_NAME (total-len, label-count, labels)."""
    labels = [label for label in name.rstrip(".").split(".") if label]
    body = b"".join(bytes([len(label)]) + label.encode() for label in labels)
    total = len(body) + 1  # +1 for the trailing root (as Windows counts it)
    return bytes([total, len(labels)]) + body


def test_decode_dns_record_a() -> None:
    blob = _dns_record(1, bytes([10, 20, 0, 5]), ttl=600)
    d = decode_dns_record(blob)
    assert d is not None
    assert d["type"] == "A"
    assert d["type_id"] == 1
    assert d["ttl"] == 600
    assert d["data"] == "10.20.0.5"


def test_decode_dns_record_aaaa() -> None:
    import ipaddress

    packed = ipaddress.IPv6Address("2001:db8::1").packed
    d = decode_dns_record(_dns_record(28, packed))
    assert d is not None
    assert d["type"] == "AAAA"
    assert d["data"] == "2001:db8::1"


def test_decode_dns_record_cname() -> None:
    d = decode_dns_record(_dns_record(5, _dns_count_name("host.example.com")))
    assert d is not None
    assert d["type"] == "CNAME"
    assert d["data"] == "host.example.com."


def test_decode_dns_record_srv() -> None:
    data = struct.pack(">HHH", 0, 100, 389) + _dns_count_name("dc1.example.com")
    d = decode_dns_record(_dns_record(33, data))
    assert d is not None
    assert d["type"] == "SRV"
    assert d["data"]["priority"] == 0
    assert d["data"]["weight"] == 100
    assert d["data"]["port"] == 389
    assert d["data"]["target"] == "dc1.example.com."


def test_decode_dns_record_mx() -> None:
    data = struct.pack(">H", 10) + _dns_count_name("mail.example.com")
    d = decode_dns_record(_dns_record(15, data))
    assert d is not None
    assert d["type"] == "MX"
    assert d["data"]["preference"] == 10
    assert d["data"]["exchange"] == "mail.example.com."


def test_decode_dns_record_txt() -> None:
    data = bytes([5]) + b"hello" + bytes([3]) + b"foo"
    d = decode_dns_record(_dns_record(16, data))
    assert d is not None
    assert d["type"] == "TXT"
    assert d["data"] == ["hello", "foo"]


def test_decode_dns_record_soa() -> None:
    data = (
        struct.pack(">IIIII", 42, 900, 600, 86400, 3600)
        + _dns_count_name("dc1.example.com")
        + _dns_count_name("hostmaster.example.com")
    )
    d = decode_dns_record(_dns_record(6, data))
    assert d is not None
    assert d["type"] == "SOA"
    assert d["data"]["serial"] == 42
    assert d["data"]["primary_server"] == "dc1.example.com."
    assert d["data"]["responsible_party"] == "hostmaster.example.com."


def test_decode_dns_record_unknown_type_is_hex() -> None:
    d = decode_dns_record(_dns_record(99, b"\xde\xad\xbe\xef"))
    assert d is not None
    assert d["type"] == "TYPE99"
    assert d["data"] == "deadbeef"


def test_decode_dns_record_rejects_short_and_nonbytes() -> None:
    assert decode_dns_record(b"\x00" * 10) is None  # shorter than header
    assert decode_dns_record("not bytes") is None
    assert decode_dns_record(None) is None


def test_decode_dns_records_handles_list_and_single() -> None:
    a = _dns_record(1, bytes([1, 1, 1, 1]))
    aaaa = _dns_record(28, b"\x00" * 16)
    assert len(decode_dns_records([a, aaaa])) == 2
    assert len(decode_dns_records(a)) == 1
    # Undecodable values are skipped.
    assert decode_dns_records([b"short"]) == []


def test_decode_entry_adds_dns_records() -> None:
    blob = _dns_record(1, bytes([192, 168, 1, 1]))
    decoded = decode_entry({"name": "www", "dnsRecord": blob})
    assert decoded["name"] == "www"
    assert decoded["dnsRecord_decoded"][0]["type"] == "A"
    assert decoded["dnsRecord_decoded"][0]["data"] == "192.168.1.1"
