"""Tests for msad.decode — pure AD attribute decoders."""

from __future__ import annotations

import datetime
import struct
import uuid

from msad.decode import (
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
    assert decode_user_account_control("514")["disabled"] is True


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
    assert decode_group_type(4)["scope"] == "domain_local"


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
