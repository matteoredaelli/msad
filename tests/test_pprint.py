"""Tests for msad.main._pprint output formatting."""

from __future__ import annotations

import datetime
import json

from msad.main import _pprint

ENTRY = {
    "cn": "matteo",
    "groups": ["g1", "g2"],
    "when": datetime.datetime(2020, 1, 1, 12, 0, 0),
}


def test_pprint_json_one_object_per_line() -> None:
    out = _pprint([ENTRY], "json").strip()
    parsed = json.loads(out)
    assert parsed["cn"] == "matteo"
    assert parsed["groups"] == ["g1", "g2"]
    assert parsed["when"] == "2020-01-01 12:00:00"


def test_pprint_json1_is_a_json_array() -> None:
    out = _pprint([ENTRY], "json1")
    parsed = json.loads(out)
    assert isinstance(parsed, list)
    assert parsed[0]["cn"] == "matteo"


def test_pprint_csv_joins_lists_with_pipe() -> None:
    out = _pprint([ENTRY], "csv").strip()
    # keys are sorted: cn, groups, when
    fields = out.split("\t")
    assert fields[0] == "matteo"
    assert fields[1] == "g1|g2"
    assert fields[2] == "2020-01-01 12:00:00"


def test_pprint_default_returns_raw() -> None:
    data = [ENTRY]
    assert _pprint(data, "default") is data


def test_pprint_empty_returns_input() -> None:
    assert _pprint([], "json") == []
    assert _pprint(None, "json") is None
