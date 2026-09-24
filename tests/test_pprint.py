"""Tests for msad.main._pprint output formatting."""

from __future__ import annotations

import datetime
import json

from msad.main import OutFormat, _pprint

ENTRY = {
    "cn": "matteo",
    "groups": ["g1", "g2"],
    "when": datetime.datetime(2020, 1, 1, 12, 0, 0),
}


def test_pprint_jsonl_one_object_per_line() -> None:
    out = _pprint([ENTRY], OutFormat.jsonl).strip()
    parsed = json.loads(out)
    assert parsed["cn"] == "matteo"
    assert parsed["groups"] == ["g1", "g2"]
    assert parsed["when"] == "2020-01-01 12:00:00"


def test_pprint_jsonl_emits_one_line_per_object() -> None:
    out = _pprint([ENTRY, ENTRY], OutFormat.jsonl)
    lines = [line for line in out.splitlines() if line]
    assert len(lines) == 2
    assert all(json.loads(line)["cn"] == "matteo" for line in lines)


def test_pprint_json_is_a_single_json_array() -> None:
    out = _pprint([ENTRY, ENTRY], OutFormat.json)
    parsed = json.loads(out)
    assert isinstance(parsed, list)
    assert len(parsed) == 2
    assert parsed[0]["cn"] == "matteo"
    assert parsed[0]["when"] == "2020-01-01 12:00:00"


def test_pprint_csv_joins_lists_with_pipe() -> None:
    out = _pprint([ENTRY], OutFormat.csv).strip()
    # keys are sorted: cn, groups, when
    fields = out.split("\t")
    assert fields[0] == "matteo"
    assert fields[1] == "g1|g2"
    assert fields[2] == "2020-01-01 12:00:00"


def test_pprint_empty_returns_input() -> None:
    assert _pprint([], OutFormat.json) == []
    assert _pprint(None, OutFormat.json) is None
