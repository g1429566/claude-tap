"""Regression tests for dashboard cache repairs racing with trace writers."""

import json
from datetime import datetime, timezone

import pytest

from claude_tap.dashboard import DASHBOARD_SUMMARY_VERSION, _session_summary_from_row
from claude_tap.trace_store import SessionQuery, get_trace_store


def _record(turn: int, *, input_tokens: int, output_tokens: int) -> dict:
    return {
        "timestamp": f"2026-05-20T03:0{turn - 1}:00+00:00",
        "turn": turn,
        "request": {
            "method": "POST",
            "path": "/v1/messages",
            "body": {
                "model": "claude-sonnet-4-6",
                "messages": [{"role": "user", "content": f"https://host/path?access_\ntoken=prompt-secret-{turn}"}],
            },
        },
        "response": {
            "status": 200,
            "body": {
                "content": [{"type": "text", "text": f"https://host/path?access_\ntoken=reply-secret-{turn}"}],
                "usage": {"input_tokens": input_tokens, "output_tokens": output_tokens},
            },
        },
    }


def _stale_active_session(store) -> str:
    session_id = store.create_session(
        client="claude",
        proxy_mode="reverse",
        started_at=datetime(2026, 5, 20, 3, tzinfo=timezone.utc),
    )
    store.append_record(session_id, _record(1, input_tokens=11, output_tokens=3))
    cached = json.loads(store.load_session_row(session_id)["summary_json"])
    cached.update(
        summary_version=4,
        first_user="https://host/path?access_ token=prompt-secret-1",
        last_response="https://host/path?access_ token=reply-secret-1",
    )
    conn = store._connect()
    conn.execute(
        "UPDATE sessions SET summary_json = ? WHERE id = ?",
        (json.dumps(cached, ensure_ascii=False, separators=(",", ":")), session_id),
    )
    conn.commit()
    return session_id


def _raw_payloads(store, session_id: str) -> list[str]:
    return [
        row["payload_json"]
        for row in store._connect().execute(
            "SELECT payload_json FROM records WHERE session_id = ? ORDER BY record_index", (session_id,)
        )
    ]


def _assert_repaired_summary(summary, row, *, input_tokens: int, output_tokens: int) -> None:
    cached = json.loads(row["summary_json"])
    for candidate in (summary, cached):
        assert candidate["status"] == row["status"]
        assert candidate["active"] == (row["status"] == "active")
        assert candidate["updated_at"] == row["updated_at"]
        assert candidate["record_count"] == row["record_count"]
        assert candidate["input_tokens"] == input_tokens
        assert candidate["output_tokens"] == output_tokens
        assert candidate["total_tokens"] == input_tokens + output_tokens
        assert candidate["summary_version"] == DASHBOARD_SUMMARY_VERSION
        assert candidate["first_user"] == "https://host/path?access_token=REDACTED"
        assert candidate["last_response"] == "https://host/path?access_token=REDACTED"
        assert "prompt-secret" not in json.dumps(candidate)
        assert "reply-secret" not in json.dumps(candidate)


def test_stale_summary_repair_preserves_newer_heartbeat_timestamp(trace_db) -> None:
    store = get_trace_store()
    session_id = _stale_active_session(store)
    store.append_log(session_id, "heartbeat")
    row = store.load_session_row(session_id)
    raw_payloads = _raw_payloads(store, session_id)
    assert row["updated_at"] != "2026-05-20T03:00:00+00:00"

    summary = _session_summary_from_row(store, row)
    repaired_row = store.load_session_row(session_id)

    assert repaired_row["status"] == row["status"]
    assert repaired_row["updated_at"] == row["updated_at"]
    _assert_repaired_summary(summary, repaired_row, input_tokens=11, output_tokens=3)
    assert _raw_payloads(store, session_id) == raw_payloads


@pytest.mark.parametrize("event", ["finalize", "append", "heartbeat"])
def test_stale_summary_repair_reloads_snapshot_after_writer_update(trace_db, monkeypatch, event: str) -> None:
    store = get_trace_store()
    session_id = _stale_active_session(store)
    old_row = store.load_session_row(session_id)
    original_load = store.load_boundary_records
    expected = {}

    def load_then_update(requested_session_id):
        records = original_load(requested_session_id)
        if not expected:
            if event == "finalize":
                store.finalize_session(
                    session_id, {"api_calls": 1, "input_tokens": 13, "output_tokens": 7, "duration_ms": 73}
                )
            elif event == "append":
                store.append_record(session_id, _record(2, input_tokens=17, output_tokens=7))
            else:
                store.append_log(session_id, "heartbeat during repair")
            expected["row"] = store.load_session_row(session_id)
            expected["payloads"] = _raw_payloads(store, session_id)
        return records

    monkeypatch.setattr(store, "load_boundary_records", load_then_update)
    summary = _session_summary_from_row(store, old_row)
    repaired_row = store.load_session_row(session_id)

    for key in ("status", "updated_at", "record_count"):
        assert repaired_row[key] == expected["row"][key]
    assert repaired_row["status"] == ("complete" if event == "finalize" else "active")
    assert repaired_row["record_count"] == (2 if event == "append" else 1)
    input_tokens, output_tokens = {"finalize": (13, 7), "append": (28, 10), "heartbeat": (11, 3)}[event]
    _assert_repaired_summary(summary, repaired_row, input_tokens=input_tokens, output_tokens=output_tokens)
    if event == "finalize":
        assert summary["duration_ms"] == 73
    assert _raw_payloads(store, session_id) == expected["payloads"]
    expected_records = [_record(1, input_tokens=11, output_tokens=3)]
    if event == "append":
        expected_records.append(_record(2, input_tokens=17, output_tokens=7))
    assert store.load_records(session_id) == expected_records


@pytest.mark.parametrize("cache_version", [4, DASHBOARD_SUMMARY_VERSION])
def test_summary_repair_preserves_active_error_filters(trace_db, cache_version: int) -> None:
    store = get_trace_store()
    session_id = store.create_session(client="claude", proxy_mode="reverse")
    record = _record(1, input_tokens=11, output_tokens=3)
    record["response"]["status"] = 500
    record["response"]["body"]["error"] = "upstream failure"
    store.append_record(session_id, record)
    old_row = store.load_session_row(session_id)
    cached = json.loads(old_row["summary_json"])
    assert cached["status"] == "error"
    cached["summary_version"] = cache_version
    conn = store._connect()
    conn.execute("UPDATE sessions SET summary_json = ? WHERE id = ?", (json.dumps(cached), session_id))
    conn.commit()
    old_row = store.load_session_row(session_id)
    raw_payloads = _raw_payloads(store, session_id)
    assert store.get_session_aggregates()["total_errors"] == 1

    summary = _session_summary_from_row(store, old_row)
    repaired_row = store.load_session_row(session_id)
    repaired_cache = json.loads(repaired_row["summary_json"])

    assert repaired_row["status"] == summary["status"] == "active"
    assert repaired_row["updated_at"] == summary["updated_at"] == old_row["updated_at"]
    assert repaired_cache["status"] == "error"
    assert repaired_cache["error"] == summary["error"] == "upstream failure"
    assert repaired_cache["summary_version"] == DASHBOARD_SUMMARY_VERSION
    assert store.get_session_aggregates()["total_errors"] == 1
    assert store.count_session_rows(SessionQuery(status="error")) == 1
    assert store.count_session_rows(SessionQuery(status="active")) == 0
    assert _raw_payloads(store, session_id) == raw_payloads
    assert store.load_records(session_id) == [record]
