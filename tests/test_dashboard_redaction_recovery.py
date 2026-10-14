"""Contracts for authority-error recovery and confirmed-URI parsing."""

import json
from urllib.parse import quote_plus

import aiohttp
import pytest

from claude_tap.dashboard import DASHBOARD_SUMMARY_VERSION, redact_dashboard_records
from claude_tap.live import LiveViewerServer
from claude_tap.trace_store import get_trace_store


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        ("HTTPS://host/path?token=secret#", "HTTPS://host/path?token=REDACTED#"),
        ("//host/path?token=secret", "//host/path?token=REDACTED"),
        ("/path?token=&token=secret&flag", "/path?token=&token=REDACTED&flag="),
        ("https://host/path?access_\ntoken=secret", "https://host/path?access_token=REDACTED"),
        ("https://host/path?token=secret\n", "https://host/path?token=REDACTED\n"),
        (
            "https://host/path?payload=client_se\ncret=secret",
            "https://host/path?payload=client_secret%3DREDACTED",
        ),
        ("https://host/path?label=\ud800&token=secret", "https://host/path?label=%ED%A0%80&token=REDACTED"),
    ],
)
def test_successful_url_parser_retains_query_cleanup_and_presentation(value: str, expected: str) -> None:
    record = {"content": value}
    assert redact_dashboard_records([record]) == [{"content": expected}]
    assert record == {"content": value}


@pytest.mark.parametrize(
    "expression",
    [
        "left : right",
        "left : token",
        "token === expected : fallback",
        "token != expected : fallback",
        "token <= expected : fallback",
        "token >= expected : fallback",
        "(token === expected) : fallback",
    ],
)
def test_authority_error_preserves_source_comparisons(expression: str) -> None:
    text = f"// Deliverables： only\nconst result = ready ? {expression};"
    record = {"old_string": text, "access_token": "sibling-secret"}
    assert redact_dashboard_records([record]) == [{"old_string": text, "access_token": "REDACTED"}]
    assert record == {"old_string": text, "access_token": "sibling-secret"}


@pytest.mark.parametrize(
    ("assignment", "redacted"),
    [
        ("token=actual-secret", "token=REDACTED"),
        ("token = actual-secret", "token = REDACTED"),
        ("token=\nactual-secret", "token=\nREDACTED"),
        ("token=\r\n'actual-secret'", "token=\r\n'REDACTED'"),
        ('token="actual secret & more"', 'token="REDACTED"'),
        ('token="actual-secret#keep"', 'token="REDACTED"'),
        ("token='actual secret'", "token='REDACTED'"),
        ("access_%74oken=%3Dactual-secret", "access_%74oken=REDACTED"),
        ("access_\ntoken=actual-secret", "access_\ntoken=REDACTED"),
        ("payload=client_secret%3Dactual-secret", "payload=client_secret%3DREDACTED"),
        ('payload="{\\"token\\":\\"actual-secret\\"}"', 'payload="{\\"token\\":\\"REDACTED\\"}"'),
    ],
)
def test_authority_error_masks_only_source_assignment_value(assignment: str, redacted: str) -> None:
    prefix = "// Deliverables： only\nconst result = ready ? "
    suffix = " : fallback;\n// keep this code"
    text = prefix + assignment + suffix
    assert redact_dashboard_records([{"old_string": text}]) == [{"old_string": prefix + redacted + suffix}]


@pytest.mark.parametrize(
    "expression", ["(secret)", "{secret}", "[secret]", "func(secret)", '"secret" + fallback', "/* secret */ foo"]
)
def test_exception_source_grammar_does_not_partially_rewrite_expressions(expression: str) -> None:
    text = f"// Deliverables： only\nready?token={expression}:fallback;"
    assert redact_dashboard_records([{"old_string": text}]) == [{"old_string": text}]


def test_source_hash_before_query_is_not_a_uri_fragment() -> None:
    text = "// Deliverables： #keep\nready?token=actual-secret:fallback;"
    expected = "// Deliverables： #keep\nready?token=REDACTED:fallback;"
    assert redact_dashboard_records([{"old_string": text}]) == [{"old_string": expected}]


@pytest.mark.parametrize("suffix", [" // keep comment", " /* keep comment */ : fallback"])
def test_complete_source_literal_can_be_followed_by_a_comment(suffix: str) -> None:
    text = '// Deliverables： only\nready?token="actual-secret"' + suffix
    expected = '// Deliverables： only\nready?token="REDACTED"' + suffix
    assert redact_dashboard_records([{"old_string": text}]) == [{"old_string": expected}]


@pytest.mark.parametrize(
    "suffix",
    [
        " /* keep */ + other",
        "\n+ other",
        " // keep\n+ other",
        " // keep\r+ other",
        " // keep\u2028+ other",
        " // keep\u2029+ other",
        "\n.foo()",
    ],
)
@pytest.mark.parametrize("quote", ["'", '"'])
def test_exception_source_literal_expression_remains_complete(quote: str, suffix: str) -> None:
    text = f"// Deliverables： only\nready?token={quote}actual-secret{quote}{suffix}:fallback;"
    assert redact_dashboard_records([{"old_string": text}]) == [{"old_string": text}]


@pytest.mark.parametrize("quote", ["'", '"'])
def test_exception_does_not_interpret_quoted_prose_as_a_uri(quote: str) -> None:
    text = f"// Deliverables： only\nconst s = {quote}a / b ? token === expected : fallback{quote};"
    assert redact_dashboard_records([{"old_string": text}]) == [{"old_string": text}]


@pytest.mark.parametrize(
    "comment",
    [
        '// Deliverables： "only\n',
        "// Deliverables： 'only\n",
        '/* Deliverables： "only */\n',
        "/* Deliverables： 'only */\n",
        '// Deliverables： "only\r',
        '// Deliverables： "only\u2028',
    ],
)
def test_exception_comment_quotes_do_not_hide_following_assignment(comment: str) -> None:
    prefix = "// Deliverables： only\n" if comment.startswith("/*") else ""
    text = prefix + comment + 'ready?token=actual-secret:fallback;\nconst note="public";'
    assert redact_dashboard_records([{"old_string": text}]) == [
        {"old_string": text.replace("actual-secret", "REDACTED")}
    ]


@pytest.mark.parametrize("prefix", ["https://host/path", "https://host：443/path"])
def test_exception_uri_literal_preserves_unrelated_json_escape(prefix: str) -> None:
    literal = '"' + prefix + r'?token=actual-secret&public=\u0061"'
    text = "// Deliverables： only\nconst u = " + literal + ";"
    expected = "// Deliverables： only\nconst u = " + literal.replace("actual-secret", "REDACTED") + ";"
    assert redact_dashboard_records([{"old_string": text}]) == [{"old_string": expected}]


@pytest.mark.parametrize("key", ["href", "hrefs", "HREF"])
def test_named_href_has_local_uri_provenance_inside_json(key: str) -> None:
    record = {
        "body": json.dumps({key: "barefile?token=actual-secret", "old_string": "ready?token===expected:fallback"})
    }
    displayed = redact_dashboard_records([record])[0]
    assert json.loads(displayed["body"]) == {
        key: "barefile?token=REDACTED",
        "old_string": "ready?token===expected:fallback",
    }
    assert "actual-secret" in record["body"]


@pytest.mark.parametrize("control", ["\t", "\r", "\n"])
@pytest.mark.parametrize("key", ["content", "old_string", "text"])
def test_ordinary_absolute_uri_raw_controls_reach_standard_query_cleanup(key: str, control: str) -> None:
    value = f"https://host/path?access_{control}token=actual-secret#keep"
    assert redact_dashboard_records([{key: value}]) == [{key: "https://host/path?access_token=REDACTED#keep"}]


@pytest.mark.parametrize("quote", ["'", '"'])
@pytest.mark.parametrize(
    "prefix", ["//bad：host/path", "https://bad：host/path", "https://host/path", "/path", "relative/path"]
)
def test_uri_literals_in_source_do_not_get_comparison_exemption(quote: str, prefix: str) -> None:
    text = f"// Deliverables： only\nconst u = {quote}{prefix}?token===actual-secret{quote};"
    expected = f"// Deliverables： only\nconst u = {quote}{prefix}?token=REDACTED{quote};"
    assert redact_dashboard_records([{"old_string": text}]) == [{"old_string": expected}]


@pytest.mark.parametrize(
    ("query", "expected_query"),
    [
        (r"\u003ftoken=actual-secret", r"\u003ftoken=REDACTED"),
        (r"?token\u003dactual-secret", r"?token\u003dREDACTED"),
        (r"?label=one two\u0026token=actual-secret", r"?label=one two\u0026token=REDACTED"),
        (r"?token=actual-secret\u0023fragment", r"?token=REDACTED\u0023fragment"),
        (r"?access_\u0074oken=actual-secret&public=\u0061", r"?access_\u0074oken=REDACTED&public=\u0061"),
        (r"?payload=client_se\ncret%3Dactual-secret&public=\u0061", r"?payload=client_secret%3DREDACTED&public=\u0061"),
    ],
)
@pytest.mark.parametrize("quote", ["'", '"'])
def test_exception_uri_literal_uses_decoded_boundaries_and_original_spans(
    query: str, expected_query: str, quote: str
) -> None:
    text = f"// Deliverables： only\nconst u = {quote}https://host：443/path{query}{quote};"
    expected = f"// Deliverables： only\nconst u = {quote}https://host：443/path{expected_query}{quote};"
    assert redact_dashboard_records([{"old_string": text}]) == [{"old_string": expected}]


def test_exception_single_quoted_uri_recognizes_ascii_hex_escape() -> None:
    text = r"// Deliverables： only" + "\n" + r"const u='https://host：443/path?tok\x65n=actual-secret&public=\x61';"
    assert redact_dashboard_records([{"old_string": text}]) == [
        {"old_string": text.replace("actual-secret", "REDACTED")}
    ]


@pytest.mark.parametrize("quote", ["'", '"'])
@pytest.mark.parametrize(
    ("query", "expected_query"),
    [
        (r"?tok\x65n===actual-secret", r"?tok\x65n=REDACTED"),
        (r"\x3ftoken=actual-secret", r"\x3ftoken=REDACTED"),
        (r"?token\x3dactual-secret", r"?token\x3dREDACTED"),
        (r"?public=one\x26token=actual-secret", r"?public=one\x26token=REDACTED"),
        (r"?\u0074oken=actual-secret&public=\x61", r"?\u0074oken=REDACTED&public=\x61"),
        (r"?\u0074oken=actual-secret&public=\q", r"?\u0074oken=REDACTED&public=\q"),
    ],
)
def test_exception_uri_quotes_share_unit_decoding_and_original_spans(
    quote: str, query: str, expected_query: str
) -> None:
    text = f"// Deliverables： only\nconst u={quote}https://host：443/path{query}{quote};"
    expected = f"// Deliverables： only\nconst u={quote}https://host：443/path{expected_query}{quote};"
    assert redact_dashboard_records([{"old_string": text}]) == [{"old_string": expected}]


@pytest.mark.parametrize("literal", [r"'\unknown'", r"'\xZZ'", r"'\u123'", r"'\u{74}ext'", r'"\unknown"'])
def test_exception_preserves_unsupported_literal_escape_without_raising(literal: str) -> None:
    text = f"// Deliverables： only\nconst s={literal};\nready ? left:right;"
    assert redact_dashboard_records([{"old_string": text}]) == [{"old_string": text}]


@pytest.mark.parametrize("surrogate", ["\\ud800", "\\udfff"])
def test_exception_nested_json_escape_does_not_introduce_unsafe_source_units(surrogate: str) -> None:
    nested = '{"token":"actual-secret","label":"' + surrogate + '"}'
    literal = json.dumps(nested)
    text = "// Deliverables： only\nready ? payload=" + literal + " : fallback;"
    displayed = redact_dashboard_records([{"old_string": text}])[0]["old_string"]
    displayed.encode("utf-8")
    redacted_literal = displayed.partition("payload=")[2].partition(" : fallback;")[0]
    assert json.loads(json.loads(redacted_literal)) == {"token": "REDACTED", "label": json.loads('"' + surrogate + '"')}


@pytest.mark.parametrize(
    "prefix", ["https://host：443/path", "//host：443/path", "//[unfinished/path", "https://[note]/path"]
)
@pytest.mark.parametrize("value", ["actual-secret", "==actual-secret", "%3Dactual-secret"])
def test_invalid_uri_query_values_do_not_get_comparison_exemption(prefix: str, value: str) -> None:
    original = f"{prefix}?access_%74oken={value}&public=one%20two#fragment?token=public"
    expected = f"{prefix}?access_token=REDACTED&public=one+two#fragment?token=public"
    assert redact_dashboard_records([{"content": original}]) == [{"content": expected}]


def test_invalid_uri_nested_credentials_reuse_existing_query_encoding() -> None:
    nested = quote_plus(json.dumps({"token": "actual-secret", "public": "one two"}))
    value = "https://host：443/path?payload=" + nested + "&public=one%20two#keep"
    expected_nested = quote_plus('{"token":"REDACTED","public":"one two"}')
    assert redact_dashboard_records([{"url": value}]) == [
        {"url": "https://host：443/path?payload=" + expected_nested + "&public=one+two#keep"}
    ]


@pytest.mark.parametrize("escape", [r"\u0026", r"\u0023", r"\u003d"])
def test_nested_json_cannot_introduce_outer_query_delimiters(escape: str) -> None:
    value = 'https://host：443/path?payload={"token":"secret","public":"a' + escape + 'b"}&other=one#keep'
    redacted = redact_dashboard_records([{"url": value}])[0]["url"]
    from urllib.parse import parse_qs

    pairs = parse_qs(redacted.partition("?")[2].partition("#")[0])
    assert pairs["other"] == ["one"]
    assert json.loads(pairs["payload"][0]) == {"token": "REDACTED", "public": json.loads('"a' + escape + 'b"')}
    assert redacted.endswith("&other=one#keep")


def test_exception_uri_origin_resolves_the_documented_comment_ambiguity() -> None:
    value = "//note：\nready?token===actual-secret"
    assert redact_dashboard_records([{"old_string": value}]) == [{"old_string": value}]
    assert redact_dashboard_records([{"url": value}]) == [{"url": "//note：\nready?token=REDACTED"}]


def test_invalid_uri_query_redaction_retains_surrogate_encoding() -> None:
    value = "https://host：443/path?label=\ud800&token=secret&public=one%20two"
    expected = "https://host：443/path?label=%ED%A0%80&token=REDACTED&public=one+two"
    assert redact_dashboard_records([{"url": value}]) == [{"url": expected}]


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("text", "expected"),
    [
        (
            "// Deliverables： only\nconst result = ready ? token === expected : fallback;",
            "// Deliverables： only\nconst result = ready ? token === expected : fallback;",
        ),
        *[
            (f"https://host/path?access_{control}token=actual-secret", "https://host/path?access_token=REDACTED")
            for control in ("\t", "\r", "\n")
        ],
        *[
            (
                f"https://host/path?payload=client_se{control}cret=actual-secret",
                "https://host/path?payload=client_secret%3DREDACTED",
            )
            for control in ("\t", "\r", "\n")
        ],
    ],
)
@pytest.mark.parametrize("cache_state", ["current", "stale-active", "stale-complete"])
async def test_recovery_records_and_html_preserve_capture(trace_db, text: str, expected: str, cache_state: str) -> None:
    store = get_trace_store()
    session_id = store.create_session(client="claude", proxy_mode="reverse")
    record = {
        "turn": 1,
        "timestamp": "2026-10-14T03:00:00Z",
        "request": {
            "method": "POST",
            "path": "/v1/messages",
            "url": "https://api.example/v1/messages?token=url-secret",
            "headers": {"Authorization": "Bearer header-secret"},
            "body": {"model": "test-model", "system": text, "messages": [{"role": "user", "content": text}]},
        },
        "response": {
            "status": 200,
            "body": {"content": [{"type": "text", "text": text}], "usage": {"input_tokens": 1, "output_tokens": 1}},
        },
    }
    store.append_record(session_id, record)
    if cache_state != "current":
        cached = json.loads(store.load_session_row(session_id)["summary_json"])
        cached.update(
            summary_version=DASHBOARD_SUMMARY_VERSION - 1,
            first_user=" ".join(text.split()),
            last_response=" ".join(text.split()),
        )
        conn = store._connect()
        conn.execute(
            "UPDATE sessions SET status = ?, summary_json = ? WHERE id = ?",
            ("complete" if cache_state == "stale-complete" else "active", json.dumps(cached), session_id),
        )
        conn.commit()
    conn = store._connect()
    captured_json = conn.execute("SELECT payload_json FROM records WHERE session_id = ?", (session_id,)).fetchone()[0]
    server = LiveViewerServer(port=0, dashboard_mode=True)
    port = await server.start()
    try:
        async with aiohttp.ClientSession() as session:
            async with session.get(f"http://127.0.0.1:{port}/api/sessions/{session_id}/records") as response:
                assert response.status == 200
                payload = await response.json()
                displayed = payload["records"][0]["request"]
                assert displayed["body"]["messages"][0]["content"] == expected
                assert displayed["headers"]["Authorization"] == "REDACTED"
                assert displayed["url"].endswith("?token=REDACTED")
                assert payload["session"]["first_user"] == " ".join(expected.split())
                assert payload["session"]["last_response"] == " ".join(expected.split())
                assert "actual-secret" not in json.dumps(payload)
                assert "header-secret" not in json.dumps(payload)
                assert "url-secret" not in json.dumps(payload)
            async with session.get(f"http://127.0.0.1:{port}/api/sessions/{session_id}/html") as response:
                assert response.status == 200
                html = await response.text()
                metadata_json = html.partition("const EMBEDDED_TRACE_META = ")[2].partition(";\n")[0]
                metadata = json.loads(metadata_json.replace("<\\/", "</"))[0]
                assert metadata["session_user_text"] == expected
                assert metadata["sys_hint"] == expected
                assert "actual-secret" not in html
    finally:
        await server.stop()
    assert store.load_records(session_id) == [record]
    assert (
        json.loads(store.load_session_row(session_id)["summary_json"])["summary_version"] == DASHBOARD_SUMMARY_VERSION
    )
    assert (
        captured_json
        == conn.execute("SELECT payload_json FROM records WHERE session_id = ?", (session_id,)).fetchone()[0]
    )
