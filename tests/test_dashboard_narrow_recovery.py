"""Preserve original redaction rules while containing URL parser failures."""

from copy import deepcopy
from json import JSONDecoder, dumps, loads
from urllib.parse import urlencode

import pytest
from aiohttp.test_utils import make_mocked_request

from claude_tap import dashboard
from claude_tap.compact_trace import load_compact_trace, materialize_compact_trace_bundle
from claude_tap.live import LiveViewerServer
from claude_tap.proxy import _build_record
from claude_tap.trace_store import get_trace_store

SECRET = "credentialvalue42"
ORIGINAL_SOURCE = "// Deliverables： only\nconst result = ready ? token === expected : fallback;\n"
AMBIGUOUS_SOURCE = [
    ORIGINAL_SOURCE,
    "// Deliverables： only\n.foo { background: url(/next?token=" + SECRET + "); }",
    "// Deliverables： only\nconst uri = `//host：443/path?token=" + SECRET + "`;",
]


def redact_text(value: str) -> str:
    records = [{"content": value, "neighbor": "keep", "turn": 2}]
    original = deepcopy(records)
    result = dashboard.redact_dashboard_records(records)
    assert records == original
    assert result[0]["neighbor"] == "keep"
    assert result[0]["turn"] == 2
    return result[0]["content"]


# These expected values come from the original successful parser path. Some
# preserve inherited recognition limits; URL recovery must not expand them.
@pytest.mark.parametrize(
    ("value", "expected"),
    [
        ("ordinary public text", "ordinary public text"),
        ("[INFO] build succeeded", "[INFO] build succeeded"),
        ("const obj = {count:1};", "const obj = {count:1};"),
        ("https://h/p?a=1&copy=2", "https://h/p?a=1&copy=2"),
        ("token=fake-secret&%63opy=keep", "token=REDACTED&copy=keep"),
        ("/next ? token = " + SECRET, "/next ?+token+=REDACTED"),
        ("/a b?token =" + SECRET, "/a b?token+=REDACTED"),
        ("//h ?token =" + SECRET, "//h ?token+=REDACTED"),
        ("relative/path ?\ntoken\n=\n" + SECRET, "relative/path ?token=REDACTED"),
        (
            "\x00https://host/path?access_\r\ntoken=" + SECRET + "&public=keep",
            "https://host/path?access_token=REDACTED&public=keep",
        ),
        ("token=" + SECRET + "&public=keep", "token=REDACTED&public=keep"),
        ('{"token":"' + SECRET + '","public":["keep",3]}', '{"token":"REDACTED","public":["keep",3]}'),
        (
            "https://host/path?token=" + SECRET + "&odd%20key=keep",
            "https://host/path?token=REDACTED&odd+key=keep",
        ),
        (
            "<https://host/path?token=" + SECRET + '>; rel="next"',
            "<https://host/path?token=REDACTED",
        ),
        (
            'const uri = "https://host/path?token=' + SECRET + '";',
            'const uri = "https://host/path?token=' + SECRET + '";',
        ),
        (r'const uri = "/next\u003ftoken=' + SECRET + '";', r'const uri = "/next\u003ftoken=' + SECRET + '";'),
        ('[INFO] {"token":"' + SECRET + '"}', '[INFO] {"token":"' + SECRET + '"}'),
        ("payload=api+key%3D" + SECRET, "payload=api+key%3D" + SECRET),
        ("payload=%2574oken%3D" + SECRET, "payload=%2574oken%3D" + SECRET),
        (
            '{"payload":"token=' + SECRET + '","payload":"public"}',
            '{"payload":"token=' + SECRET + '","payload":"public"}',
        ),
    ],
)
def test_successful_normal_parser_outputs_retain_original_contract(value: str, expected: str) -> None:
    assert redact_text(value) == expected


@pytest.mark.parametrize(
    ("value", "depth", "expected"),
    [
        ("token=" + SECRET, 7, "token=REDACTED"),
        ("token=" + SECRET, 8, "token=" + SECRET),
        ("%74oken=" + SECRET, 0, "%74oken=" + SECRET),
        ("ordinary value", 0, "ordinary value"),
    ],
)
def test_nested_hint_and_depth_gates_retain_original_contract(value: str, depth: int, expected: str) -> None:
    assert dashboard._redact_nested_sensitive_text(value, depth) == expected


def test_sensitive_dictionary_keys_and_nulls_retain_original_contract() -> None:
    original = [{"authorization": "captured-prefix...", "password": None, "public": ["keep", {"api_key": SECRET}]}]
    saved = deepcopy(original)
    assert dashboard.redact_dashboard_records(original) == [
        {"authorization": "REDACTED", "password": None, "public": ["keep", {"api_key": "REDACTED"}]}
    ]
    assert original == saved


@pytest.mark.parametrize("authority", ["https://host：443", "https://[broken", "//host：443"])
@pytest.mark.parametrize(
    ("query", "expected_query"),
    [
        ("token=" + SECRET + "&public=keep", "token=REDACTED&public=keep"),
        ("%74oken=" + SECRET + "&token=&public=&flag", "token=REDACTED&token=REDACTED&public=&flag="),
        ("access_\r\ntoken=" + SECRET + "&public=keep", "access_token=REDACTED&public=keep"),
        (
            urlencode({"payload": "client_secret=" + SECRET + "&public=keep"}),
            urlencode({"payload": "client_secret=REDACTED&public=keep"}),
        ),
        (
            urlencode({"payload": '{"token":"' + SECRET + '","public":["keep",3]}'}),
            urlencode({"payload": '{"token":"REDACTED","public":["keep",3]}'}),
        ),
        (
            urlencode({"redirect_uri": "https://nested.example/path?token=" + SECRET + "&public=keep"}),
            urlencode({"redirect_uri": "https://nested.example/path?token=REDACTED&public=keep"}),
        ),
        ("public=keep&flag", "public=keep&flag"),
    ],
)
def test_failed_authority_uses_original_query_and_nested_rules(authority: str, query: str, expected_query: str) -> None:
    normal = redact_text("https://host/path?" + query + "#fragment")
    repaired = redact_text(authority + "/path?" + query + "#fragment")
    assert normal == "https://host/path?" + expected_query + "#fragment"
    assert repaired == authority + "/path?" + expected_query + "#fragment"
    assert redact_text(repaired) == repaired


@pytest.mark.parametrize("authority", ["https://host：443", "https://[broken"])
def test_recovery_restores_authority_by_component_without_restoring_sensitive_query(authority: str) -> None:
    suffix = "/redaction.invalid?token=" + SECRET + "&public=redaction.invalid#redaction.invalid"
    assert redact_text(authority + suffix) == authority + suffix.replace(SECRET, "REDACTED")


@pytest.mark.parametrize("source", AMBIGUOUS_SOURCE)
def test_failed_parse_of_ambiguous_source_masks_only_its_field(source: str) -> None:
    assert redact_text(source) == "REDACTED"


@pytest.mark.parametrize("delimiter", ["？", "＃", "／", "＠"])
def test_recovery_never_restores_authority_with_new_normalized_component_boundaries(delimiter: str) -> None:
    value = "https://host" + delimiter + "token=" + SECRET + "/path?public=keep"
    assert redact_text(value) == "REDACTED"


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        (ORIGINAL_SOURCE, "REDACTED"),
        (AMBIGUOUS_SOURCE[1], "REDACTED"),
        (
            "https://host：443/path?token=" + SECRET + "&public=keep",
            "https://host：443/path?token=REDACTED&public=keep",
        ),
    ],
)
@pytest.mark.asyncio
async def test_display_recovery_preserves_captured_auth_and_raw_downloads(trace_db, text: str, expected: str) -> None:
    auth_tail = "capture-auth-hidden-tail-9284"
    original_authorization = "Bearer abcdefghij-" + auth_tail
    captured = _build_record(
        "req_narrow_recovery",
        1,
        10,
        "POST",
        "/v1/messages",
        {"Authorization": original_authorization, "Cookie": "session=" + auth_tail, "X-Public": "keep"},
        {"system": text, "messages": [{"role": "user", "content": text}]},
        200,
        {"Set-Cookie": "session=" + auth_tail},
        {"content": [{"type": "text", "text": "Checked."}]},
    )
    assert captured["request"]["headers"]["Authorization"] == original_authorization[:12] + "..."
    assert captured["request"]["headers"]["Cookie"] == "***"
    assert captured["response"]["headers"]["Set-Cookie"] == "***"
    assert auth_tail not in dumps(captured)
    saved = deepcopy(captured)
    store = get_trace_store()
    session_id = store.create_session(client="claude", proxy_mode="reverse")
    store.append_record(session_id, captured)
    connection = store._connect()
    raw_payload = connection.execute("SELECT payload_json FROM records WHERE session_id=?", (session_id,)).fetchone()[0]
    raw_jsonl = store.export_jsonl(session_id)
    raw_compact = store.export_compact(session_id)
    server = LiveViewerServer(host="127.0.0.1", port=0)

    def request(suffix: str):
        return make_mocked_request("GET", "/api/sessions/" + session_id + suffix, match_info={"session_id": session_id})

    records_response = await server._handle_session_records(request("/records"))
    assert records_response.status == 200
    displayed = loads(records_response.text)["records"][0]
    assert displayed["request"]["body"]["system"] == expected
    assert displayed["request"]["body"]["messages"][0]["content"] == expected
    assert displayed["request"]["headers"]["Authorization"] == "REDACTED"
    assert displayed["request"]["headers"]["Cookie"] == "REDACTED"
    assert displayed["request"]["headers"]["X-Public"] == "keep"
    html_response = await server._handle_session_html_compat(request("/html"))
    assert html_response.status == 200
    assert SECRET not in html_response.text
    assert auth_tail not in html_response.text
    assert "REDACTED" in html_response.text

    jsonl_response = await server._handle_export_jsonl(request("/export/jsonl"))
    assert jsonl_response.status == 200
    assert jsonl_response.text == raw_jsonl
    assert loads(jsonl_response.text) == saved
    compact_response = await server._handle_export_compact(request("/export/compact"))
    assert compact_response.status == 200
    assert compact_response.text == raw_compact
    assert load_compact_trace(compact_response.text) == [saved]
    download_response = await server._handle_export_html(request("/export/html"))
    assert download_response.status == 200
    embedded = download_response.text.partition("const EMBEDDED_TRACE_COMPACT_DATA = ")[2]
    bundle, _ = JSONDecoder().raw_decode(embedded)
    assert materialize_compact_trace_bundle(bundle) == [saved]
    assert auth_tail not in download_response.text
    assert captured == saved
    assert store.load_records(session_id) == [saved]
    assert (
        connection.execute("SELECT payload_json FROM records WHERE session_id=?", (session_id,)).fetchone()[0]
        == raw_payload
    )
