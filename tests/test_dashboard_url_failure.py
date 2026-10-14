"""Contracts for exception-only URL recovery using the original redactors."""

import json
from itertools import product
from urllib.parse import quote_plus

import aiohttp
import pytest

from claude_tap import dashboard
from claude_tap.live import LiveViewerServer
from claude_tap.trace_store import get_trace_store


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        ("https://host/path?token=secret&label=public ", "https://host/path?token=REDACTED&label=public+"),
        ("https://host/path?token=secret\t", "https://host/path?token=REDACTED"),
        ("HTTPS://host/path?token=secret#", "https://host/path?token=REDACTED"),
        (" https://host/path?token=secret", "https://host/path?token=REDACTED"),
        ("/path?token=&flag", "/path?token=REDACTED&flag="),
        ("?token=secret", "?token=REDACTED"),
        ("relative/path?token=secret", "relative/path?token=REDACTED"),
        ("https://host/path?access_\ntoken=secret", "https://host/path?access_token=REDACTED"),
        ("token=secret&label=public", "token=REDACTED&label=public"),
        ("plain text without a URI", "plain text without a URI"),
        (
            "const result = ready ? token =~/expected/ : fallback;",
            "const result = ready ? token =~/expected/ : fallback;",
        ),
        (
            '{"url":"https://host/path?token=secret","label":"public"}',
            '{"url":"https://host/path?token=REDACTED","label":"public"}',
        ),
    ],
)
def test_normal_redaction_retains_original_outputs_without_recovery(monkeypatch, value: str, expected: str) -> None:
    def unexpected_recovery(*args):
        pytest.fail("Successful URL parsing must not invoke exception recovery")

    monkeypatch.setattr(dashboard, "_redact_failed_url_text", unexpected_recovery)
    record = {"content": value}
    assert dashboard.redact_dashboard_records([record]) == [{"content": expected}]
    assert record == {"content": value}


@pytest.mark.parametrize(
    "expression", ["token === expected", "token =~/expected/", "left : right", "token=actual-secret"]
)
@pytest.mark.parametrize("comment", ["// Deliverables： only", "//Deliverables： only", "//note："])
def test_failed_source_parse_does_not_run_assignment_grammar(expression: str, comment: str) -> None:
    text = f"{comment}\nconst result = ready ? {expression} : fallback;"
    assert dashboard.redact_dashboard_records([{"old_string": text}]) == [{"old_string": text}]


@pytest.mark.parametrize("authority", ["https://host：443", "https://[broken", "//host：443"])
@pytest.mark.parametrize("credential", ["actual-secret", "==actual-secret", "~actual-secret"])
def test_failed_uri_authorities_reuse_sensitive_query_rules(authority: str, credential: str) -> None:
    value = f"{authority}/path?token={credential}&label=public#keep"
    record = {"content": value}
    assert dashboard.redact_dashboard_records([record]) == [
        {"content": f"{authority}/path?token=REDACTED&label=public#keep"}
    ]
    assert record == {"content": value}


@pytest.mark.parametrize(
    ("query", "expected"),
    [
        ("payload=client_secret%3Dactual-secret", "payload=client_secret%3DREDACTED"),
        (
            "payload=%7B%22client_secret%22%3A%22actual-secret%22%2C%22public%22%3A%22keep%22%7D",
            "payload=%7B%22client_secret%22%3A%22REDACTED%22%2C%22public%22%3A%22keep%22%7D",
        ),
        ('payload={"client_secret":"actual-secret"}', "payload=%7B%22client_secret%22%3A%22REDACTED%22%7D"),
        ("access_\ntoken=actual-secret&label=public", "access_token=REDACTED&label=public"),
        ("%74oken=actual-secret&label=public", "token=REDACTED&label=public"),
    ],
)
def test_failed_uri_nested_values_use_original_query_and_field_rules(query: str, expected: str) -> None:
    value = "https://host：443/path?" + query + "#keep"
    record = {"content": value}
    assert dashboard.redact_dashboard_records([record]) == [{"content": "https://host：443/path?" + expected + "#keep"}]
    assert record["content"] == value


@pytest.mark.parametrize("quote", ["'", '"', "`"])
@pytest.mark.parametrize(
    "uri",
    [
        "https://host/path",
        "https://host：443/path",
        "//host：443/path",
        "/path",
        "relative/path",
        "",
        "mailto:public@example.com",
    ],
)
@pytest.mark.parametrize("value", ["==actual-secret", "~actual-secret"])
def test_simple_quoted_uris_keep_surrounding_source(quote: str, uri: str, value: str) -> None:
    prefix = "// Deliverables： only\nconst uri = "
    suffix = ";\nconst untouched = ready ? token =~/expected/ : fallback;"
    text = prefix + quote + uri + "?token=" + value + "&label=public#keep" + quote + suffix
    expected = prefix + quote + uri + "?token=REDACTED&label=public#keep" + quote + suffix
    assert dashboard.redact_dashboard_records([{"old_string": text}]) == [{"old_string": expected}]


@pytest.mark.parametrize(
    ("literal", "expected"),
    [
        ('"https://host：443/path?token=actual-secret;', "REDACTED"),
        ('"//host：443/path?token=actual-secret;', "REDACTED"),
        ('"/path?token=actual-secret;', "REDACTED"),
        ('"relative/path?token=actual-secret;', "REDACTED"),
        ('https://host：443/path?payload={"token":"actual-secret"};', "REDACTED"),
        ('"https://host：443/path?payload={"token":"actual-secret"}";', "REDACTED"),
        (r'"https://host：443/path?access_\u0074oken=actual-secret";', '"REDACTED";'),
        (r'"https:\/\/host：443/path?token=actual-secret";', '"REDACTED";'),
    ],
)
def test_final_fallback_hides_only_bounded_literal_or_uncertain_tail(literal: str, expected: str) -> None:
    prefix = "// Deliverables： only\nconst uri = "
    text = prefix + literal
    record = {"old_string": text}
    assert dashboard.redact_dashboard_records([record]) == [{"old_string": prefix + expected}]
    assert record == {"old_string": text}


@pytest.mark.parametrize("control", ["\t", "\r", "\n", "\r\n"])
@pytest.mark.parametrize(
    "query", ["access_{control}token=actual-secret", "payload=client_se{control}cret=actual-secret"]
)
def test_second_layer_cleans_quoted_query_controls_without_hiding_source(control: str, query: str) -> None:
    prefix = "// Deliverables： only\nconst uri = "
    suffix = ";\nconst keep = ready ? token =~/expected/ : fallback;"
    text = prefix + '"https://host：443/path?' + query.format(control=control) + '"' + suffix
    expected_query = "access_token=REDACTED" if query.startswith("access_") else "payload=client_secret%3DREDACTED"
    expected = prefix + '"https://host：443/path?' + expected_query + '"' + suffix
    record = {"old_string": text}
    assert dashboard.redact_dashboard_records([record]) == [{"old_string": expected}]
    assert record == {"old_string": text}


def test_second_layer_reuses_original_nested_json_redactor_in_bounded_literal() -> None:
    prefix = "// Deliverables： only\nconst uri = 'https://host：443/path?"
    suffix = "';\nconst keep = 1;"
    text = prefix + 'payload={"token":"actual-secret","public":"ok"}' + suffix
    expected = prefix + "payload=%7B%22token%22%3A%22REDACTED%22%2C%22public%22%3A%22ok%22%7D" + suffix
    record = {"old_string": text}
    assert dashboard.redact_dashboard_records([record]) == [{"old_string": expected}]
    assert record == {"old_string": text}


@pytest.mark.parametrize(
    "prefix",
    [
        "https\n://host：443/path",
        "https\r\n://host：443/path",
        "\x00//host：443/path",
        "//ho\nst：443/path",
        "//ho\tst：443/path",
    ],
)
def test_second_layer_recognizes_standard_parser_prefix_control_cleanup(prefix: str) -> None:
    text = prefix + "?token=actual-secret&label=public"
    record = {"old_string": text}
    assert dashboard.redact_dashboard_records([record]) == [{"old_string": prefix + "?token=REDACTED&label=public"}]
    assert record == {"old_string": text}


@pytest.mark.parametrize("prefix", ["//h：\n", "//ho\nst：443", "//ho\r\nst：443"])
@pytest.mark.parametrize("credential", ["s", "actual-secret", "==actual-secret"])
@pytest.mark.parametrize("quote", ["", "'", '"'])
def test_ambiguous_multiline_network_prefix_reuses_query_without_leaking(
    prefix: str, credential: str, quote: str
) -> None:
    uri = prefix + "?token=" + credential + "&public=keep#fragment"
    before = "// Deliverables： only\nconst uri=" if quote else ""
    after = ";\nconst keep=1;" if quote else ""
    text = before + quote + uri + quote + after
    expected = before + quote + prefix + "?token=REDACTED&public=keep#fragment" + quote + after
    record = {"old_string": text}
    assert dashboard.redact_dashboard_records([record]) == [{"old_string": expected}]
    assert record == {"old_string": text}


@pytest.mark.parametrize("quote", ["", "'", '"'])
def test_ambiguous_sensitive_query_that_original_rules_cannot_redact_hides_only_tail(quote: str) -> None:
    prefix = "//ho\nst：443?"
    before = "// Deliverables： only\nconst uri=" if quote else ""
    after = ";\nconst keep=1;" if quote else ""
    text = before + quote + prefix + "public=(token==actual-secret)" + quote + after
    expected = before + quote + prefix + "REDACTED" + quote + after
    record = {"old_string": text}
    assert dashboard.redact_dashboard_records([record]) == [{"old_string": expected}]
    assert record == {"old_string": text}


@pytest.mark.parametrize(
    ("expression", "masked_query"),
    [("token===expected", "token=REDACTED"), ("token =~/expected/ : fallback;", "token+=REDACTED")],
)
def test_uri_shaped_multiline_comment_uses_privacy_first_query_policy(expression: str, masked_query: str) -> None:
    prefix = "//note：\nready?"
    text = prefix + expression
    assert dashboard.redact_dashboard_records([{"old_string": text}]) == [{"old_string": prefix + masked_query}]


@pytest.mark.parametrize(
    "literal",
    [
        '"https://host：443/path?token=actual-secret;\nconst title="public";\nconst keep=1;',
        '\'https://host：443/path?payload={"token":"before\'actual-secret"}\';\nconst keep=1;',
    ],
)
def test_conflicting_source_quotes_do_not_count_as_safe_recovery(literal: str) -> None:
    prefix = "// Deliverables： only\nconst uri = "
    record = {"old_string": prefix + literal}
    assert dashboard.redact_dashboard_records([record]) == [{"old_string": prefix + "REDACTED"}]
    assert record == {"old_string": prefix + literal}


@pytest.mark.parametrize(
    "literal",
    [
        r'"https:\/\/host：443/path?token=actual-secret"',
        r'"https://host：443/path?tok\u0065n=actual-secret"',
        r'"https\u003a//host/path?token=actual-secret"',
        r'"https:\u002f\u002fhost/path?token=actual-secret"',
        r'"https:\x2f\x2fhost/path?token=actual-secret"',
    ],
)
def test_bounded_source_escapes_use_local_last_fallback_and_keep_following_source(literal: str) -> None:
    prefix = "// Deliverables： only\nconst uri = "
    suffix = ';\nconst title="public";\nconst keep=1;'
    record = {"old_string": prefix + literal + suffix}
    assert dashboard.redact_dashboard_records([record]) == [{"old_string": prefix + '"REDACTED"' + suffix}]
    assert record == {"old_string": prefix + literal + suffix}


def test_unsupported_quoted_nested_form_uses_local_last_fallback() -> None:
    prefix = "// Deliverables： only\nconst uri = "
    literal = "'https://host/path?payload=\"client_secret=actual-secret\"'"
    suffix = ";\nconst keep=1;"
    record = {"old_string": prefix + literal + suffix}
    assert dashboard.redact_dashboard_records([record]) == [{"old_string": prefix + "'REDACTED'" + suffix}]
    assert record == {"old_string": prefix + literal + suffix}


def test_second_layer_redacts_clear_network_query_despite_space_in_authority() -> None:
    text = "//host：443 /path?token=actual-secret"
    record = {"old_string": text}
    assert dashboard.redact_dashboard_records([record]) == [{"old_string": "//host：443 /path?token=REDACTED"}]
    assert record == {"old_string": text}


@pytest.mark.parametrize("path", ["", "/path", "/path;param=value"])
@pytest.mark.parametrize("quote", ["", "'", '"', "`"])
def test_network_uri_variations_never_expose_query_credentials(path: str, quote: str) -> None:
    # Independent input dimensions exercise the URI grammar, not the recovery regex.
    for delimiter in "!$&'()*+,;=:":
        uri = f"//user{delimiter}name@host：443{path}?access_token=actual-secret&public=keep#fragment"
        if quote:
            content = uri.replace(quote, "\\" + quote)
            text = "// Deliverables： only\nconst u = " + quote + content + quote + ";\nconst keep = 1;"
        else:
            text = uri
        record = {"old_string": text}
        output = dashboard.redact_dashboard_records([record])[0]["old_string"]
        assert "actual-secret" not in output, (delimiter, path, quote, output)
        assert "REDACTED" in output
        if quote and quote in uri:
            # Escaped source uses a bounded conservative replacement.
            assert output.endswith(quote + ";\nconst keep = 1;")
        else:
            assert output == text.replace("actual-secret", "REDACTED")
        assert record == {"old_string": text}


def test_failed_uri_query_combinations_preserve_public_text_and_hide_secrets() -> None:
    authorities = [
        "//host：443",
        "//user=name@host：443",
        "//[broken",
        "https://host：443",
        "https://[broken",
        "//host／part",
        "//host＠name",
        "//host＃part",
    ]
    queries = [
        "access_token=actual-secret",
        "%61ccess_token=actual-secret",
        "access_\ntoken=actual-secret",
        "payload=" + quote_plus("client_secret=actual-secret"),
        "payload=" + quote_plus('{"token":"actual-secret"}'),
    ]
    for authority, path, query, quote in product(authorities, ["", "/path"], queries, ["", "'", '"', "`"]):
        uri = authority + path + "?" + query + "&public=keep"
        before = "// Deliverables： only\nconst u = " + quote if quote else ""
        after = quote + ";\nconst keep = 1;" if quote else ""
        text = before + uri + after
        output = dashboard.redact_dashboard_records([{"old_string": text}])[0]["old_string"]
        assert "actual-secret" not in output, (text, output)
        assert output.startswith(before + authority + path + "?")
        assert output.endswith("&public=keep" + after)
        assert "REDACTED" in output


@pytest.mark.parametrize("quote", ["'", '"', "`"])
def test_multiple_uri_literals_are_each_processed(quote: str) -> None:
    first = "//user=name@host：443?token=first-secret"
    second = "//host：443?token=second-secret"
    text = f"// Deliverables： only\nconst a = {quote}{first}{quote}; const b = {quote}{second}{quote};"
    output = dashboard.redact_dashboard_records([{"old_string": text}])[0]["old_string"]
    assert output == text.replace("first-secret", "REDACTED").replace("second-secret", "REDACTED")


@pytest.mark.parametrize("comment", ["// Verify： ready", "//Verify： ready", "// Verify："])
@pytest.mark.parametrize("operator", ["===", "==", "=~", "!=", "<=", ">="])
def test_same_line_comment_query_does_not_consume_source(comment: str, operator: str) -> None:
    text = f"{comment}? token {operator} expected\nconst keep = 1;"
    assert dashboard.redact_dashboard_records([{"old_string": text}]) == [{"old_string": text}]


@pytest.mark.parametrize("quote", ["'", '"', "`"])
def test_unclosed_network_literal_without_path_reaches_final_fallback(quote: str) -> None:
    prefix = "// Deliverables： only\nconst u = "
    text = prefix + quote + "//user=name@host：443?access_token=actual-secret;"
    assert dashboard.redact_dashboard_records([{"old_string": text}]) == [{"old_string": prefix + "REDACTED"}]


def test_unsupported_network_authority_still_reaches_query_redaction() -> None:
    text = r"//user\name@host：443?access_token=actual-secret"
    assert dashboard.redact_dashboard_records([{"old_string": text}]) == [
        {"old_string": text.replace("actual-secret", "REDACTED")}
    ]


def test_unrecoverable_candidate_cannot_fall_through_as_safe(monkeypatch) -> None:
    # Simulate a representation the precise query layer cannot recover.
    monkeypatch.setattr(dashboard, "_redact_failed_uri_query", lambda *args, **kwargs: None)
    for value in (
        "//user=name@host：443?access_token=actual-secret",
        '// Deliverables： only\nconst u = "//host：443?access_token=actual-secret";',
        "// Deliverables： only\nconst u = `//host：443?access_token=actual-secret`;",
    ):
        output = dashboard.redact_dashboard_records([{"old_string": value}])[0]["old_string"]
        assert "actual-secret" not in output
        assert "REDACTED" in output


@pytest.mark.parametrize(
    "template",
    [
        "`//${host}/path?token=${`actual-secret`}`",
        "`${base}?token=actual-secret`",
        r"`${base}?tok\u0065n=${`actual-secret`}`",
        "`https://${`host`}/path?token=actual-secret`",
        "`${getBase(`prod`)}/path?token=actual-secret`",
        "`${`https://host/path`}?token=actual-secret`",
        "`${ready ? `https://host#fragment` : base}/path?token=actual-secret`",
    ],
)
def test_dynamic_template_does_not_claim_a_static_literal_boundary(template: str) -> None:
    text = "// Deliverables： only\nconst u = " + template + ";"
    output = dashboard.redact_dashboard_records([{"old_string": text}])[0]["old_string"]
    expected = (
        "// Deliverables： only\nconst u = `REDACTED`;"
        if template == "`${base}?token=actual-secret`"
        else "// Deliverables： only\nconst u = REDACTED"
    )
    assert output == expected


@pytest.mark.parametrize("quote", ["'", '"', "`"])
@pytest.mark.parametrize(
    "uri", ["//host：443 ?token=actual-secret", "//ho st：443?token=actual-secret", " //host：443?token=actual-secret"]
)
def test_literal_context_recovers_network_authority_spaces(quote: str, uri: str) -> None:
    text = "// Deliverables： only\nconst u = " + quote + uri + quote + ";\nconst keep = 1;"
    output = dashboard.redact_dashboard_records([{"old_string": text}])[0]["old_string"]
    assert output == text.replace("actual-secret", "REDACTED")


def test_trailing_authority_space_without_path_does_not_bypass_recovery() -> None:
    uri = "//host：443 ?token=actual-secret"
    assert dashboard.redact_dashboard_records([{"old_string": uri}]) == [
        {"old_string": uri.replace("actual-secret", "REDACTED")}
    ]


@pytest.mark.parametrize("quote", ["'", '"', "`"])
@pytest.mark.parametrize(
    "uri",
    [
        " /path?token=actual-secret",
        r"https\u003a\u002f\u002fhost?access_token=actual-secret",
        r"https:\/\/host?token=actual-secret",
    ],
)
def test_closed_and_unclosed_literals_share_candidate_discovery(quote: str, uri: str) -> None:
    prefix = "// Deliverables： only\nconst u = "
    for closing in [quote, ""]:
        text = prefix + quote + uri + closing + ";"
        output = dashboard.redact_dashboard_records([{"old_string": text}])[0]["old_string"]
        assert "actual-secret" not in output
        assert output.startswith(prefix)
        if not closing:
            assert output == prefix + "REDACTED"


@pytest.mark.parametrize("quote", ["'", '"', "`"])
def test_dangling_escape_does_not_hide_an_unclosed_candidate(quote: str) -> None:
    prefix = "// Deliverables： only\nconst u = "
    text = prefix + quote + r"https\u003a\u002f\u002fhost?access_token=actual-secret" + "\\"
    assert dashboard.redact_dashboard_records([{"old_string": text}]) == [{"old_string": prefix + "REDACTED"}]


@pytest.mark.parametrize("quote", ["'", '"', "`"])
@pytest.mark.parametrize("comment", ["// Don't： change", '// Say "hello：', "// Use `literal："])
def test_rejected_comment_quotes_cannot_consume_later_uri_literals(quote: str, comment: str) -> None:
    text = comment + "\nconst u = " + quote + "/path?token=actual-secret" + quote + ";\nconst keep = 1;"
    output = dashboard.redact_dashboard_records([{"old_string": text}])[0]["old_string"]
    assert output == text.replace("actual-secret", "REDACTED")


@pytest.mark.parametrize("template", ['`${ready ? "ready" : "waiting"}`', "`Ready? ${name}`", "`${base}?public=keep`"])
def test_templates_without_sensitive_queries_preserve_source(template: str) -> None:
    text = "// Deliverables： only\nconst message = " + template + ";\nconst keep = 1;"
    assert dashboard.redact_dashboard_records([{"old_string": text}]) == [{"old_string": text}]


@pytest.mark.parametrize(
    "template", ["`Hello ${name}`", '`${ready ? "ready" : "waiting"}`', '`Hello ${{name: "}"}.name}`']
)
def test_bounded_templates_do_not_consume_later_source(template: str) -> None:
    text = (
        "// Deliverables： only\nconst label = " + template + ";\nconst result = ready ? token === expected : fallback;"
    )
    assert dashboard.redact_dashboard_records([{"old_string": text}]) == [{"old_string": text}]


@pytest.mark.parametrize("expression", ['"#".slice(1)', 'opts["#"]', "getBase(`host#fragment`)"])
def test_dynamic_expression_fragment_cannot_hide_later_query_credentials(expression: str) -> None:
    prefix = "// Deliverables： only\nconst u = "
    text = prefix + "`https://host/path?public=${" + expression + "}&token=actual-secret`;\nconst keep = 1;"
    output = dashboard.redact_dashboard_records([{"old_string": text}])[0]["old_string"]
    assert "actual-secret" not in output
    if "`" not in expression:
        assert output == prefix + "`REDACTED`;\nconst keep = 1;"
    else:
        assert output == prefix + "REDACTED"


def test_unparsed_regex_in_template_cannot_establish_a_false_boundary() -> None:
    text = "// Deliverables： only\nconst u = `${/}/.test(x) ? `host` : base}/path?token=actual-secret`;"
    assert dashboard.redact_dashboard_records([{"old_string": text}]) == [
        {"old_string": "// Deliverables： only\nconst u = REDACTED"}
    ]


@pytest.mark.parametrize(
    ("text", "secret", "expected_text"),
    [
        ("//user=name@host：443?access_token=actual-secret", "actual-secret", None),
        (
            "// Deliverables： only\nconst u = `//host：443/path?access_token=actual-secret`;",
            "actual-secret",
            None,
        ),
        ("// Verify： ready? token === expected\nconst keep = 1;", None, None),
        ("// Deliverables： only\nconst result = ready ? token =~/expected/ : fallback;", None, None),
        ("https://host：443/path?token=actual-secret&label=public", "actual-secret", None),
        ("https://host：443/path?payload=client_secret%3Dactual-secret", "actual-secret", None),
        (
            '// Deliverables： only\nconst uri="https://host：443/path?token=actual-secret&label=public";',
            "actual-secret",
            None,
        ),
        ("https\n://host：443/path?token=actual-secret", "actual-secret", None),
        ("\x00//host：443/path?token=actual-secret", "actual-secret", None),
        (
            '// Deliverables： only\nconst uri="https://host：443/path?access_\r\ntoken=actual-secret";\nconst keep=1;',
            "actual-secret",
            '// Deliverables： only\nconst uri="https://host：443/path?access_token=REDACTED";\nconst keep=1;',
        ),
        (
            '// Deliverables： only\nconst uri=\'https://host：443/path?payload={"token":"actual-secret","public":"ok"}\';\nconst keep=1;',
            "actual-secret",
            "// Deliverables： only\nconst uri='https://host：443/path?payload=%7B%22token%22%3A%22REDACTED%22%2C%22public%22%3A%22ok%22%7D';\nconst keep=1;",
        ),
    ],
)
@pytest.mark.asyncio
async def test_original_failed_records_and_html_views_preserve_raw_capture(
    trace_db, text: str, secret: str | None, expected_text: str | None
) -> None:
    store = get_trace_store()
    session_id = store.create_session(client="claude", proxy_mode="reverse")
    record = {
        "timestamp": "2026-05-20T03:00:00+00:00",
        "request": {
            "method": "POST",
            "path": "/v1/messages",
            "body": {
                "system": text,
                "messages": [
                    {"role": "user", "content": "Apply the captured Edit."},
                    {
                        "role": "assistant",
                        "content": [{"type": "tool_use", "name": "Edit", "input": {"old_string": text}}],
                    },
                ],
            },
        },
        "response": {"status": 200, "body": {"content": [{"type": "text", "text": "Edit applied."}]}},
    }
    store.append_record(session_id, record)
    conn = store._connect()
    raw_payload = conn.execute("SELECT payload_json FROM records WHERE session_id=?", (session_id,)).fetchone()[0]
    server = LiveViewerServer(host="127.0.0.1", port=0)
    port = await server.start()
    base_url = f"http://127.0.0.1:{port}"
    try:
        async with aiohttp.ClientSession() as client:
            async with client.get(f"{base_url}/api/sessions/{session_id}/records") as response:
                assert response.status == 200
                payload = await response.json()
                actual_text = payload["records"][0]["request"]["body"]["messages"][1]["content"][0]["input"][
                    "old_string"
                ]
                if expected_text is None:
                    expected_text = text.replace("actual-secret", "REDACTED")
                assert actual_text == expected_text
                assert payload["records"][0]["request"]["body"]["system"] == expected_text
                if secret:
                    assert secret not in json.dumps(payload)
                else:
                    assert actual_text == text
            async with client.get(f"{base_url}/api/sessions/{session_id}/html") as response:
                assert response.status == 200
                html = await response.text()
                if secret:
                    assert secret not in html
    finally:
        await server.stop()
    assert store.load_records(session_id) == [record]
    assert (
        conn.execute("SELECT payload_json FROM records WHERE session_id=?", (session_id,)).fetchone()[0] == raw_payload
    )
