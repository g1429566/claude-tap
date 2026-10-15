# URL query redaction regression evidence

## Reproduction and behavior

The real captured Edit input below is source code, not a URL. Its `//` comment,
fullwidth colon and ternary `?` make Python's `urlsplit()` raise `ValueError`:

```javascript
// Deliverables： only
const result = ready ? token === expected : fallback;
```

The original six-request session also contains this text in its version-4 cached
`first_user`. Recovery therefore starts before record redaction, when that cached
summary is normalized. Session records and online HTML return HTTP 200 on first
and repeated reads; the Edit old/new strings show `REDACTED`.

Recovery is limited to display scopes and the original `urlsplit()` call. Other
redaction failures still propagate. Successful parsing uses the original
query/form/JSON rules. After an observed URL-parser failure, session responses
hide their nonempty `first_user`, `last_response` and `error`; online HTML hides
`sys_hint`, `session_user_text` and `error_message` across the generated metadata.
This deliberately avoids guessing which truncated preview came from the failed
source. Record siblings and other metadata remain intact.

The existing record queries, decoding, preview generation and cache version
remain unchanged. Each existing summary write is skipped if that summary build
recovered a URL-parser failure; normal writes keep their
original values and order. Append/import builders outside display retain the
original error behavior. Raw captures and JSONL/compact/HTML downloads are unchanged.

Existing recognition/depth limits remain. A page that never parses the failed
source can retain an old truncated preview, as in the baseline; this fix does not
scan other pages to reconstruct provenance. An existing successful cache write
that precedes a later records error is also retained.

## Validation

Final candidate validation on Python 3.13.14 with Chromium: **1,683 passed,
26 skipped**. The **404 focused regressions** cover original successful outputs,
actual parser failures, nested leaves, public siblings, cached summaries,
HTML metadata, pagination, repeated requests,
cache-write boundaries, concurrent scope isolation and unchanged raw exports.

```bash
python -m pytest tests/ -q -x --timeout=60
ruff check .
ruff format --check .
git diff --check
```

Normal e17 comparisons retain identical complete response bytes, SQL shapes,
decoded rows and existing redactor/parser call counts. Alternating latency runs
still observe a small positive difference for 1,000-record responses: the fixed
32-pair follow-up has a +0.883 ms paired median (about +0.55%). No zero-latency-cost
claim is made. Python coverage is 85.61% overall and 100% of changed executable
lines (42/42) relative to e17.

## Screenshots

Screenshots use the original real two-user-turn Claude Code session, captured
through the local proxy with the configured DeepSeek `deepseek-flash` backend.
No new model calls are needed to render the retained capture. The current image
uses headless Chromium on macOS at 1280x900 CSS pixels and 2x scale.

- `trace-viewer-multiturn-baseline-network.png`: native Chromium Network Headers
  show the original records GET returning HTTP 500.
- `trace-viewer-source-redacted-current.png`: the current candidate's viewer
  shows the captured Edit old/new fields as `REDACTED`, with its filename visible.
- `trace-viewer-multiturn-fixed.png`: retained historical evidence of complete
  Edit source, not evidence of the current display policy.
