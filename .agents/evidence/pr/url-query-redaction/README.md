# URL query redaction regression evidence

## Reproduction and behavior

This captured Edit input makes `urlsplit()` interpret the comment as an
invalid authority and raise an NFKC-related `ValueError`:

```javascript
// Deliverables： only
const result = ready ? token === expected : fallback;
```

The records and HTML handlers return HTTP 200, with this display field set to
`REDACTED`. Simple malformed authorities reuse existing query redaction;
uncertain failed fields are hidden. Stored captures and raw exports are unchanged.

## Validation

```bash
python -m pytest tests/ -q -x --timeout=60
ruff check .
ruff format --check .
git diff --check
```

Python 3.13 with Chromium: **1,592 passed, 26 skipped**; lint, formatting, and diff
checks pass. Skips cover 18 tests requiring local trace files, seven opt-in CLI
E2E tests, and one Windows test. Regressions verify normal redaction, authority
boundaries, records/HTML responses, masking, and unchanged stored and export data.

## Screenshots

Current screenshots use local headless Chromium on macOS at 1280x900 CSS pixels
and 2x scale. Both viewer pages and records endpoints return HTTP 200.

- `trace-viewer-query-redacted-demo.png`: demonstration fixture, with no model
  call. Only the fake token is hidden; the public parameter and URL structure remain.
- `trace-viewer-source-redacted-current.png`: the original real two-user-turn
  Claude Code session, captured through the local proxy using tmux with DeepSeek
  `deepseek-flash`. Edit fields show `REDACTED`; the filename and session remain visible.
- `trace-viewer-multiturn-baseline-network.png`: native Chromium Network Headers
  show the records GET returning HTTP 500, documenting the original failure.

The original `trace-viewer-multiturn-fixed.png` is retained as a historical
capture of complete Edit source, not current masking evidence.
