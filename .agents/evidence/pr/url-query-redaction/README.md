# URL query redaction regression evidence

`trace-viewer-deepseek-flash.png` shows the actual session viewer for one real
Claude Code request proxied to the locally configured DeepSeek backend on
2026-10-13. The response returned HTTP 200, model `deepseek-flash`, 92 input
tokens and 59 output tokens. The prompt and response contain a comment starting
with `//`, a full-width colon (U+FF1A), and a ternary expression using `?`.

The prompt was written specifically for this regression check. The request
used a minimal system prompt and disabled tools. The nested Edit `old_string`
payload is separately covered by the local HTTP regression test.

Before/after checks used separate servers and a SQLite backup of the same
captured session. Before the fix, session records and HTML viewer requests
returned 500, with a server traceback ending in the NFKC `ValueError`
from CPython's `_checknetloc()`. The original DeepSeek model response was 200;
the failures occurred in claude-tap's viewer endpoints.

With this fix, the original prompt is preserved and the browser's request to
`/api/sessions/{session_id}/records?offset=0&limit=1` returns HTTP 200. The actual
HTML viewer also returns HTTP 200.

Query redaction extracts the query directly, without authority parsing. The
captured model request was reused unchanged for the before/after comparison.
The follow-up control-character cleanup is covered by regression tests and
does not change the captured code snippet or the pictured viewer content.

Raw request/response records are intentionally excluded from this contribution.

## Original failure screenshot

`trace-viewer-baseline-500.jpg` directly captures the original server's native
HTTP 500 page in an isolated Chromium window, including the real Network Headers
panel showing the request URL, GET method and status 500. The native screenshot
tool returns JPEG bytes; the file retains those bytes unchanged with the correct
`.jpg` extension. No conversion or image editing was performed. The fixed viewer
screenshot directly captures the rendered session. Neither screenshot uses a
comparison layout, compositing or simulated response. Both use the same real
captured record and were visually checked for private content.

Actual GET requests verified both original endpoints returned 500 and both fixed
endpoints returned 200. The two SQLite databases contain the identical captured
record.

Both screenshots pass the screenshot checker. Its JPEG blankness check is not
implemented, so the native JPEG was also inspected visually and sampled without
modification: the dominant color occupies 72.4% of the sampled pixels, below the
PNG checker's 90% blankness threshold.
