# URL query redaction regression evidence

These original browser screenshots use one complete two-user-turn Claude Code
conversation captured through the local claude-tap proxy on 2026-10-14
(Asia/Shanghai). The capture used the documented tmux interactive flow,
without `-p` or `--print`, and the configured DeepSeek Anthropic backend with
model `deepseek-flash`.

The first prompt starts with the regression snippet, then asks Claude Code to
read `sample.js`. The second prompt requests an Edit using the complete snippet
as `old_string`, including its trailing newline. Real tool calls were
Read, Edit and Read; the edit changed only the comment from `only` to `verified`.
Both user turns completed successfully.

The session contains six real `/v1/messages?beta=true` requests, all HTTP 200,
including Claude Code's session-title request. Their combined usage is 2,379
input tokens, 438 output tokens and 3,456 cache-read tokens. The viewer's
2,817 cumulative API-token total counts input plus output; its six entries
represent recorded API requests, rather than six user turns.

The actual Edit `old_string` is:

```javascript
// Deliverables： only
const result = ready ? token === expected : fallback;
```

A trailing newline follows the second line. The prompts and isolated sample
file were written for this regression check.

Before/after HTTP checks used separate servers and SQLite backups containing
the same six captured records. The records and HTML viewer endpoints both
return HTTP 500 before the fix, with the server traceback containing an NFKC
`ValueError` from CPython's `_checknetloc()`. Both endpoints return HTTP 200
after the fix; the actual Edit strings and captured prompt are preserved.
The original model responses are HTTP 200 throughout.

- `trace-viewer-multiturn-fixed.jpg` is the primary trace evidence. It directly
  captures the actual fixed viewer,
  selecting the Edit-producing record and expanding its escaped input strings.
  The sidebar shows all six requests and the header shows nonzero token usage.
- `trace-viewer-multiturn-baseline-500.jpg` is supplementary failure evidence.
  It directly captures the records endpoint's native HTTP 500 response page
  for the same multi-turn session.

Both images retain the JPEG bytes returned by the browser screenshot API.
No image editing or compositing was performed. The baseline error page is the
intentional reproduced failure state, paired with the working viewer.
Both images were visually inspected; the screenshot checker reported no
failures, with warnings that JPEG blankness analysis is unsupported.

Regression tests additionally cover URI context, surrounding and internal
whitespace, nested credentials, control characters, JSON and lone surrogates.
Raw trace exports, database files, logs and credentials are excluded from this
contribution.
