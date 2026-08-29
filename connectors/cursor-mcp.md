# Cursor MCP example

Use the [Bay Run connector discovery document](https://run.huggingbay.xyz/.well-known/connectors.json)
and [Cursor's MCP documentation](https://cursor.com/docs/mcp/install-links) as
the current setup references. The canonical MCP URL is
`https://run.huggingbay.xyz/mcp/`.

## Configuration

The URL-only config in `cursor-mcp.json` is:

```json
{
  "mcpServers": {
    "bay-run": {
      "url": "https://run.huggingbay.xyz/mcp/"
    }
  }
}
```

`cursor-install.json` records the corresponding install payload and deeplink.
The optional `cursor-plugin/` directory contains the minimal source-only
plugin manifest and the same URL-only MCP definition.

Keep the available tools bounded to:

```text
run_pin, solve_task, coprocessor
```

Complete authentication through Cursor's supported OAuth or secret flow. The
checked-in MCP object is intentionally URL-only: do not add headers, env
values, OAuth client material, a bearer, API key, private key, or provider
credential to configuration.

Fail closed on an unavailable or unauthenticated server, a malformed response,
or a missing or unsupported action. Stop without generation, tool use, or raw
result handling; never treat an MCP or policy failure as `allow`.

Before sending data, read Bay Run's [privacy policy](https://run.huggingbay.xyz/privacy)
and [data policy](https://run.huggingbay.xyz/.well-known/data-policy.json).

## Decision handling

Start with `coprocessor` for the bounded Guard-first composition. For
`run_pin` and `solve_task`, read `response.decision.action` before using
`response.result`; for `coprocessor`, read the top-level `response.action`.
The coprocessor independently guards `user_text` and every supplied document.
Require complete, one-to-one `document_guards` and `evidence.document_guards`
rows with `source="document"` and the exact `document_index`; combine their
actions with `block > escalate > allow` precedence. Every supplied document
still receives a Guard row when the user Guard or action-safety signal already
blocks or escalates. Use ranked documents only
when every Guard action is `allow` and Rerank returns `signal="ranked"`.
Stop on `block`, pause on `escalate`, and continue only on `allow` within the
caller's approved policy. A top-level `escalate` may preserve a signed Guard
`allow` for high-risk action safety or Rerank abstention; do not rewrite that
signed Guard evidence. The default is decision-only
(`omit_raw_result=true`); raw evidence is an explicit opt-in.

Example `coprocessor` call:

```json
{
  "user_text": "How do I reset a password?",
  "documents": [
    "Open Settings and choose Reset password.",
    "Invoices are available under Billing."
  ],
  "omit_raw_result": true
}
```

The connector never generates text or executes tools. Re-check the live
contract before relying on route IDs or limits. See [submission guidance](SUBMISSION.md)
for the separate human review steps.
