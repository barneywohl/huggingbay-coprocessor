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
coprocessor, run_pin, solve_task
```

Complete authentication through Cursor's supported OAuth or secret flow. Do
not put a bearer, API key, private key, or provider credential in configuration.

## Decision handling

Start with `coprocessor` for the bounded Guard-first composition. For
`run_pin` and `solve_task`, read `response.decision.action` before using
`response.result`; for `coprocessor`, read the top-level `response.action`.
Stop on `block`, pause on `escalate`, and continue only on `allow` within the
caller's approved policy. The default is decision-only
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
