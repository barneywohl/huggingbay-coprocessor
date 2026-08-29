# Bay Run connector examples

This directory contains bounded Grok and Cursor connector assets for Bay Run's
public Streamable HTTP MCP surface. The checked-in Cursor receipt records that
the Marketplace publish form displayed a submission acknowledgement on
2026-08-28; provider review, approval, and listing remain unclaimed. The assets
do not deploy a service or create credentials.

The canonical MCP URL is `https://run.huggingbay.xyz/mcp/`. Keep the focused
tool set bounded to:

```text
coprocessor, run_pin, solve_task
```

Start with `coprocessor` for one Guard-first composition. It independently
guards `user_text` and every supplied document; require complete, one-to-one
`document_guards` and `evidence.document_guards` rows with exact source/index
mapping even when the user Guard or action-safety signal already blocks or
escalates. Combine document actions with `block > escalate > allow`, and use
ranked documents only when every Guard allows and Rerank returns a ranked
signal. A top-level `escalate` can preserve a signed Guard `allow` for high-risk
action safety or Rerank abstention. Use `run_pin` for a known canonical Pin and
`solve_task` only when no canonical Pin fits. Follow the returned action before
reading or acting on raw result data. The service's decision-only default is
`omit_raw_result=true`; opt into raw evidence only when it is explicitly
required and receipt-bound.

This connector pack is fail-closed. If the MCP service is unavailable,
authentication fails, the response is malformed, or the required action is
missing or unsupported, stop and do not generate, use tools, or treat the
failure as `allow`. No fail-open path is configured for these provider assets.

Files in this directory:

- `grok-custom-connector.json` and `grok-custom-connector.md`: Grok setup and
  bounded tool examples.
- `grok-connection.json`: the verified Custom MCP connection state and exact
  three-tool inventory; it does not claim xAI catalog submission or approval.
- `cursor-mcp.json`, `cursor-install.json`, and `cursor-mcp.md`: Cursor setup,
  install-link, and decision-handling examples.
- `cursor-plugin/`: the minimal source-only Cursor plugin manifest and remote
  MCP definition.
- `cursor-submission.json`: the bounded Cursor submission acknowledgement;
  provider review remains pending.
- `decision-policy.json`: the shared action-handling guidance.
- `SUBMISSION.md`: provider submission readiness and the remaining human steps.

The public repository changed after the recorded acknowledgement. Under
Cursor's current publisher terms, the human publisher must request a provider
re-index for the changed package if required; no re-index, approval, or
marketplace listing is recorded here.

Before sending data, read Bay Run's [privacy policy](https://run.huggingbay.xyz/privacy)
and [data policy](https://run.huggingbay.xyz/.well-known/data-policy.json), and
use only the provider's supported OAuth or secret flow. The static files
contain no credential value.
