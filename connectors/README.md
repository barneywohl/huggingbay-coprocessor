# Bay Run connector examples

This directory contains bounded Grok and Cursor connector assets for Bay Run's
public Streamable HTTP MCP surface. The Cursor Marketplace application was
submitted on 2026-08-28 and is pending provider review. The assets do not deploy
a service, create credentials, or claim provider approval.

The canonical MCP URL is `https://run.huggingbay.xyz/mcp/`. Keep the focused
tool set bounded to:

```text
run_pin, solve_task, coprocessor
```

Start with `coprocessor` for one Guard-first composition. Use `run_pin` for a
known canonical Pin and `solve_task` only when no canonical Pin fits. Follow
the returned action before reading or acting on raw result data. The service's
decision-only default is `omit_raw_result=true`; opt into raw evidence only
when it is explicitly required and receipt-bound.

This connector pack is fail-closed. If the MCP service is unavailable,
authentication fails, the response is malformed, or the required action is
missing or unsupported, stop and do not generate, use tools, or treat the
failure as `allow`. No fail-open path is configured for these provider assets.

Files in this directory:

- `grok-custom-connector.json` and `grok-custom-connector.md`: Grok setup and
  bounded tool examples.
- `cursor-mcp.json`, `cursor-install.json`, and `cursor-mcp.md`: Cursor setup,
  install-link, and decision-handling examples.
- `cursor-plugin/`: the minimal source-only Cursor plugin manifest and remote
  MCP definition.
- `cursor-submission.json`: the bounded Cursor submission acknowledgement;
  provider review remains pending.
- `decision-policy.json`: the shared action-handling guidance.
- `SUBMISSION.md`: provider submission readiness and the remaining human steps.

Before sending data, read Bay Run's [privacy policy](https://run.huggingbay.xyz/privacy)
and [data policy](https://run.huggingbay.xyz/.well-known/data-policy.json), and
use only the provider's supported OAuth or secret flow. The static files
contain no credential value.
