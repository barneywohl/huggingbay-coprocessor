# Grok Custom MCP example

`grok-custom-connector.json` is a bounded example of the remote MCP tool
object. It is not an xAI catalog-import format. For the current service
contract, check the [Bay Run connector discovery document](https://run.huggingbay.xyz/.well-known/connectors.json)
and the [official xAI Custom MCP documentation](https://docs.x.ai/grok/connectors).

Use `https://run.huggingbay.xyz/mcp/` as the MCP server URL and complete Grok's
supported authentication flow. Keep only these tools enabled when the client
offers a per-tool selector:

```json
["coprocessor", "run_pin", "solve_task"]
```

The `$BAY_RUN_TOKEN` value in the JSON is an environment placeholder, not a
credential. Do not replace it with a token in a repository or connector
packet.

## Decision handling

For `run_pin` and `solve_task`, inspect `response.decision.action` first. For
`coprocessor`, inspect the top-level `response.action` first:

- `allow`: continue only within the caller's approved task and data policy.
- `block`: stop generation, tool use, and downstream execution for that input.
- `escalate`: pause automation for human or policy review.

Raw result data is omitted by default. Set `omit_raw_result=false` only for an
explicit receipt-bound evidence need. The coprocessor never generates text or
executes tools; the caller owns the next step.

Example `run_pin` call:

```json
{
  "pin_id": "route_1c7472e940dc02517f5af93792bf07ee",
  "input": "This is wonderful.",
  "omit_raw_result": true
}
```

The four currently documented canonical Pins are provisional. Re-check the
live discovery document before relying on route IDs, limits, or availability.
This pack makes no claim about a public third-party Grok catalog submission or
approval; see [submission guidance](SUBMISSION.md).
