# Connector submission guidance

The Cursor Marketplace application for this public repository was submitted on
2026-08-28 and acknowledged by Cursor. Provider review remains pending and no
approval is claimed. The Grok material remains a Custom MCP setup guide rather
than a public catalog submission.

## Grok

1. Review the [official Custom MCP documentation](https://docs.x.ai/grok/connectors).
2. In [Grok Connectors](https://grok.com/connectors), add a Custom MCP connector.
3. Use `https://run.huggingbay.xyz/mcp/` and complete the provider's supported
   authentication flow.
4. Confirm that the focused tool set is exactly `run_pin`, `solve_task`, and
   `coprocessor`, and exercise a safe, non-sensitive request.

xAI's documented Custom MCP flow does not define a public third-party catalog
submission process. The operator's Custom MCP connection was verified connected
on 2026-08-28 with exactly the three expected tools; see
`grok-connection.json`. Do not claim catalog submission or approval.

## Cursor

1. Host this standalone artifact in the intended public repository:
   `https://github.com/barneywohl/huggingbay-coprocessor`.
2. Test the `cursor-plugin/` package locally in Cursor and confirm the
   URL-only MCP definition and bounded tool set.
3. The public repository link was submitted through [Cursor Marketplace publishing](https://cursor.com/marketplace/publish)
   on 2026-08-28; see `cursor-submission.json` for the bounded receipt.
4. Treat Cursor review and approval as separate provider evidence. The current
   state is submitted and pending review, not approved or listed.

## Privacy and failure handling

Before sending any user text or documents, read Bay Run's [privacy policy](https://run.huggingbay.xyz/privacy)
and [data policy](https://run.huggingbay.xyz/.well-known/data-policy.json).
The checked-in provider assets use a fail-closed decision policy: an
authentication, transport, malformed-response, or missing-action failure stops
the workflow and is never treated as `allow`. Credentials belong only in the
provider's supported OAuth or runtime secret flow.

## Revalidation before external action

This source export encodes the branch's intended three-tool boundary; it is not
a signed copy of deployed discovery metadata. If the live contract differs,
pause and reconcile the connector files before any provider action.

Re-fetch the [connector discovery document](https://run.huggingbay.xyz/.well-known/connectors.json),
the [server card](https://run.huggingbay.xyz/.well-known/mcp/server-card.json),
and the live `tools/list` response from `https://run.huggingbay.xyz/mcp/`.
Read the [privacy policy](https://run.huggingbay.xyz/privacy) and [data policy](https://run.huggingbay.xyz/.well-known/data-policy.json)
before sending data. Keep all tokens and provider credentials in the supported
runtime authentication flow; never copy them into this repository.
