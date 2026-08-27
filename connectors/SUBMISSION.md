# Connector submission guidance

Preparation only: no provider account was changed, no listing was submitted,
and no approval is claimed by this repository.

## Grok

1. Review the [official Custom MCP documentation](https://docs.x.ai/grok/connectors).
2. In [Grok Connectors](https://grok.com/connectors), add a Custom MCP connector.
3. Use `https://run.huggingbay.xyz/mcp/` and complete the provider's supported
   authentication flow.
4. Confirm that the focused tool set is `coprocessor`, `run_pin`, and
   `solve_task`, and exercise a safe, non-sensitive request.

xAI's documented Custom MCP flow does not define a public third-party catalog
submission process. Do not claim catalog submission or approval.

## Cursor

1. Host this standalone artifact in the intended public repository:
   `https://github.com/barneywohl/huggingbay-coprocessor`.
2. Test the `cursor-plugin/` package locally in Cursor and confirm the
   URL-only MCP definition and bounded tool set.
3. Submit the public repository link through [Cursor Marketplace publishing](https://cursor.com/marketplace/publish).
4. Treat Cursor review and approval as separate provider evidence; do not infer
   either from a successful local test or a submitted link.

## Revalidation before external action

This source export encodes the branch's intended three-tool boundary; it is not
a signed copy of deployed discovery metadata. If the live contract differs,
pause and reconcile the connector files before any provider action.

Re-fetch the [connector discovery document](https://run.huggingbay.xyz/.well-known/connectors.json),
the [server card](https://run.huggingbay.xyz/.well-known/mcp/server-card.json),
and the live `tools/list` response from `https://run.huggingbay.xyz/mcp/`.
Read the [data policy](https://run.huggingbay.xyz/.well-known/data-policy.json)
before sending data. Keep all tokens and provider credentials in the supported
runtime authentication flow; never copy them into this repository.
