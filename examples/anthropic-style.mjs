import {
  BAY_RUN_PRODUCTION_TRUST_V1,
  anthropicAdapter,
  withBayRun,
} from "@huggingbay/coprocessor";

const providerCreate = async (request) => ({
  type: "message",
  model: request.model,
  content: [{ type: "text", text: "provider response" }],
});

const guardedCreate = withBayRun(providerCreate, {
  apiKey: process.env.BAY_RUN_API_TOKEN,
  adapter: anthropicAdapter(),
  ...BAY_RUN_PRODUCTION_TRUST_V1,
  timeoutMs: 5_000,
});

const outcome = await guardedCreate({
  model: "provider-model",
  system: "Answer concisely.",
  messages: [{ role: "user", content: "Explain this result." }],
});

console.log({ status: outcome.status, action: outcome.decision?.action });
