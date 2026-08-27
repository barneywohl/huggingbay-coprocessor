import {
  BAY_RUN_PRODUCTION_TRUST_V1,
  openAICompatibleAdapter,
  withBayRun,
} from "@huggingbay/coprocessor";

const providerCreate = async (request) => ({
  object: "chat.completion",
  model: request.model,
  choices: [{ message: { role: "assistant", content: "provider response" } }],
});

const guardedCreate = withBayRun(providerCreate, {
  token: process.env.BAY_RUN_TOKEN,
  adapter: openAICompatibleAdapter({
    documents: (request) => request.bayRun?.documents,
  }),
  ...BAY_RUN_PRODUCTION_TRUST_V1,
  idempotencyKey: "example-openai-compatible-20260825",
});

const outcome = await guardedCreate({
  model: "provider-model",
  messages: [{ role: "user", content: "Summarize this request." }],
  bayRun: { documents: ["A relevant document"] },
});

console.log({
  status: outcome.status,
  action: outcome.decision?.action,
  rerankedDocumentCount: outcome.context?.rerankedDocuments?.length ?? 0,
});
