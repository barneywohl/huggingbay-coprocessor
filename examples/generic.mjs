import {
  BAY_RUN_PRODUCTION_TRUST_V1,
  genericAdapter,
  withBayRun,
} from "@huggingbay/coprocessor";

const generate = async (request, context) => ({
  text: `generated for ${request.input}`,
  rankedDocumentCount: context.rerankedDocuments?.length ?? 0,
});

const guardedGenerate = withBayRun(generate, {
  token: process.env.BAY_RUN_TOKEN,
  adapter: genericAdapter,
  ...BAY_RUN_PRODUCTION_TRUST_V1,
  failClosed: true,
});

const outcome = await guardedGenerate({
  input: "Answer using the retrieved context.",
  documents: ["A relevant document"],
});

console.log({ status: outcome.status, action: outcome.decision?.action });
