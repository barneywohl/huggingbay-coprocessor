import {
  BAY_RUN_PRODUCTION_TRUST_V1,
  type BayRunPinReceipt,
  type BayRunPinReceiptVerification,
  type BayRunOutcome,
  type BayRunRequestAdapter,
  type OpenAICompatibleRequest,
  anthropicAdapter,
  genericAdapter,
  openAICompatibleAdapter,
  withBayRun,
  verifyPinReceipt,
} from "../src/index.js";

declare const pinReceipt: BayRunPinReceipt;
const offlineVerification: BayRunPinReceiptVerification = verifyPinReceipt(pinReceipt, {
  input: { userText: "Find reset help" },
  result: { labels: [] },
  idempotencyKey: "offline-types-fixture",
  ...BAY_RUN_PRODUCTION_TRUST_V1,
});
void offlineVerification;

const openAIRequest: OpenAICompatibleRequest = {
  messages: [{ role: "user", content: "Find reset help" }],
  bayRun: { documents: ["A relevant document"] },
};

const openAIGuarded = withBayRun(
  async () => "ok",
  {
    ...BAY_RUN_PRODUCTION_TRUST_V1,
    adapter: openAICompatibleAdapter(),
  },
);

const anthropicGuarded = withBayRun(
  () => "ok",
  {
    ...BAY_RUN_PRODUCTION_TRUST_V1,
    adapter: anthropicAdapter(),
  },
);

type GenericInput = { input: string; documents?: readonly string[] };
const genericInputAdapter: BayRunRequestAdapter<GenericInput> = (input) =>
  genericAdapter(input);

const genericGuarded = withBayRun<GenericInput, string>(
  (request, context) => `${request.input}:${context.bayRunAvailable}`,
  {
    ...BAY_RUN_PRODUCTION_TRUST_V1,
    adapter: genericInputAdapter,
  },
);

const rotatedPolicyGuarded = withBayRun<GenericInput, string>(
  (request) => request.input,
  {
    trustedKeyId: BAY_RUN_PRODUCTION_TRUST_V1.trustedKeyId,
    trustedPublicKeySha256: BAY_RUN_PRODUCTION_TRUST_V1.trustedPublicKeySha256,
    trustedPolicyId: BAY_RUN_PRODUCTION_TRUST_V1.trustedPolicyId,
    trustedPolicyDigests: BAY_RUN_PRODUCTION_TRUST_V1.trustedPolicyDigests,
    adapter: genericInputAdapter,
  },
);

const output: Promise<BayRunOutcome<string>> = openAIGuarded(openAIRequest);
void output;
void anthropicGuarded(openAIRequest);
void genericGuarded({ input: "Find reset help", documents: ["A relevant document"] });
void rotatedPolicyGuarded;
