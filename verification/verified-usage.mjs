import assert from "node:assert/strict";

import {
  BAY_RUN_PRODUCTION_TRUST_V1,
  BayRunApiError,
  genericAdapter,
  withBayRun,
} from "@huggingbay/coprocessor";

let generated = false;
const guardedGenerate = withBayRun(
  async () => {
    generated = true;
    return "must not run after a failed coprocessor check";
  },
  {
    ...BAY_RUN_PRODUCTION_TRUST_V1,
    adapter: genericAdapter,
    fetch: async () => ({
      ok: false,
      status: 503,
      async text() {
        return JSON.stringify({
          error: {
            code: "service_unavailable",
            reason: "offline verification stub",
            retriable: true,
          },
        });
      },
    }),
  },
);

await assert.rejects(
  guardedGenerate("offline verification request"),
  (error) => error instanceof BayRunApiError && error.code === "service_unavailable",
);
assert.equal(generated, false);
console.log("Verified: a failed coprocessor check did not invoke generation.");
