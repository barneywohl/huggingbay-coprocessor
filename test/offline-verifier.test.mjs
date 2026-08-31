import assert from "node:assert/strict";
import {
  createHash,
  generateKeyPairSync,
  sign,
} from "node:crypto";
import {
  mkdtempSync,
  readFileSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { spawnSync } from "node:child_process";
import test from "node:test";

import {
  BayRunContractError,
  BayRunInputError,
  parseBayRunJson,
  verifyPinReceipt,
} from "../src/index.js";

const PIN_RECEIPT_SCHEMA = "bay-run.pin-receipt.v1";
const PIN_PROOF_SCHEMA = "bay-run.pin-proof.v1";
const NO_SPEND_NUMERIC_FIELDS = new Set([
  "max_price_usd",
  "priced_cost_usd",
  "charged_usd",
]);
const NO_SPEND = {
  schema: "bay-run.no-spend-evidence.v1",
  status: "no_spend",
  server_authoritative: true,
  payment_required: false,
  max_price_usd: 0.0,
  priced_cost_usd: 0.0,
  charged_usd: 0.0,
  scope: "this_execution",
};
const CLI = new URL("../bin/bay-verify", import.meta.url);

function compareCodePoints(left, right) {
  let leftIndex = 0;
  let rightIndex = 0;
  while (leftIndex < left.length && rightIndex < right.length) {
    const leftCode = left.codePointAt(leftIndex);
    const rightCode = right.codePointAt(rightIndex);
    if (leftCode !== rightCode) return leftCode < rightCode ? -1 : 1;
    leftIndex += leftCode > 0xffff ? 2 : 1;
    rightIndex += rightCode > 0xffff ? 2 : 1;
  }
  if (leftIndex !== left.length) return 1;
  if (rightIndex !== right.length) return -1;
  return 0;
}

function quoteJson(value) {
  let result = '"';
  for (let index = 0; index < value.length; index += 1) {
    const code = value.charCodeAt(index);
    if (code === 0x08) result += "\\b";
    else if (code === 0x09) result += "\\t";
    else if (code === 0x0a) result += "\\n";
    else if (code === 0x0c) result += "\\f";
    else if (code === 0x0d) result += "\\r";
    else if (code === 0x22) result += '\\"';
    else if (code === 0x5c) result += "\\\\";
    else if (code < 0x20) result += `\\u${code.toString(16).padStart(4, "0")}`;
    else result += value[index];
  }
  return `${result}"`;
}

function canonicalJson(value, key = undefined) {
  if (value === null) return "null";
  if (typeof value === "string") return quoteJson(value);
  if (typeof value === "boolean") return value ? "true" : "false";
  if (typeof value === "number") {
    if (NO_SPEND_NUMERIC_FIELDS.has(String(key)) && Object.is(value, 0)) return "0.0";
    return JSON.stringify(value);
  }
  if (Array.isArray(value)) {
    return `[${value.map((item, index) => canonicalJson(item, index)).join(",")}]`;
  }
  if (typeof value === "object" && value !== null) {
    return `{${Object.keys(value)
      .sort(compareCodePoints)
      .map((name) => `${quoteJson(name)}:${canonicalJson(value[name], name)}`)
      .join(",")}}`;
  }
  throw new TypeError("unsupported fixture value");
}

function digestBytes(value) {
  return `sha256:${createHash("sha256").update(value).digest("hex")}`;
}

function digestJson(value) {
  return digestBytes(Buffer.from(canonicalJson(value), "utf8"));
}

function clone(value) {
  return JSON.parse(JSON.stringify(value));
}

function makeFixture() {
  const { privateKey, publicKey } = generateKeyPairSync("ed25519");
  const publicJwk = publicKey.export({ format: "jwk" });
  const publicKeyBytes = Buffer.from(publicJwk.x, "base64url");
  const trust = {
    trustedKeyId: "offline-verifier-test",
    trustedPublicKeySha256: digestBytes(publicKeyBytes),
  };
  const input = {
    userText: "Résumé 🚀 — 東京",
    documents: ["Use Settings → Reset password."],
  };
  const result = {
    model: "fixture-model",
    labels: [{ label: "SAFE", score: 0.99 }],
    note: "✓ exact result",
  };
  const idempotencyKey = "offline-verifier-idempotency-key";
  const payload = {
    schema: PIN_RECEIPT_SCHEMA,
    execution_id: "pinexec_offline_verifier_01",
    pin_id: "route_offline_verifier_test",
    route_id: "route_offline_verifier_test",
    model: "fixture-model",
    served_weight_sha256: null,
    input_sha256: digestJson(input),
    result_sha256: digestJson(result),
    idempotency_key_sha256: digestJson(idempotencyKey),
    no_spend_evidence: NO_SPEND,
  };
  const proofBody = Buffer.from(canonicalJson(payload), "utf8");
  const proof = {
    schema: PIN_PROOF_SCHEMA,
    alg: "Ed25519",
    kid: trust.trustedKeyId,
    payload_sha256: digestBytes(proofBody),
    public_key: publicJwk.x,
    signature: sign(null, proofBody, privateKey).toString("base64url"),
    key_scope: "configured",
  };
  const receipt = {
    ...payload,
    receipt_id: digestJson({ ...payload, proof }),
    proof,
  };
  const bundle = { receipt, input, result, idempotency_key: idempotencyKey };
  const wire = canonicalJson(bundle);
  return {
    trust,
    input,
    result,
    idempotencyKey,
    receipt,
    bundle,
    wire,
    parsedBundle: parseBayRunJson(wire),
  };
}

function verifyFixture(fixture, overrides = {}) {
  const bundle = fixture.parsedBundle;
  return verifyPinReceipt(bundle.receipt, {
    input: bundle.input,
    result: bundle.result,
    idempotencyKey: bundle.idempotency_key,
    ...fixture.trust,
    ...overrides,
  });
}

function runCli(input, args = []) {
  return spawnSync(process.execPath, [CLI.pathname, ...args], {
    input,
    encoding: "utf8",
    env: { ...process.env },
  });
}

function cliJson(processResult) {
  assert.equal(processResult.stderr, "");
  return JSON.parse(processResult.stdout);
}

test("verifyPinReceipt accepts Unicode and returns metadata without raw values", () => {
  const fixture = makeFixture();
  const verified = verifyFixture(fixture);

  assert.deepEqual(verified, {
    valid: true,
    schema: PIN_RECEIPT_SCHEMA,
    receiptId: fixture.receipt.receipt_id,
    executionId: fixture.receipt.execution_id,
    pinId: fixture.receipt.pin_id,
    keyId: fixture.trust.trustedKeyId,
    signedPayloadFields: [
      "schema",
      "execution_id",
      "pin_id",
      "route_id",
      "model",
      "served_weight_sha256",
      "input_sha256",
      "result_sha256",
      "idempotency_key_sha256",
      "no_spend_evidence",
    ],
  });
  const serialized = JSON.stringify(verified);
  assert.equal(serialized.includes("Résumé"), false);
  assert.equal(serialized.includes("exact result"), false);
});

test("verifyPinReceipt accepts a plain object and requires explicit trust", () => {
  const fixture = makeFixture();
  const plainReceipt = clone(fixture.receipt);
  const verified = verifyPinReceipt(plainReceipt, {
    input: fixture.input,
    result: fixture.result,
    idempotencyKey: fixture.idempotencyKey,
    ...fixture.trust,
  });
  assert.equal(verified.valid, true);

  assert.throws(
    () => verifyPinReceipt(plainReceipt, {
      input: fixture.input,
      result: fixture.result,
      idempotencyKey: fixture.idempotencyKey,
    }),
    (error) => error instanceof BayRunInputError && error.code === "invalid_proof_trust",
  );
  assert.throws(
    () => verifyFixture(fixture, {
      trustedKeyId: "wrong-key-id",
    }),
    (error) => error instanceof BayRunContractError && error.code === "proof_untrusted_signer",
  );
});

test("verifyPinReceipt checks input, result, and idempotency hashes", () => {
  const fixture = makeFixture();
  const cases = [
    ["evidence_input_mismatch", { input: { userText: "tampered" } }],
    ["evidence_result_mismatch", { result: { changed: true } }],
    ["evidence_idempotency_mismatch", { idempotencyKey: "different-idempotency-key" }],
  ];
  for (const [code, overrides] of cases) {
    assert.throws(
      () => verifyFixture(fixture, overrides),
      (error) => error instanceof BayRunContractError && error.code === code,
    );
  }
});

test("verifyPinReceipt fails closed for signed-field, signature, ID, and field-set tampering", () => {
  const fixture = makeFixture();

  const signedFieldTampered = clone(fixture.receipt);
  signedFieldTampered.model = "tampered-model";
  assert.throws(
    () => verifyFixture({ ...fixture, parsedBundle: { ...fixture.parsedBundle, receipt: signedFieldTampered } }),
    (error) => error instanceof BayRunContractError && error.code === "proof_payload_mismatch",
  );

  const signatureTampered = clone(fixture.receipt);
  signatureTampered.proof.signature = `${"A".repeat(86)}`;
  assert.throws(
    () => verifyFixture({ ...fixture, parsedBundle: { ...fixture.parsedBundle, receipt: signatureTampered } }),
    (error) => error instanceof BayRunContractError && error.code === "proof_signature_invalid",
  );

  const receiptIdTampered = clone(fixture.receipt);
  receiptIdTampered.receipt_id = `sha256:${"0".repeat(64)}`;
  assert.throws(
    () => verifyFixture({ ...fixture, parsedBundle: { ...fixture.parsedBundle, receipt: receiptIdTampered } }),
    (error) => error instanceof BayRunContractError && error.code === "receipt_id_mismatch",
  );

  const unknownField = clone(fixture.receipt);
  unknownField.untrusted = "ignored content";
  assert.throws(
    () => verifyFixture({ ...fixture, parsedBundle: { ...fixture.parsedBundle, receipt: unknownField } }),
    (error) => error instanceof BayRunContractError && error.code === "evidence_invalid",
  );
});

test("bay-verify reads stdin and files, and emits only bounded status metadata", () => {
  const fixture = makeFixture();
  const args = [
    "--key-id",
    fixture.trust.trustedKeyId,
    "--public-key-sha256",
    fixture.trust.trustedPublicKeySha256,
  ];
  const stdinResult = runCli(fixture.wire, args);
  assert.equal(stdinResult.status, 0);
  const stdinOutput = cliJson(stdinResult);
  assert.equal(stdinOutput.status, "verified");
  assert.equal(stdinOutput.receipt_id, fixture.receipt.receipt_id);
  assert.equal(JSON.stringify(stdinOutput).includes("Résumé"), false);
  assert.equal(JSON.stringify(stdinOutput).includes("exact result"), false);

  const directory = mkdtempSync(join(tmpdir(), "bay-verify-test-"));
  const path = join(directory, "bundle.json");
  try {
    writeFileSync(path, fixture.wire, "utf8");
    const fileResult = runCli(undefined, [...args, path]);
    assert.equal(fileResult.status, 0);
    assert.equal(cliJson(fileResult).status, "verified");
    assert.equal(readFileSync(path, "utf8"), fixture.wire);
  } finally {
    rmSync(directory, { recursive: true, force: true });
  }
});

test("bay-verify reports stable wrong-key, malformed, and size failures", () => {
  const fixture = makeFixture();
  const wrongKey = runCli(fixture.wire, [
    "--key-id",
    "wrong-key-id",
    "--public-key-sha256",
    fixture.trust.trustedPublicKeySha256,
  ]);
  assert.equal(wrongKey.status, 1);
  assert.deepEqual(cliJson(wrongKey), { status: "invalid", code: "proof_untrusted_signer" });

  const malformed = runCli("{", []);
  assert.equal(malformed.status, 1);
  assert.deepEqual(cliJson(malformed), { status: "invalid", code: "invalid_json" });

  const oversized = runCli(Buffer.alloc(1_048_577, 0x20), []);
  assert.equal(oversized.status, 1);
  assert.deepEqual(cliJson(oversized), { status: "invalid", code: "input_too_large" });
});

test("invalid Unicode is rejected before any receipt claim is accepted", () => {
  const fixture = makeFixture();
  assert.throws(
    () => verifyFixture(fixture, { input: "unpaired\ud800" }),
    (error) => error instanceof BayRunContractError && error.code === "canonical_json_invalid",
  );
});
