import { createHash, createPublicKey, verify as verifySignature } from "node:crypto";
import { isIP } from "node:net";

/**
 * Explicit production trust configuration for the v1 Pin proof contract.
 * This convenience snapshot is never applied implicitly by withBayRun.
 */
export const BAY_RUN_PRODUCTION_TRUST_V1 = Object.freeze({
  trustedKeyId: "bay-run-pin-v1",
  trustedPublicKeySha256:
    "sha256:a03d5e873393aa061bf993d0387dab61d5f39c4fc664fbeb0bded3c9485a2a5e",
  trustedPolicyId: "bay-run.canonical-pin-decision-policy.v1",
  trustedPolicyDigest:
    "sha256:eb1808545f112b5bbfac4a519b2b555e0cf8960c765ac8599d6d27ca3ea565b2",
});

const DEFAULT_BASE_URL = "https://run.huggingbay.xyz";
const DEFAULT_TIMEOUT_MS = 10_000;
const SDK_HEADER = "@huggingbay/coprocessor/0.1.4";
const COPROCESSOR_SCHEMA = "bay-run.coprocessor.v1";
const GUARD_POLICY_SCHEMA = "bay-run.guard-policy.v1";
const PIN_PROOF_SCHEMA = "bay-run.pin-proof.v1";
const PIN_RECEIPT_SCHEMA = "bay-run.pin-receipt.v1";
const PIN_ABSTENTION_SCHEMA = "bay-run.pin-abstention.v1";
const CANONICAL_GUARD_PIN_ID = "route_00857aa05f863c2cdba0e908366b2cca";
const CANONICAL_RERANK_PIN_ID = "route_f5411cdb31b03621742a58371fa95732";
const DECISION_ACTIONS = new Set(["allow", "block", "escalate"]);
const RERANK_BOUND_FIELDS = Object.freeze([
  "text",
  "relevance_score",
  "raw_score",
]);
const RERANK_SCORE_FIELDS = Object.freeze(["relevance_score", "raw_score"]);
const SHA256_DIGEST = /^sha256:[0-9a-f]{64}$/;
const BASE64URL = /^[A-Za-z0-9_-]+$/;
const ED25519_PUBLIC_KEY_BYTES = 32;
const ED25519_SIGNATURE_BYTES = 64;
const RAW_NUMBER_TOKENS = Symbol("bay-run-raw-number-tokens");
const RAW_NUMBER_MUTATIONS = Symbol("bay-run-raw-number-mutations");
const PIN_RECEIPT_SIGNED_FIELDS = Object.freeze([
  "schema",
  "execution_id",
  "pin_id",
  "route_id",
  "model",
  "served_weight_sha256",
  "input_sha256",
  "result_sha256",
  "idempotency_key_sha256",
]);
const PIN_DECISION_SCHEMA = "bay-run.pin-decision.v1";
const PIN_DECISION_EVIDENCE_SCHEMA = "bay-run.pin-decision-evidence.v1";
const PIN_DECISION_EVIDENCE_PROOF_SCHEMA = "bay-run.pin-decision-evidence-proof.v1";
const PIN_DECISION_EVIDENCE_SIGNED_FIELDS = Object.freeze([
  "schema",
  "receipt_id",
  "execution_id",
  "pin_id",
  "input_sha256",
  "result_sha256",
  "decision_sha256",
  "policy_contract_id",
  "policy_contract_digest",
]);
const PIN_DECISION_EVIDENCE_ALLOWED_FIELDS = new Set([
  ...PIN_DECISION_EVIDENCE_SIGNED_FIELDS,
  "proof",
]);
const PIN_RECEIPT_ALLOWED_FIELDS = new Set([
  ...PIN_RECEIPT_SIGNED_FIELDS,
  "no_spend_evidence",
  "receipt_id",
  "proof",
]);
const PIN_PROOF_FIELDS = new Set([
  "schema",
  "alg",
  "kid",
  "payload_sha256",
  "public_key",
  "signature",
  "key_scope",
]);
const ZERO_SPEND_EVIDENCE = Object.freeze({
  schema: "bay-run.no-spend-evidence.v1",
  status: "no_spend",
  server_authoritative: true,
  payment_required: false,
  max_price_usd: 0,
  priced_cost_usd: 0,
  charged_usd: 0,
  scope: "this_execution",
});
const ZERO_SPEND_EVIDENCE_FIELDS = new Set(Object.keys(ZERO_SPEND_EVIDENCE));
const ZERO_SPEND_NUMERIC_FIELDS = new Set([
  "max_price_usd",
  "priced_cost_usd",
  "charged_usd",
]);

function isRecord(value) {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function nonEmptyString(value, name) {
  if (typeof value !== "string" || value.trim() === "") {
    throw new BayRunInputError(`${name} must be a non-empty string`, {
      code: "invalid_input",
    });
  }
  return value;
}

function isLoopbackHostname(hostname) {
  const normalized = hostname.toLowerCase().replace(/^\[|\]$/g, "").replace(/\.$/, "");
  if (normalized === "localhost") return true;
  if (isIP(normalized) === 4) return normalized.split(".")[0] === "127";
  return isIP(normalized) === 6 && normalized === "::1";
}

function normalizeBaseUrl(value) {
  const raw = typeof value === "string" && value.trim() ? value.trim() : DEFAULT_BASE_URL;
  if (raw.includes("\\")) {
    throw new BayRunInputError("baseUrl must not contain backslashes", {
      code: "invalid_base_url",
    });
  }
  let parsed;
  try {
    parsed = new URL(raw);
  } catch {
    throw new BayRunInputError("baseUrl must be an absolute HTTP(S) URL", {
      code: "invalid_base_url",
    });
  }
  if (parsed.protocol !== "http:" && parsed.protocol !== "https:") {
    throw new BayRunInputError("baseUrl must use HTTP or HTTPS", {
      code: "invalid_base_url",
    });
  }
  if (parsed.username !== "" || parsed.password !== "") {
    throw new BayRunInputError("baseUrl must not contain username or password", {
      code: "invalid_base_url",
    });
  }
  if (parsed.search !== "" || parsed.hash !== "") {
    throw new BayRunInputError("baseUrl must not contain a query string or fragment", {
      code: "invalid_base_url",
    });
  }
  const pathMatch = raw.match(/^[a-z][a-z\d+.-]*:\/\/[^/?#]*(\/[^?#]*)?(?:[?#].*)?$/i);
  if (!pathMatch) {
    throw new BayRunInputError("baseUrl has an invalid pathname", {
      code: "invalid_base_url",
    });
  }
  const rawPath = pathMatch[1] ?? "/";
  if (rawPath.includes("%")) {
    throw new BayRunInputError(
      "baseUrl must not contain percent-encoded path components",
      { code: "invalid_base_url" },
    );
  }
  const normalizedRawPath = rawPath.replace(/\/+$/, "") || "/";
  const normalizedPath = parsed.pathname.replace(/\/+$/, "") || "/";
  if (
    normalizedRawPath !== normalizedPath ||
    (normalizedPath !== "/" && normalizedPath !== "/v1")
  ) {
    throw new BayRunInputError("baseUrl pathname must be / or /v1", {
      code: "invalid_base_url",
    });
  }
  if (parsed.protocol === "http:" && !isLoopbackHostname(parsed.hostname)) {
    throw new BayRunInputError(
      "non-loopback baseUrl must use HTTPS; HTTP is allowed only for loopback development",
      { code: "insecure_base_url" },
    );
  }
  return normalizedPath === "/v1" ? `${parsed.origin}/v1` : parsed.origin;
}

function coprocessorUrl(baseUrl) {
  return baseUrl.endsWith("/v1") ? `${baseUrl}/coprocessor` : `${baseUrl}/v1/coprocessor`;
}

function normalizeDocuments(documents) {
  if (documents === undefined) return undefined;
  if (!Array.isArray(documents) || documents.length === 0 || documents.length > 64) {
    throw new BayRunInputError("documents must contain between 1 and 64 strings", {
      code: "invalid_documents",
    });
  }
  return documents.map((document, index) =>
    nonEmptyString(document, `documents[${index}]`),
  );
}

function normalizeIdempotencyKey(value) {
  if (value === undefined || value === null || value === "") return undefined;
  const key = nonEmptyString(value, "idempotencyKey");
  if (key.length < 8 || key.length > 200) {
    throw new BayRunInputError("idempotencyKey must be between 8 and 200 characters", {
      code: "invalid_idempotency_key",
    });
  }
  return key;
}

function textFromContent(content) {
  if (typeof content === "string") return content;
  if (!Array.isArray(content)) return "";
  return content
    .map((part) => {
      if (typeof part === "string") return part;
      if (isRecord(part) && typeof part.text === "string") return part.text;
      return "";
    })
    .filter(Boolean)
    .join("\n");
}

function lastUserMessage(messages, name = "messages") {
  if (!Array.isArray(messages)) {
    throw new BayRunInputError(`${name} must be an array`, { code: "invalid_input" });
  }
  for (let index = messages.length - 1; index >= 0; index -= 1) {
    const message = messages[index];
    if (!isRecord(message)) continue;
    if (String(message.role || "").toLowerCase() !== "user") continue;
    const text = textFromContent(message.content);
    if (text.trim()) return text;
  }
  throw new BayRunInputError(`${name} must contain a non-empty user message`, {
    code: "invalid_input",
  });
}

function selectedDocuments(input, selector) {
  const selected = typeof selector === "function" ? selector(input) : undefined;
  if (selected !== undefined) return normalizeDocuments(selected);
  if (isRecord(input) && isRecord(input.bayRun) && input.bayRun.documents !== undefined) {
    return normalizeDocuments(input.bayRun.documents);
  }
  if (isRecord(input) && input.documents !== undefined) {
    return normalizeDocuments(input.documents);
  }
  return undefined;
}

function selectedIdempotencyKey(input, selector) {
  const selected = typeof selector === "function" ? selector(input) : undefined;
  if (selected !== undefined) return normalizeIdempotencyKey(selected);
  if (isRecord(input) && isRecord(input.bayRun)) {
    return normalizeIdempotencyKey(input.bayRun.idempotencyKey);
  }
  if (isRecord(input)) return normalizeIdempotencyKey(input.idempotencyKey);
  return undefined;
}

function serializedFailure(error) {
  if (error instanceof BayRunError) return error.toJSON();
  return { code: "bay_run_unavailable", retriable: true };
}

function invalidContract(message, code = "invalid_contract") {
  throw new BayRunContractError(message, { code });
}

function contractString(value, name) {
  if (typeof value !== "string" || value.trim() === "") {
    invalidContract(`${name} must be a non-empty string`);
  }
  return value;
}

function contractNumber(value, name, { nullable = false } = {}) {
  if (nullable && value === null) return value;
  if (typeof value !== "number" || !Number.isFinite(value)) {
    invalidContract(`${name} must be a finite number`);
  }
  return value;
}

function contractDigest(value, name) {
  if (typeof value !== "string" || !SHA256_DIGEST.test(value)) {
    invalidContract(`${name} must be a SHA-256 digest`);
  }
  return value;
}

function normalizeTrustedProof(options) {
  const publicKeySha256 = options.trustedPublicKeySha256;
  const keyId = options.trustedKeyId;
  if (
    typeof publicKeySha256 !== "string" ||
    !SHA256_DIGEST.test(publicKeySha256) ||
    typeof keyId !== "string" ||
    keyId.trim() === ""
  ) {
    throw new BayRunInputError(
      "trustedPublicKeySha256 and trustedKeyId are required; provide a SHA-256 digest and non-empty key ID",
      { code: "invalid_proof_trust" },
    );
  }
  return Object.freeze({ publicKeySha256, keyId });
}

function normalizeTrustedPolicy(options) {
  const policyId = options.trustedPolicyId;
  const policyDigest = options.trustedPolicyDigest;
  if (
    typeof policyId !== "string" ||
    policyId.trim() === "" ||
    typeof policyDigest !== "string" ||
    !SHA256_DIGEST.test(policyDigest)
  ) {
    throw new BayRunInputError(
      "trustedPolicyId and trustedPolicyDigest are required; provide a non-empty policy ID and SHA-256 digest",
      { code: "invalid_policy_trust" },
    );
  }
  return Object.freeze({ id: policyId, digest: policyDigest });
}

function canonicalJsonText(value) {
  return serializeCanonicalJson(value, undefined, undefined, false);
}

function childKeyJsonText(value) {
  return serializeCanonicalJson(value, undefined, undefined, true);
}

function assertWellFormedUnicode(value) {
  for (let index = 0; index < value.length; index += 1) {
    const code = value.charCodeAt(index);
    if (code >= 0xd800 && code <= 0xdbff) {
      const next = value.charCodeAt(index + 1);
      if (next >= 0xdc00 && next <= 0xdfff) {
        index += 1;
        continue;
      }
      throw new BayRunContractError(
        "canonical JSON cannot contain an unpaired surrogate",
        { code: "canonical_json_invalid" },
      );
    }
    if (code >= 0xdc00 && code <= 0xdfff) {
      throw new BayRunContractError(
        "canonical JSON cannot contain an unpaired surrogate",
        { code: "canonical_json_invalid" },
      );
    }
  }
}

function canonicalJsonString(value, ensureAscii) {
  assertWellFormedUnicode(value);
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
    else if (code < 0x20 || (ensureAscii && code >= 0x7f)) {
      result += `\\u${code.toString(16).padStart(4, "0")}`;
    } else {
      result += value[index];
    }
  }
  return `${result}"`;
}

function compareCanonicalKeys(left, right) {
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

function serializeCanonicalJson(value, parent, key, ensureAscii) {
  if (value === null) return "null";
  if (value === undefined) return undefined;
  if (typeof value === "string") return canonicalJsonString(value, ensureAscii);
  if (typeof value === "boolean") return value ? "true" : "false";
  if (typeof value === "number") {
    const field = String(key);
    const raw = parent?.[RAW_NUMBER_TOKENS]?.get(field);
    const mutated = parent?.[RAW_NUMBER_MUTATIONS]?.has(field);
    if (!mutated && raw !== undefined && Number(raw) === value) return raw;
    if (!Number.isFinite(value)) {
      throw new TypeError("canonical JSON cannot contain a non-finite number");
    }
    return JSON.stringify(value);
  }
  if (Array.isArray(value)) {
    return `[${value
      .map((item, index) => serializeCanonicalJson(item, value, index, ensureAscii) ?? "null")
      .join(",")}]`;
  }
  if (isRecord(value)) {
    return `{${Object.keys(value)
      .sort(compareCanonicalKeys)
      .map((name) => {
        const serialized = serializeCanonicalJson(value[name], value, name, ensureAscii);
        return serialized === undefined
          ? undefined
          : `${canonicalJsonString(name, ensureAscii)}:${serialized}`;
      })
      .filter((item) => item !== undefined)
      .join(",")}}`;
  }
  throw new TypeError("canonical JSON cannot contain an unsupported value");
}

function canonicalJsonBytes(value) {
  return Buffer.from(canonicalJsonText(value), "utf8");
}

function sha256Digest(value) {
  return `sha256:${createHash("sha256")
    .update(canonicalJsonBytes(value))
    .digest("hex")}`;
}

function sha256BytesDigest(value) {
  return `sha256:${createHash("sha256").update(value).digest("hex")}`;
}

function decodeBase64Url(value, name, expectedLength) {
  contractString(value, name);
  if (!BASE64URL.test(value) || value.length % 4 === 1) {
    invalidContract(`${name} must be unpadded base64url`, "proof_invalid");
  }
  let decoded;
  try {
    decoded = Buffer.from(value, "base64url");
  } catch {
    invalidContract(`${name} must be unpadded base64url`, "proof_invalid");
  }
  if (
    decoded.length !== expectedLength ||
    decoded.toString("base64url") !== value
  ) {
    invalidContract(`${name} has an invalid Ed25519 length`, "proof_invalid");
  }
  return decoded;
}

function rememberRawNumber(container, key, raw) {
  let tokens = container[RAW_NUMBER_TOKENS];
  if (!tokens) {
    tokens = new Map();
    Object.defineProperty(container, RAW_NUMBER_TOKENS, {
      configurable: false,
      enumerable: false,
      value: tokens,
      writable: false,
    });
  }
  tokens.set(String(key), raw);
}

function trackParsedContainer(container) {
  // Keep a signed number's wire lexeme only until a caller mutates that field.
  Object.defineProperty(container, RAW_NUMBER_MUTATIONS, {
    configurable: false,
    enumerable: false,
    value: new Set(),
    writable: false,
  });
  return new Proxy(container, {
    defineProperty(target, property, descriptor) {
      const field = String(property);
      if (target[RAW_NUMBER_TOKENS]?.has(field)) {
        target[RAW_NUMBER_MUTATIONS].add(field);
      }
      return Reflect.defineProperty(target, property, descriptor);
    },
    deleteProperty(target, property) {
      const field = String(property);
      if (target[RAW_NUMBER_TOKENS]?.has(field)) {
        target[RAW_NUMBER_MUTATIONS].add(field);
      }
      return Reflect.deleteProperty(target, property);
    },
    set(target, property, value, receiver) {
      const field = String(property);
      if (target[RAW_NUMBER_TOKENS]?.has(field)) {
        target[RAW_NUMBER_MUTATIONS].add(field);
      }
      return Reflect.set(target, property, value, receiver);
    },
  });
}

function parseJsonWithRawNumbers(text) {
  let offset = 0;

  const fail = () => {
    throw new SyntaxError("invalid JSON");
  };
  const skipWhitespace = () => {
    while (offset < text.length && /[\u0009\u000a\u000d\u0020]/.test(text[offset])) {
      offset += 1;
    }
  };
  const parseString = () => {
    const start = offset;
    if (text[offset] !== '"') fail();
    offset += 1;
    let escaped = false;
    while (offset < text.length) {
      const character = text[offset];
      if (escaped) {
        escaped = false;
        offset += 1;
        continue;
      }
      if (character === "\\") {
        escaped = true;
        offset += 1;
        continue;
      }
      if (character === '"') {
        offset += 1;
        try {
          return JSON.parse(text.slice(start, offset));
        } catch {
          fail();
        }
      }
      if (character < " ") fail();
      offset += 1;
    }
    fail();
  };
  const parseNumber = () => {
    const match = text.slice(offset).match(/^-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?/);
    if (!match) fail();
    const raw = match[0];
    const value = Number(raw);
    if (!Number.isFinite(value)) fail();
    offset += raw.length;
    return { raw, value };
  };
  const parseValue = () => {
    skipWhitespace();
    const character = text[offset];
    if (character === '"') return { value: parseString() };
    if (character === "{") return { value: parseObject() };
    if (character === "[") return { value: parseArray() };
    if (character === "t" && text.startsWith("true", offset)) {
      offset += 4;
      return { value: true };
    }
    if (character === "f" && text.startsWith("false", offset)) {
      offset += 5;
      return { value: false };
    }
    if (character === "n" && text.startsWith("null", offset)) {
      offset += 4;
      return { value: null };
    }
    if (character === "-" || /[0-9]/.test(character || "")) {
      const number = parseNumber();
      return { value: number.value, raw: number.raw };
    }
    fail();
  };
  const parseArray = () => {
    const result = trackParsedContainer([]);
    offset += 1;
    skipWhitespace();
    if (text[offset] === "]") {
      offset += 1;
      return result;
    }
    while (offset < text.length) {
      const parsed = parseValue();
      result.push(parsed.value);
      if (parsed.raw !== undefined) rememberRawNumber(result, result.length - 1, parsed.raw);
      skipWhitespace();
      if (text[offset] === "]") {
        offset += 1;
        return result;
      }
      if (text[offset] !== ",") fail();
      offset += 1;
    }
    fail();
  };
  const parseObject = () => {
    const result = trackParsedContainer(Object.create(null));
    const keys = new Set();
    offset += 1;
    skipWhitespace();
    if (text[offset] === "}") {
      offset += 1;
      return result;
    }
    while (offset < text.length) {
      skipWhitespace();
      const key = parseString();
      if (keys.has(key)) fail();
      keys.add(key);
      skipWhitespace();
      if (text[offset] !== ":") fail();
      offset += 1;
      const parsed = parseValue();
      Object.defineProperty(result, key, {
        configurable: true,
        enumerable: true,
        value: parsed.value,
        writable: true,
      });
      if (parsed.raw !== undefined) rememberRawNumber(result, key, parsed.raw);
      skipWhitespace();
      if (text[offset] === "}") {
        offset += 1;
        return result;
      }
      if (text[offset] !== ",") fail();
      offset += 1;
    }
    fail();
  };

  const parsed = parseValue();
  skipWhitespace();
  if (offset !== text.length) fail();
  return parsed.value;
}

function validateZeroSpendEvidence(evidence, name) {
  if (!isRecord(evidence)) {
    invalidContract(`${name} must be an object`, "no_spend_invalid");
  }
  const fields = Object.keys(evidence);
  if (
    fields.length !== ZERO_SPEND_EVIDENCE_FIELDS.size ||
    fields.some((field) => !ZERO_SPEND_EVIDENCE_FIELDS.has(field))
  ) {
    invalidContract(
      `${name} must contain exactly the zero-spend evidence fields`,
      "no_spend_invalid",
    );
  }
  for (const field of ZERO_SPEND_EVIDENCE_FIELDS) {
    if (!(field in evidence)) {
      invalidContract(`${name}.${field} is required`, "no_spend_invalid");
    }
    if (!ZERO_SPEND_NUMERIC_FIELDS.has(field) && evidence[field] !== ZERO_SPEND_EVIDENCE[field]) {
      invalidContract(
        `${name}.${field} does not exactly declare zero server spend`,
        "no_spend_invalid",
      );
    }
  }
  for (const field of ZERO_SPEND_NUMERIC_FIELDS) {
    if (
      typeof evidence[field] !== "number" ||
      !Object.is(evidence[field], 0) ||
      evidence[RAW_NUMBER_MUTATIONS]?.has(field) ||
      evidence[RAW_NUMBER_TOKENS]?.get(field) !== "0.0"
    ) {
      invalidContract(
        `${name}.${field} must be the exact wire number 0.0`,
        "no_spend_invalid",
      );
    }
  }
  return evidence;
}

function deriveStageIdempotencyKey(pinId, input) {
  return createHash("sha256")
    .update(`${pinId}\u0000${childKeyJsonText(input)}`, "utf8")
    .digest("hex")
    .slice(0, 32);
}

function verifyEd25519Proof(proof, payload, stageName, trustedProof, proofSchema) {
  if (!trustedProof) {
    invalidContract(
      `${stageName} proof trust is not configured`,
      "proof_trust_unconfigured",
    );
  }
  for (const field of PIN_PROOF_FIELDS) {
    if (!(field in proof)) {
      invalidContract(`${stageName}.${field} is required`, "proof_invalid");
    }
  }
  const unknown = Object.keys(proof).filter((field) => !PIN_PROOF_FIELDS.has(field));
  if (unknown.length > 0) {
    invalidContract(
      `${stageName} has unsupported proof fields: ${unknown.join(", ")}`,
      "proof_invalid",
    );
  }
  if (
    proof.schema !== proofSchema ||
    proof.alg !== "Ed25519" ||
    proof.key_scope !== "configured"
  ) {
    invalidContract(
      `${stageName} must declare ${proofSchema} Ed25519`,
      "proof_invalid",
    );
  }
  contractString(proof.kid, `${stageName}.kid`);
  contractString(proof.key_scope, `${stageName}.key_scope`);
  contractDigest(proof.payload_sha256, `${stageName}.payload_sha256`);
  if (proof.kid !== trustedProof.keyId) {
    invalidContract(
      `${stageName}.kid does not match trusted configuration`,
      "proof_untrusted_signer",
    );
  }

  const publicKeyBytes = decodeBase64Url(
    proof.public_key,
    `${stageName}.public_key`,
    ED25519_PUBLIC_KEY_BYTES,
  );
  if (sha256BytesDigest(publicKeyBytes) !== trustedProof.publicKeySha256) {
    invalidContract(
      `${stageName}.public_key does not match trusted configuration`,
      "proof_untrusted_signer",
    );
  }
  const signature = decodeBase64Url(
    proof.signature,
    `${stageName}.signature`,
    ED25519_SIGNATURE_BYTES,
  );
  const body = canonicalJsonBytes(payload);
  if (proof.payload_sha256 !== sha256BytesDigest(body)) {
    invalidContract(
      `${stageName}.payload_sha256 does not match the signed payload`,
      "proof_payload_mismatch",
    );
  }

  let publicKey;
  try {
    publicKey = createPublicKey({
      key: { crv: "Ed25519", kty: "OKP", x: proof.public_key },
      format: "jwk",
    });
  } catch {
    invalidContract(`${stageName}.public_key is not a valid Ed25519 key`, "proof_invalid");
  }
  let signatureValid = false;
  try {
    signatureValid = verifySignature(null, body, publicKey, signature);
  } catch {
    signatureValid = false;
  }
  if (!signatureValid) {
    invalidContract(
      `${stageName}.signature is invalid`,
      "proof_signature_invalid",
    );
  }
}

function validateReceiptProof(proof, payload, receiptId, stageName, trustedProof) {
  verifyEd25519Proof(
    proof,
    payload,
    `${stageName}.receipt.proof`,
    trustedProof,
    PIN_PROOF_SCHEMA,
  );
  if (receiptId !== sha256Digest({ ...payload, proof })) {
    invalidContract(
      `${stageName}.receipt.receipt_id does not match the payload and proof`,
      "receipt_id_mismatch",
    );
  }
}

function validateDecisionEvidence(
  decision,
  decisionEvidence,
  receipt,
  stageName,
  trustedProof,
  trustedPolicy,
) {
  if (!isRecord(decision)) {
    invalidContract(`${stageName}.decision must be an object`, "decision_invalid");
  }
  if (decision.schema !== PIN_DECISION_SCHEMA) {
    invalidContract(`${stageName}.decision has an unsupported schema`, "decision_invalid");
  }
  if (
    decision.pin_id !== receipt.pin_id ||
    decision.raw_result_preserved !== true ||
    decision.receipt_binds !== "result"
  ) {
    invalidContract(
      `${stageName}.decision is not bound to the exact stage result`,
      "decision_invalid",
    );
  }
  contractString(decision.action, `${stageName}.decision.action`);
  if (!isRecord(decisionEvidence)) {
    invalidContract(
      `${stageName}.decision_evidence must be an object`,
      "decision_evidence_invalid",
    );
  }
  for (const field of PIN_DECISION_EVIDENCE_SIGNED_FIELDS) {
    if (!(field in decisionEvidence)) {
      invalidContract(
        `${stageName}.decision_evidence.${field} is required`,
        "decision_evidence_invalid",
      );
    }
  }
  const unknown = Object.keys(decisionEvidence).filter(
    (field) => !PIN_DECISION_EVIDENCE_ALLOWED_FIELDS.has(field),
  );
  if (unknown.length > 0) {
    invalidContract(
      `${stageName}.decision_evidence has unsupported fields: ${unknown.join(", ")}`,
      "decision_evidence_invalid",
    );
  }
  if (decisionEvidence.schema !== PIN_DECISION_EVIDENCE_SCHEMA) {
    invalidContract(
      `${stageName}.decision_evidence has an unsupported schema`,
      "decision_evidence_invalid",
    );
  }
  if (decisionEvidence.receipt_id !== receipt.receipt_id) {
    invalidContract(
      `${stageName}.decision_evidence.receipt_id does not match the receipt`,
      "decision_evidence_mismatch",
    );
  }
  for (const field of ["execution_id", "pin_id", "input_sha256", "result_sha256"]) {
    if (decisionEvidence[field] !== receipt[field]) {
      invalidContract(
        `${stageName}.decision_evidence.${field} does not match the receipt`,
        "decision_evidence_mismatch",
      );
    }
  }
  contractString(
    decisionEvidence.policy_contract_id,
    `${stageName}.decision_evidence.policy_contract_id`,
  );
  contractDigest(
    decisionEvidence.policy_contract_digest,
    `${stageName}.decision_evidence.policy_contract_digest`,
  );
  if (!trustedPolicy) {
    invalidContract(
      `${stageName}.decision_evidence policy trust is not configured`,
      "policy_trust_unconfigured",
    );
  }
  if (decisionEvidence.policy_contract_id !== trustedPolicy.id) {
    invalidContract(
      `${stageName}.decision_evidence policy ID does not match trusted configuration`,
      "policy_mismatch",
    );
  }
  if (decisionEvidence.policy_contract_digest !== trustedPolicy.digest) {
    invalidContract(
      `${stageName}.decision_evidence policy digest does not match trusted configuration`,
      "policy_mismatch",
    );
  }
  contractDigest(
    decisionEvidence.decision_sha256,
    `${stageName}.decision_evidence.decision_sha256`,
  );
  if (decisionEvidence.decision_sha256 !== sha256Digest(decision)) {
    invalidContract(
      `${stageName}.decision_evidence.decision_sha256 does not match the complete decision`,
      "decision_evidence_mismatch",
    );
  }
  const payload = Object.fromEntries(
    PIN_DECISION_EVIDENCE_SIGNED_FIELDS.map((field) => [field, decisionEvidence[field]]),
  );
  if (!isRecord(decisionEvidence.proof)) {
    invalidContract(
      `${stageName}.decision_evidence.proof must be an object`,
      "decision_evidence_invalid",
    );
  }
  verifyEd25519Proof(
    decisionEvidence.proof,
    payload,
    `${stageName}.decision_evidence.proof`,
    trustedProof,
    PIN_DECISION_EVIDENCE_PROOF_SCHEMA,
  );
}

function validateReceipt(
  receipt,
  pinId,
  stageName,
  expectedInput,
  expectedIdempotencyKey,
  trustedProof,
) {
  if (!isRecord(receipt)) {
    invalidContract(`${stageName}.receipt must be an object`, "evidence_invalid");
  }
  for (const field of [
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
    "receipt_id",
    "proof",
  ]) {
    if (!(field in receipt)) {
      invalidContract(`${stageName}.receipt.${field} is required`, "evidence_invalid");
    }
  }
  const unknown = Object.keys(receipt).filter((field) => !PIN_RECEIPT_ALLOWED_FIELDS.has(field));
  if (unknown.length > 0) {
    invalidContract(
      `${stageName}.receipt has unsupported fields: ${unknown.join(", ")}`,
      "evidence_invalid",
    );
  }
  if (receipt.schema !== PIN_RECEIPT_SCHEMA) {
    invalidContract(`${stageName}.receipt has an unsupported schema`, "evidence_invalid");
  }
  if (receipt.pin_id !== pinId || receipt.route_id !== pinId) {
    invalidContract(`${stageName}.receipt identity does not match its stage`, "evidence_identity_mismatch");
  }
  contractString(receipt.execution_id, `${stageName}.receipt.execution_id`);
  contractString(receipt.model, `${stageName}.receipt.model`);
  contractDigest(receipt.input_sha256, `${stageName}.receipt.input_sha256`);
  if (expectedInput !== undefined && receipt.input_sha256 !== sha256Digest(expectedInput)) {
    invalidContract(
      `${stageName}.receipt.input_sha256 does not match the caller request`,
      "evidence_input_mismatch",
    );
  }
  contractDigest(receipt.result_sha256, `${stageName}.receipt.result_sha256`);
  contractDigest(
    receipt.idempotency_key_sha256,
    `${stageName}.receipt.idempotency_key_sha256`,
  );
  if (
    expectedIdempotencyKey !== undefined &&
    receipt.idempotency_key_sha256 !== sha256Digest(expectedIdempotencyKey)
  ) {
    invalidContract(
      `${stageName}.receipt.idempotency_key_sha256 does not match the deterministic stage key`,
      "evidence_idempotency_mismatch",
    );
  }
  contractDigest(receipt.receipt_id, `${stageName}.receipt.receipt_id`);
  if (
    receipt.served_weight_sha256 !== null &&
    (typeof receipt.served_weight_sha256 !== "string" ||
      !SHA256_DIGEST.test(receipt.served_weight_sha256))
  ) {
    invalidContract(
      `${stageName}.receipt.served_weight_sha256 must be null or a SHA-256 digest`,
      "evidence_invalid",
    );
  }
  if (!isRecord(receipt.proof)) {
    invalidContract(`${stageName}.receipt.proof must be an object`, "evidence_invalid");
  }
  validateZeroSpendEvidence(receipt.no_spend_evidence, `${stageName}.receipt.no_spend_evidence`);
  const payload = Object.fromEntries(
    PIN_RECEIPT_SIGNED_FIELDS.map((field) => [field, receipt[field]]),
  );
  payload.no_spend_evidence = receipt.no_spend_evidence;
  validateReceiptProof(
    receipt.proof,
    payload,
    receipt.receipt_id,
    stageName,
    trustedProof,
  );
  return receipt;
}

function validateStageEvidence(
  stage,
  pinId,
  stageName,
  expectedInput,
  expectedIdempotencyKey,
  trustedProof,
  trustedPolicy,
) {
  if (!isRecord(stage)) {
    invalidContract(`${stageName} evidence must be an object`, "evidence_invalid");
  }
  if (stage.pin_id !== pinId) {
    invalidContract(`${stageName} evidence is not bound to the canonical Pin`, "evidence_identity_mismatch");
  }
  if (!isRecord(stage.result)) {
    invalidContract(`${stageName}.result must be an object`, "evidence_invalid");
  }
  if (!isRecord(stage.decision)) {
    invalidContract(`${stageName}.decision must be an object`, "decision_invalid");
  }
  if (!isRecord(stage.decision_evidence)) {
    invalidContract(
      `${stageName}.decision_evidence must be an object`,
      "decision_evidence_invalid",
    );
  }
  if (!isRecord(stage.no_spend_evidence)) {
    invalidContract(
      `${stageName}.no_spend_evidence must be an object`,
      "evidence_invalid",
    );
  }
  if (typeof stage.verified !== "boolean" || typeof stage.replayed !== "boolean") {
    invalidContract(`${stageName} evidence flags are invalid`, "evidence_invalid");
  }
  contractString(stage.evidence_level, `${stageName}.evidence_level`);
  validateZeroSpendEvidence(stage.no_spend_evidence, `${stageName}.no_spend_evidence`);
  const receipt = validateReceipt(
    stage.receipt,
    pinId,
    stageName,
    expectedInput,
    expectedIdempotencyKey,
    trustedProof,
  );
  if (receipt.result_sha256 !== sha256Digest(stage.result)) {
    invalidContract(
      `${stageName}.receipt.result_sha256 does not match stage.result`,
      "evidence_result_mismatch",
    );
  }
  if (canonicalJsonText(stage.no_spend_evidence) !== canonicalJsonText(receipt.no_spend_evidence)) {
    invalidContract(
      `${stageName} no-spend evidence is not receipt-consistent`,
      "evidence_mismatch",
    );
  }
  validateDecisionEvidence(
    stage.decision,
    stage.decision_evidence,
    receipt,
    stageName,
    trustedProof,
    trustedPolicy,
  );
  return stage.result;
}

function validateGuardPolicy(policy, guard, action) {
  if (policy === undefined) return;
  if (!isRecord(policy) || policy.schema !== GUARD_POLICY_SCHEMA) {
    invalidContract("guard.policy has an unsupported schema", "guard_policy_invalid");
  }
  if (policy.decision !== action) {
    invalidContract("guard.policy.decision does not match action", "guard_policy_mismatch");
  }
  if (policy.raw_label !== null && policy.raw_label !== undefined) {
    contractString(policy.raw_label, "guard.policy.raw_label");
    if (policy.raw_label.trim().toUpperCase() !== guard.label.trim().toUpperCase()) {
      invalidContract("guard.policy.raw_label does not match guard.label", "guard_policy_mismatch");
    }
  }
  if (policy.raw_score !== null && policy.raw_score !== undefined) {
    contractNumber(policy.raw_score, "guard.policy.raw_score");
    if (policy.raw_score !== guard.score) {
      invalidContract("guard.policy.raw_score does not match guard.score", "guard_policy_mismatch");
    }
  }
  if (policy.confidence_threshold !== undefined && policy.confidence_threshold !== null) {
    contractNumber(policy.confidence_threshold, "guard.policy.confidence_threshold");
  }
  if (
    policy.manipulation_indicators !== undefined &&
    (!Array.isArray(policy.manipulation_indicators) ||
      policy.manipulation_indicators.some((item) => typeof item !== "string"))
  ) {
    invalidContract(
      "guard.policy.manipulation_indicators must be strings",
      "guard_policy_invalid",
    );
  }
}

function validateRerankRows(rows, documents, stageName) {
  if (!Array.isArray(rows)) {
    invalidContract(`${stageName}.results must be an array`, "rerank_invalid");
  }
  const seen = new Set();
  const indexes = [];
  for (const item of rows) {
    if (!isRecord(item) || !Number.isInteger(item.index)) {
      invalidContract(`${stageName}.results rows require integer indices`, "rerank_index_invalid");
    }
    if (item.index < 0 || item.index >= documents.length || seen.has(item.index)) {
      invalidContract(`${stageName}.results contains an invalid or duplicate index`, "rerank_index_invalid");
    }
    seen.add(item.index);
    if ("text" in item && item.text !== documents[item.index]) {
      invalidContract(
        `${stageName}.results text does not match the caller-owned document`,
        "rerank_text_mismatch",
      );
    }
    if ("text" in item && typeof item.text !== "string") {
      invalidContract(`${stageName}.results text must be a string`, "rerank_text_mismatch");
    }
    for (const field of RERANK_SCORE_FIELDS) {
      if (field in item) {
        contractNumber(item[field], `${stageName}.results.${field}`);
      }
    }
    indexes.push(item.index);
  }
  return indexes;
}

function rerankTopScore(rows, stageName) {
  const scores = rows
    .filter((item) => isRecord(item) && item.relevance_score !== undefined)
    .map((item) => contractNumber(item.relevance_score, `${stageName}.relevance_score`));
  return scores.length > 0 ? Math.max(...scores) : undefined;
}

function validateRerankBindings(summaryRows, evidenceRows, stageName) {
  // The receipt's result_sha256 authenticates evidenceRows. The response
  // summary is not signed separately, so every exposed text or score must
  // match the corresponding receipt-bound result row without adding fields to
  // the receipt contract.
  for (let position = 0; position < summaryRows.length; position += 1) {
    const summaryRow = summaryRows[position];
    const evidenceRow = evidenceRows[position];
    for (const field of RERANK_BOUND_FIELDS) {
      const summaryHasField = field in summaryRow;
      const evidenceHasField = field in evidenceRow;
      if (summaryHasField !== evidenceHasField) {
        invalidContract(
          `${stageName} row ${position} ${field} is not present in both the summary and receipt-bound result`,
          "rerank_evidence_mismatch",
        );
      }
      if (!summaryHasField) continue;
      if (field === "text") {
        const summaryText = contractString(
          summaryRow[field],
          `${stageName}.results[${position}].text`,
        );
        const evidenceText = contractString(
          evidenceRow[field],
          `${stageName}.result.results[${position}].text`,
        );
        if (summaryText !== evidenceText) {
          invalidContract(
            `${stageName} text does not match the receipt-bound result`,
            "rerank_evidence_mismatch",
          );
        }
        continue;
      }
      const summaryScore = contractNumber(
        summaryRow[field],
        `${stageName}.results[${position}].${field}`,
      );
      const evidenceScore = contractNumber(
        evidenceRow[field],
        `${stageName}.result.results[${position}].${field}`,
      );
      if (!Object.is(summaryScore, evidenceScore)) {
        invalidContract(
          `${stageName} ${field} does not match the receipt-bound result`,
          "rerank_evidence_mismatch",
        );
      }
    }
  }
}

function validateRerankSummary(
  rerank,
  rerankEvidence,
  documents,
  userText,
  trustedProof,
  trustedPolicy,
) {
  if (!isRecord(rerank)) {
    invalidContract("rerank must be an object when documents were supplied", "rerank_invalid");
  }
  if (rerank.pin_id !== CANONICAL_RERANK_PIN_ID) {
    invalidContract("rerank is not bound to the canonical Rerank Pin", "rerank_identity_mismatch");
  }
  contractString(rerank.score_type, "rerank.score_type");
  if (rerank.signal !== "ranked" && rerank.signal !== "no_signal") {
    invalidContract("rerank.signal is invalid", "rerank_invalid");
  }
  if (rerank.signal === "ranked") {
    if (rerank.abstention !== null) {
      invalidContract("ranked rerank cannot include abstention", "rerank_invalid");
    }
  } else if (
    !isRecord(rerank.abstention) ||
    rerank.abstention.schema !== PIN_ABSTENTION_SCHEMA ||
    rerank.abstention.abstained !== true
  ) {
    invalidContract("no-signal rerank requires abstention evidence", "rerank_invalid");
  }
  if (rerank.signal === "no_signal") {
    for (const field of ["score", "threshold"]) {
      if (rerank.abstention[field] !== undefined && rerank.abstention[field] !== null) {
        contractNumber(rerank.abstention[field], `rerank.abstention.${field}`);
      }
    }
    contractString(rerank.abstention.reason_code, "rerank.abstention.reason_code");
  }

  const summaryIndexes = validateRerankRows(rerank.results, documents, "rerank");
  const summaryTopScore = rerankTopScore(rerank.results, "rerank");
  const evidenceResult = validateStageEvidence(
    rerankEvidence,
    CANONICAL_RERANK_PIN_ID,
    "evidence.rerank",
    { query: userText, documents },
    deriveStageIdempotencyKey(CANONICAL_RERANK_PIN_ID, { query: userText, documents }),
    trustedProof,
    trustedPolicy,
  );
  const decision = rerankEvidence.decision;
  if (
    (rerank.signal === "ranked" && decision.action !== "rank") ||
    (rerank.signal === "no_signal" && decision.action !== "abstain")
  ) {
    invalidContract(
      "rerank decision action does not match ranked/no_signal semantics",
      "rerank_evidence_mismatch",
    );
  }
  const evidenceIndexes = validateRerankRows(
    evidenceResult.results,
    documents,
    "evidence.rerank.result",
  );
  const evidenceTopScore = rerankTopScore(
    evidenceResult.results,
    "evidence.rerank.result",
  );
  if (
    summaryIndexes.length !== evidenceIndexes.length ||
    summaryIndexes.some((index, position) => index !== evidenceIndexes[position])
  ) {
    invalidContract("rerank summary and evidence rows do not match", "rerank_evidence_mismatch");
  }
  validateRerankBindings(rerank.results, evidenceResult.results, "rerank");
  if (rerank.signal === "ranked" && summaryIndexes.length === 0) {
    invalidContract("ranked rerank requires at least one result", "rerank_invalid");
  }
  if (rerank.signal === "ranked") {
    contractNumber(decision.score, "evidence.rerank.decision.score");
    if (
      summaryTopScore === undefined ||
      evidenceTopScore === undefined ||
      decision.score !== summaryTopScore ||
      decision.score !== evidenceTopScore
    ) {
      invalidContract(
        "signed rerank score does not match the ranked rows",
        "rerank_evidence_mismatch",
      );
    }
  } else {
    contractString(decision.reason_code, "evidence.rerank.decision.reason_code");
    if (decision.reason_code !== rerank.abstention.reason_code) {
      invalidContract(
        "signed rerank abstention reason does not match the summary",
        "rerank_evidence_mismatch",
      );
    }
    if (decision.score !== undefined && decision.score !== null) {
      contractNumber(decision.score, "evidence.rerank.decision.score");
      if (
        rerank.abstention.score !== undefined &&
        rerank.abstention.score !== null &&
        decision.score !== rerank.abstention.score
      ) {
        invalidContract(
          "signed rerank abstention score does not match the summary",
          "rerank_evidence_mismatch",
        );
      }
    }
    if (decision.threshold !== undefined && decision.threshold !== null) {
      contractNumber(decision.threshold, "evidence.rerank.decision.threshold");
      if (
        rerank.abstention.threshold !== undefined &&
        rerank.abstention.threshold !== null &&
        decision.threshold !== rerank.abstention.threshold
      ) {
        invalidContract(
          "signed rerank abstention threshold does not match the summary",
          "rerank_evidence_mismatch",
        );
      }
    }
  }
  return rerank.signal === "ranked"
    ? evidenceIndexes.map((index) => documents[index])
    : undefined;
}

function validateCoprocessorResponse(body, request, options) {
  if (!isRecord(body)) {
    invalidContract("Bay Run coprocessor response must be an object");
  }
  if (body.schema !== COPROCESSOR_SCHEMA) {
    invalidContract("Bay Run coprocessor response has an unsupported schema", "schema_invalid");
  }
  const action = typeof body.action === "string" ? body.action : "";
  if (!DECISION_ACTIONS.has(action)) {
    invalidContract(
      "Bay Run response did not contain a supported top-level action",
      "decision_missing",
    );
  }
  if (typeof body.ok !== "boolean" || body.ok !== (action === "allow")) {
    invalidContract("Bay Run response ok does not match action", "success_contract_invalid");
  }
  contractString(body.reason, "reason");

  if (!isRecord(body.guard)) {
    invalidContract("Bay Run response is missing guard", "guard_invalid");
  }
  if (body.guard.pin_id !== CANONICAL_GUARD_PIN_ID) {
    invalidContract("guard is not bound to the canonical Guard Pin", "guard_identity_mismatch");
  }
  if (body.guard.action !== action) {
    invalidContract("guard.action does not match action", "guard_evidence_mismatch");
  }
  contractString(body.guard.label, "guard.label");
  contractNumber(body.guard.score, "guard.score");
  if (action === "allow" && body.guard.label.trim().toUpperCase() !== "SAFE") {
    invalidContract("allow requires the canonical Guard SAFE label", "guard_evidence_mismatch");
  }

  if (!isRecord(body.evidence)) {
    invalidContract("Bay Run response is missing evidence", "evidence_invalid");
  }
  const guardResult = validateStageEvidence(
    body.evidence.guard,
    CANONICAL_GUARD_PIN_ID,
    "evidence.guard",
    request.userText,
    deriveStageIdempotencyKey(CANONICAL_GUARD_PIN_ID, request.userText),
    options.trustedProof,
    options.trustedPolicy,
  );
  const guardDecision = body.evidence.guard.decision;
  if (
    guardDecision.pin_id !== CANONICAL_GUARD_PIN_ID ||
    !DECISION_ACTIONS.has(guardDecision.action) ||
    guardDecision.action !== action ||
    guardDecision.action !== body.guard.action
  ) {
    invalidContract(
      "signed Guard decision does not match the top-level action and summary",
      "guard_evidence_mismatch",
    );
  }
  const labels = guardResult.labels;
  if (!Array.isArray(labels) || labels.length === 0 || !isRecord(labels[0])) {
    invalidContract("evidence.guard.result must contain Guard labels", "guard_evidence_mismatch");
  }
  contractString(labels[0].label, "evidence.guard.result.labels[0].label");
  contractNumber(labels[0].score, "evidence.guard.result.labels[0].score");
  if (labels[0].label.trim().toUpperCase() !== body.guard.label.trim().toUpperCase()) {
    invalidContract("Guard label and evidence label do not match", "guard_evidence_mismatch");
  }
  if (labels[0].score !== body.guard.score) {
    invalidContract("Guard score and evidence score do not match", "guard_evidence_mismatch");
  }
  if (!isRecord(body.guard.policy)) {
    invalidContract("guard.policy is required for the signed Guard decision", "guard_policy_invalid");
  }
  validateGuardPolicy(body.guard.policy, body.guard, action);
  contractString(guardDecision.reason_code, "evidence.guard.decision.reason_code");
  contractNumber(guardDecision.score, "evidence.guard.decision.score");
  if (guardDecision.score !== body.guard.score || guardDecision.score !== labels[0].score) {
    invalidContract(
      "signed Guard score does not match the summary and result",
      "guard_evidence_mismatch",
    );
  }
  if (guardDecision.reason_code !== body.guard.policy.reason_code) {
    invalidContract(
      "signed Guard reason does not match the policy summary",
      "guard_evidence_mismatch",
    );
  }

  const hasDocuments = request.documents !== undefined;
  const expectsRerank = action === "allow" && hasDocuments;
  if (expectsRerank) {
    if (body.rerank === null || body.evidence.rerank === null) {
      invalidContract("allow with documents requires rerank evidence", "rerank_invalid");
    }
  } else if (body.rerank !== null || body.evidence.rerank !== null) {
    invalidContract("response contains unexpected rerank data", "rerank_invalid");
  }
  const orderedDocuments = expectsRerank
    ? validateRerankSummary(
      body.rerank,
      body.evidence.rerank,
      request.documents,
      request.userText,
      options.trustedProof,
      options.trustedPolicy,
    )
    : undefined;

  if (!isRecord(body.next_call)) {
    invalidContract("Bay Run response is missing next_call", "success_contract_invalid");
  }
  const expectedNextCall = {
    allow: { generation: "allowed", tool_use: "allowed" },
    block: { generation: "blocked", tool_use: "blocked" },
    escalate: { generation: "review_required", tool_use: "review_required" },
  }[action];
  if (
    body.next_call.action !== action ||
    body.next_call.generation !== expectedNextCall.generation ||
    body.next_call.tool_use !== expectedNextCall.tool_use
  ) {
    invalidContract("next_call does not match action", "success_contract_invalid");
  }

  return {
    decision: guardDecision,
    rerankDecision: expectsRerank ? body.evidence.rerank.decision : undefined,
    rerankedDocuments: orderedDocuments,
  };
}

function timeoutSignal(parentSignal, timeoutMs) {
  const controller = new AbortController();
  let timedOut = false;
  let cancelled = false;
  let settled = false;
  const timeoutReason = {};
  const cancellationReason = {};
  let rejectDeadline;
  const deadlinePromise = new Promise((_, reject) => {
    rejectDeadline = reject;
  });
  const timer = setTimeout(() => {
    if (settled) return;
    settled = true;
    timedOut = true;
    controller.abort();
    rejectDeadline(timeoutReason);
  }, timeoutMs);
  const abortParent = () => {
    if (settled) return;
    settled = true;
    cancelled = true;
    controller.abort(parentSignal?.reason);
    rejectDeadline(cancellationReason);
  };
  if (parentSignal) {
    if (parentSignal.aborted) abortParent();
    else parentSignal.addEventListener("abort", abortParent, { once: true });
  }
  return {
    signal: controller.signal,
    deadlinePromise,
    timeoutReason,
    cancellationReason,
    didTimeout: () => timedOut,
    didCancel: () => cancelled,
    clear: () => {
      settled = true;
      clearTimeout(timer);
      parentSignal?.removeEventListener("abort", abortParent);
    },
  };
}

function timeoutFailure() {
  return new BayRunTransportError("Bay Run coprocessor request timed out", {
    code: "timeout",
    retriable: true,
  });
}

function cancellationFailure() {
  return new BayRunTransportError("Bay Run coprocessor request was cancelled", {
    code: "request_cancelled",
    retriable: false,
  });
}

function throwIfRequestCancelled(signal) {
  if (signal?.aborted) throw cancellationFailure();
}

async function awaitWithTimeout(promise, timeout) {
  try {
    return await Promise.race([promise, timeout.deadlinePromise]);
  } catch (cause) {
    if (cause === timeout.timeoutReason) throw timeoutFailure();
    if (cause === timeout.cancellationReason) throw cancellationFailure();
    throw cause;
  }
}

async function parseResponseBody(response) {
  let text = "";
  try {
    text = await response.text();
  } catch (cause) {
    throw new BayRunTransportError("Bay Run response could not be read", {
      code: "invalid_response",
      status: response.status,
      cause,
    });
  }
  try {
    return text ? parseJsonWithRawNumbers(text) : {};
  } catch (cause) {
    throw new BayRunTransportError("Bay Run returned an invalid JSON response", {
      code: "invalid_response",
      status: response.status,
      cause,
    });
  }
}

function apiErrorFromBody(status, body) {
  const error = isRecord(body) && isRecord(body.error) ? body.error : {};
  const details = {};
  for (const key of [
    "request_id",
    "reason_code",
    "minimum_available_price",
    "recommended_action",
    "retry_after_ms",
  ]) {
    if (error[key] !== undefined) details[key] = error[key];
  }
  return new BayRunApiError(
    typeof error.reason === "string" ? error.reason : "Bay Run rejected the coprocessor request",
    {
      code: typeof error.code === "string" ? error.code : "bay_run_rejected",
      status,
      retriable: error.retriable === true,
      details,
    },
  );
}

async function requestCoprocessor(request, options) {
  const fetchImpl = options.fetch ?? globalThis.fetch;
  if (typeof fetchImpl !== "function") {
    throw new BayRunTransportError("This runtime does not provide fetch", {
      code: "fetch_unavailable",
    });
  }
  const timeout = timeoutSignal(request.signal, options.timeoutMs);
  const headers = {
    Accept: "application/json",
    "Content-Type": "application/json",
    "X-Bay-Run-Client": SDK_HEADER,
  };
  const credential = options.token ?? options.apiKey;
  if (credential) headers.Authorization = `Bearer ${credential}`;
  if (request.idempotencyKey) headers["Idempotency-Key"] = request.idempotencyKey;
  // The SDK verifies the complete receipt-bound evidence before it acts on a
  // decision, so it explicitly opts into the REST audit representation.
  const body = { user_text: request.userText, omit_raw_result: false };
  if (request.documents) body.documents = request.documents;
  try {
    let response;
    try {
      response = await awaitWithTimeout(
        Promise.resolve().then(() => fetchImpl(coprocessorUrl(options.baseUrl), {
          method: "POST",
          headers,
          body: JSON.stringify(body),
          redirect: "error",
          signal: timeout.signal,
        })),
        timeout,
      );
    } catch (cause) {
      if (
        cause instanceof BayRunTransportError &&
        (cause.code === "timeout" || cause.code === "request_cancelled")
      ) {
        throw cause;
      }
      if (timeout.didTimeout()) {
        throw timeoutFailure();
      }
      if (timeout.didCancel()) {
        throw cancellationFailure();
      }
      throw new BayRunTransportError("Bay Run coprocessor request failed", {
        code: "network_error",
        retriable: true,
        cause,
      });
    }
    if (!response || typeof response.text !== "function" || typeof response.status !== "number") {
      throw new BayRunTransportError("Bay Run returned an invalid HTTP response", {
        code: "invalid_response",
        retriable: true,
      });
    }
    if (response.redirected === true) {
      throw new BayRunTransportError("Bay Run redirected the coprocessor request", {
        code: "redirect_error",
        status: response.status,
        retriable: true,
      });
    }
    let parsed;
    try {
      parsed = await awaitWithTimeout(parseResponseBody(response), timeout);
    } catch (cause) {
      if (
        cause instanceof BayRunTransportError &&
        (cause.code === "timeout" || cause.code === "request_cancelled")
      ) {
        throw cause;
      }
      if (timeout.didTimeout()) throw timeoutFailure();
      if (timeout.didCancel()) throw cancellationFailure();
      if (cause instanceof BayRunTransportError) throw cause;
      throw new BayRunTransportError("Bay Run response could not be read", {
        code: "invalid_response",
        status: response.status,
      });
    }
    if (response.status < 200 || response.status >= 300) {
      throw apiErrorFromBody(response.status, parsed);
    }
    let validated;
    try {
      validated = validateCoprocessorResponse(parsed, request, options);
    } catch (error) {
      if (error instanceof BayRunContractError && error.status === undefined) {
        error.status = response.status;
      }
      throw error;
    }
    return {
      body: parsed,
      decision: validated.decision,
      rerankDecision: validated.rerankDecision,
      rerankedDocuments: validated.rerankedDocuments,
    };
  } finally {
    timeout.clear();
  }
}

export class BayRunError extends Error {
  constructor(message, { code = "bay_run_error", status, retriable = false, details = {} } = {}) {
    // Deliberately do not retain the underlying exception: fetch errors can
    // contain URLs, headers, or provider data that applications may log.
    super(message);
    this.name = "BayRunError";
    this.code = code;
    this.status = status;
    this.retriable = retriable;
    this.details = Object.freeze({ ...details });
  }

  toJSON() {
    const value = { code: this.code, retriable: this.retriable };
    if (this.status !== undefined) value.status = this.status;
    Object.assign(value, this.details);
    return value;
  }
}

export class BayRunInputError extends BayRunError {
  constructor(message, options = {}) {
    super(message, { ...options, code: options.code ?? "invalid_input" });
    this.name = "BayRunInputError";
  }
}

export class BayRunApiError extends BayRunError {
  constructor(message, options = {}) {
    super(message, options);
    this.name = "BayRunApiError";
  }
}

export class BayRunTransportError extends BayRunError {
  constructor(message, options = {}) {
    super(message, { ...options, code: options.code ?? "bay_run_unavailable" });
    this.name = "BayRunTransportError";
  }
}

export class BayRunContractError extends BayRunError {
  constructor(message, options = {}) {
    super(message, { ...options, code: options.code ?? "invalid_response" });
    this.name = "BayRunContractError";
  }
}

export function genericAdapter(input) {
  if (typeof input === "string") return { userText: nonEmptyString(input, "input") };
  if (!isRecord(input)) {
    throw new BayRunInputError("generic input must be a string or object", {
      code: "invalid_input",
    });
  }
  const userText = input.userText ?? input.input ?? input.prompt;
  return {
    userText: nonEmptyString(userText, "input"),
    documents: selectedDocuments(input),
    idempotencyKey: selectedIdempotencyKey(input),
    signal: input.signal,
  };
}

export function openAICompatibleAdapter({ documents, idempotencyKey } = {}) {
  const adapter = (input) => ({
    userText: lastUserMessage(input?.messages),
    documents: selectedDocuments(input, documents),
    idempotencyKey: selectedIdempotencyKey(input, idempotencyKey),
    signal: input?.signal,
  });
  adapter.prepare = stripBayRunFields;
  return adapter;
}

export function anthropicAdapter({ documents, idempotencyKey } = {}) {
  const adapter = (input) => ({
    userText: lastUserMessage(input?.messages),
    documents: selectedDocuments(input, documents),
    idempotencyKey: selectedIdempotencyKey(input, idempotencyKey),
    signal: input?.signal,
  });
  adapter.prepare = stripBayRunFields;
  return adapter;
}

export function stripBayRunFields(input) {
  if (!isRecord(input)) return input;
  const {
    bayRun: _bayRun,
    documents: _documents,
    idempotencyKey: _idempotencyKey,
    signal: _signal,
    ...providerInput
  } = input;
  return providerInput;
}

function normalizeRequest(request) {
  if (!isRecord(request)) {
    throw new BayRunInputError("adapter must return an object", { code: "invalid_input" });
  }
  return {
    userText: nonEmptyString(request.userText, "userText"),
    documents: normalizeDocuments(request.documents),
    idempotencyKey: normalizeIdempotencyKey(request.idempotencyKey),
    signal: request.signal,
  };
}

function normalizeOptions(options) {
  if (!isRecord(options)) {
    throw new BayRunInputError("withBayRun options are required", { code: "invalid_options" });
  }
  if (typeof options.adapter !== "function") {
    throw new BayRunInputError("withBayRun requires an adapter function", {
      code: "invalid_options",
    });
  }
  const timeoutMs = options.timeoutMs ?? DEFAULT_TIMEOUT_MS;
  if (!Number.isFinite(timeoutMs) || timeoutMs <= 0) {
    throw new BayRunInputError("timeoutMs must be a positive number", { code: "invalid_options" });
  }
  const token = options.token === undefined ? undefined : nonEmptyString(options.token, "token");
  const apiKey = options.apiKey === undefined ? undefined : nonEmptyString(options.apiKey, "apiKey");
  return {
    ...options,
    baseUrl: normalizeBaseUrl(options.baseUrl),
    trustedProof: normalizeTrustedProof(options),
    trustedPolicy: normalizeTrustedPolicy(options),
    timeoutMs,
    token,
    apiKey,
    failClosed: options.failClosed !== false,
  };
}

async function prepareForGeneration(input, context, config) {
  let preparedInput = input;
  if (typeof config.adapter.prepare === "function") {
    preparedInput = await config.adapter.prepare(preparedInput, context);
  }
  preparedInput = stripBayRunFields(preparedInput);
  if (typeof config.prepare === "function") {
    preparedInput = await config.prepare(preparedInput, context);
  }
  return stripBayRunFields(preparedInput);
}

export function withBayRun(generate, options) {
  if (typeof generate !== "function") {
    throw new BayRunInputError("generate must be a function", { code: "invalid_generator" });
  }
  const config = normalizeOptions(options);
  return async function guardedGenerate(input) {
    let request;
    try {
      request = normalizeRequest(config.adapter(input));
      if (typeof config.idempotencyKey === "function") {
        request.idempotencyKey = normalizeIdempotencyKey(
          config.idempotencyKey(input, request),
        );
      } else if (config.idempotencyKey !== undefined) {
        request.idempotencyKey = normalizeIdempotencyKey(config.idempotencyKey);
      }
    } catch (error) {
      throw error;
    }

    throwIfRequestCancelled(request.signal);
    let checked;
    try {
      checked = await requestCoprocessor(request, config);
    } catch (error) {
      if (
        error instanceof BayRunTransportError &&
        error.code === "request_cancelled"
      ) {
        throw error;
      }
      if (request.signal?.aborted) {
        if (error instanceof BayRunTransportError && error.code === "timeout") {
          throw error;
        }
        throw cancellationFailure();
      }
      if (config.failClosed) throw error;
      const context = Object.freeze({
        bayRunAvailable: false,
        error: serializedFailure(error),
        originalDocuments: request.documents,
      });
      throwIfRequestCancelled(request.signal);
      const preparedInput = await prepareForGeneration(input, context, config);
      throwIfRequestCancelled(request.signal);
      const output = await generate(preparedInput, context);
      return { status: "bypassed", output, context, error: serializedFailure(error) };
    }

    throwIfRequestCancelled(request.signal);
    const context = Object.freeze({
      bayRunAvailable: true,
      decision: checked.decision,
      bayRunResponse: checked.body,
      originalDocuments: request.documents,
      rerankedDocuments: checked.rerankedDocuments,
    });
    if (checked.decision.action === "block") {
      return { status: "blocked", decision: checked.decision, context };
    }
    if (checked.decision.action !== "allow") {
      return { status: "review_required", decision: checked.decision, context };
    }
    if (checked.rerankDecision?.action === "abstain") {
      return { status: "review_required", decision: checked.rerankDecision, context };
    }

    const preparedInput = await prepareForGeneration(input, context, config);
    throwIfRequestCancelled(request.signal);
    const output = await generate(preparedInput, context);
    return { status: "generated", output, decision: checked.decision, context };
  };
}

export const DEFAULT_BAY_RUN_BASE_URL = DEFAULT_BASE_URL;
export const BAY_RUN_COPROCESSOR_PATH = "/v1/coprocessor";
