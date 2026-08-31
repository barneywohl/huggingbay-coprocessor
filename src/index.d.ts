/** Explicit v1 production trust snapshot; pass it explicitly to withBayRun. */
export const BAY_RUN_PRODUCTION_TRUST_V1: Readonly<{
  trustedKeyId: "bay-run-pin-v1";
  trustedPublicKeySha256: "sha256:a03d5e873393aa061bf993d0387dab61d5f39c4fc664fbeb0bded3c9485a2a5e";
  trustedPolicyId: "bay-run.canonical-pin-decision-policy.v1";
  trustedPolicyDigest: "sha256:8e96163e816880f1e62e8307964b3268c97ba496a5a96bf492e0d97d3b12be82";
  trustedPolicyDigests: readonly [
    "sha256:8e96163e816880f1e62e8307964b3268c97ba496a5a96bf492e0d97d3b12be82",
    "sha256:0aedfb921cd643cbe8e4f9ac264539d5adc699d445030e66cab4e9d56ff68d48",
  ];
}>;

export type BayRunPinProof = {
  schema: "bay-run.pin-proof.v1";
  alg: "Ed25519";
  kid: string;
  payload_sha256: string;
  public_key: string;
  signature: string;
  key_scope: "configured";
};

export type BayRunPinReceipt = {
  schema: "bay-run.pin-receipt.v1";
  execution_id: string;
  pin_id: string;
  route_id: string;
  model: string;
  served_weight_sha256: string | null;
  input_sha256: string;
  result_sha256: string;
  idempotency_key_sha256: string;
  no_spend_evidence: Readonly<Record<string, unknown>>;
  receipt_id: string;
  proof: BayRunPinProof;
};

export type BayRunPinReceiptTrust = {
  /** Exact configured Ed25519 proof key ID. */
  trustedKeyId: string;
  /** SHA-256 of the decoded raw 32-byte Ed25519 public key in the proof. */
  trustedPublicKeySha256: string;
};

export type BayRunPinReceiptVerificationOptions =
  BayRunPinReceiptTrust & {
    /** Exact original value that the receipt claims to bind. */
    input: unknown;
    /** Exact raw result value that the receipt claims to bind. */
    result: unknown;
    /** Exact caller-supplied idempotency key that the receipt claims to bind. */
    idempotencyKey: string;
  };

export type BayRunPinReceiptVerification = {
  valid: true;
  schema: "bay-run.pin-receipt.v1";
  receiptId: string;
  executionId: string;
  pinId: string;
  keyId: string;
  signedPayloadFields: readonly string[];
};

export type BayRunDecisionAction = "allow" | "block" | "escalate" | "abstain";

export type BayRunDecision = {
  schema: "bay-run.pin-decision.v1";
  pin_id: string;
  raw_result_preserved: true;
  receipt_binds: "result";
  action: BayRunDecisionAction;
  reason_code: string;
  [key: string]: unknown;
};

export type BayRunRequest = {
  userText: string;
  documents?: readonly string[];
  idempotencyKey?: string;
  signal?: AbortSignal;
};

export type BayRunCoprocessorResponse = Record<string, unknown>;

export type BayRunGenerationContext = {
  bayRunAvailable: true;
  /** The receipt-bound Guard decision; inspect bayRunResponse.action for composite overlays. */
  decision: BayRunDecision;
  bayRunResponse: BayRunCoprocessorResponse;
  originalDocuments?: readonly string[];
  rerankedDocuments?: readonly string[];
};

export type BayRunBypassContext = {
  bayRunAvailable: false;
  error: BayRunFailure;
  originalDocuments?: readonly string[];
};

export type BayRunFailure = {
  code: string;
  status?: number;
  retriable: boolean;
  [key: string]: unknown;
};

export type BayRunOutcome<T> =
  | {
      status: "generated";
      output: T;
      decision: BayRunDecision;
      context: BayRunGenerationContext;
    }
  | {
      status: "blocked";
      decision: BayRunDecision;
      context: BayRunGenerationContext;
    }
  | {
      status: "review_required";
      decision: BayRunDecision;
      context: BayRunGenerationContext;
    }
  | {
      status: "bypassed";
      output: T;
      context: BayRunBypassContext;
      error: BayRunFailure;
    };

export type BayRunFetch = (
  input: string | URL,
  init?: RequestInit,
) => Promise<Response>;

export type BayRunPreparedInput<TInput> = TInput extends object
  ? Omit<TInput, "bayRun" | "documents" | "idempotencyKey" | "signal">
  : TInput;

export type BayRunRequestAdapter<
  TInput,
  TPreparedInput = BayRunPreparedInput<TInput>,
> = ((input: TInput) => BayRunRequest) & {
  prepare?: (
    input: TInput,
    context: BayRunGenerationContext | BayRunBypassContext,
  ) => TPreparedInput | Promise<TPreparedInput>;
};

type BayRunPolicyTrust =
  | {
      /** Exact caller-pinned decision policy contract digest. */
      trustedPolicyDigest: string;
      /** Explicit immutable accepted digest set for rotations. */
      trustedPolicyDigests?: readonly string[];
    }
  | {
      /** Exact caller-pinned decision policy contract digest. */
      trustedPolicyDigest?: string;
      /** Explicit immutable accepted digest set for rotations. */
      trustedPolicyDigests: readonly string[];
    };

export type BayRunOptions<
  TInput,
  TPreparedInput = BayRunPreparedInput<TInput>,
> = {
  adapter: BayRunRequestAdapter<TInput, TPreparedInput>;
  /** HTTPS is required for non-loopback origins; HTTP is for loopback development only. */
  baseUrl?: string;
  /** SHA-256 of the decoded raw 32-byte Ed25519 public key from the proof. */
  trustedPublicKeySha256: string;
  /** Exact configured Ed25519 proof key ID. */
  trustedKeyId: string;
  /** Exact caller-pinned decision policy contract ID. */
  trustedPolicyId: string;
  token?: string;
  apiKey?: string;
  timeoutMs?: number;
  /** Defaults to true; false explicitly permits generation without a verified decision. */
  failClosed?: boolean;
  fetch?: BayRunFetch;
  idempotencyKey?: string | ((input: TInput, request: BayRunRequest) => string | undefined);
  prepare?: (
    input: TPreparedInput,
    context: BayRunGenerationContext | BayRunBypassContext,
  ) => TPreparedInput | Promise<TPreparedInput>;
} & BayRunPolicyTrust;

export type BayRunGenerate<TInput, TOutput> = (
  input: TInput,
  context: BayRunGenerationContext | BayRunBypassContext,
) => TOutput | Promise<TOutput>;

export type OpenAIMessage = {
  role: string;
  content: string | readonly { type?: string; text?: string }[];
};

export type OpenAICompatibleRequest = {
  model?: string;
  messages: readonly OpenAIMessage[];
  bayRun?: { documents?: readonly string[]; idempotencyKey?: string };
  documents?: readonly string[];
  idempotencyKey?: string;
  signal?: AbortSignal;
};

export type AnthropicMessage = OpenAIMessage;
export type AnthropicStyleRequest = OpenAICompatibleRequest & {
  system?: string | readonly { type?: string; text?: string }[];
};

export class BayRunError extends Error {
  readonly code: string;
  readonly status?: number;
  readonly retriable: boolean;
  readonly details: Readonly<Record<string, unknown>>;
  toJSON(): BayRunFailure;
}

export class BayRunInputError extends BayRunError {}
export class BayRunApiError extends BayRunError {}
export class BayRunTransportError extends BayRunError {}
export class BayRunContractError extends BayRunError {}

export function genericAdapter(
  input: string | { input?: string; userText?: string; prompt?: string; documents?: readonly string[]; signal?: AbortSignal; idempotencyKey?: string },
): BayRunRequest;

export function openAICompatibleAdapter<T extends OpenAICompatibleRequest>(options?: {
  documents?: (input: T) => readonly string[] | undefined;
  idempotencyKey?: (input: T) => string | undefined;
}): BayRunRequestAdapter<T, BayRunPreparedInput<T>>;

export function anthropicAdapter<T extends AnthropicStyleRequest>(options?: {
  documents?: (input: T) => readonly string[] | undefined;
  idempotencyKey?: (input: T) => string | undefined;
}): BayRunRequestAdapter<T, BayRunPreparedInput<T>>;

export function stripBayRunFields<TInput extends object>(
  input: TInput,
): Omit<TInput, "bayRun" | "documents" | "idempotencyKey" | "signal">;

export function withBayRun<TInput, TOutput, TPreparedInput = BayRunPreparedInput<TInput>>(
  generate: BayRunGenerate<TPreparedInput, TOutput>,
  options: BayRunOptions<TInput, TPreparedInput>,
): (input: TInput) => Promise<BayRunOutcome<TOutput>>;

/**
 * Verify one signed Pin receipt against caller-owned input, result, and key.
 * Throws a BayRunContractError with a stable code when any binding fails.
 */
export function verifyPinReceipt(
  receipt: BayRunPinReceipt,
  options: BayRunPinReceiptVerificationOptions,
): BayRunPinReceiptVerification;

/** @internal Parse package wire JSON while preserving canonical number lexemes. */
export function parseBayRunJson(text: string): unknown;

export const DEFAULT_BAY_RUN_BASE_URL: string;
export const BAY_RUN_COPROCESSOR_PATH: "/v1/coprocessor";
