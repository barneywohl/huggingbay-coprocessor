/** Explicit v1 production trust snapshot; pass it explicitly to withBayRun. */
export const BAY_RUN_PRODUCTION_TRUST_V1: Readonly<{
  trustedKeyId: "bay-run-pin-v1";
  trustedPublicKeySha256: "sha256:a03d5e873393aa061bf993d0387dab61d5f39c4fc664fbeb0bded3c9485a2a5e";
  trustedPolicyId: "bay-run.canonical-pin-decision-policy.v1";
  trustedPolicyDigest: "sha256:eb1808545f112b5bbfac4a519b2b555e0cf8960c765ac8599d6d27ca3ea565b2";
}>;

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
  /** SHA-256 digest of the exact caller-pinned decision policy contract. */
  trustedPolicyDigest: string;
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
};

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

export const DEFAULT_BAY_RUN_BASE_URL: string;
export const BAY_RUN_COPROCESSOR_PATH: "/v1/coprocessor";
