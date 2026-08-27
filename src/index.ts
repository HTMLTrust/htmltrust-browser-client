/**
 * Public API surface for @htmltrust/browser-client.
 *
 * Two layers, matching the specification's two-layer verification model:
 *   - Layer 1 (verify): cryptographic verification of signed-section blocks
 *   - Layer 2 (policy): user-policy-driven trust evaluation
 * Plus endorsement fetching/verification (§2.5) and resolver helpers.
 */

export { verifySignedSection, extractSignedSections, canonicalizeSignedContent } from "./verify.js";
export type { VerifyOptions, VerifyResult } from "./verify.js";

export { evaluateTrustPolicy } from "./policy.js";
export type {
  TrustPolicy,
  TrustEvaluation,
  TrustInput,
  DirectorySubscription,
} from "./policy.js";

export {
  fetchEndorsements,
  fetchEndorsementsWithFailures,
  verifyStructuredEndorsement,
} from "./endorsements.js";
export type {
  EndorsementFetchFailure,
  FetchEndorsementsOptions,
  FetchEndorsementsResult,
  StructuredEndorsement,
} from "./endorsements.js";

export {
  didWebResolver,
  directUrlResolver,
  trustDirectoryResolver,
  resolveKey,
  defaultResolverChain,
} from "./resolver.js";
export type {
  DefaultResolverChainOptions,
  ResolverOptions,
  TrustDirectoryResolverOptions,
} from "./resolver.js";

export type {
  KeyResolver,
  ResolvedKey,
  SignatureBindingParts,
} from "./types.js";
export { isLoopbackHost, isPrivateHost } from "./spec.js";
export type {
  VerificationFailureReason,
  VerificationInputState,
} from "./spec.js";
