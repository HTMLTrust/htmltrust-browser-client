/**
 * Public API surface for @htmltrust/browser-client.
 *
 * Two layers, matching the specification's two-layer verification model:
 *   - Layer 1 (verify): cryptographic verification of signed-section blocks
 *   - Layer 2 (policy): user-policy-driven trust evaluation
 * Plus endorsement fetching/verification (§2.5) and resolver helpers.
 */

export { verifySignedSection, extractSignedSections } from "./verify.js";
export type { VerifyOptions, VerifyResult } from "./verify.js";

export { evaluateTrustPolicy } from "./policy.js";
export type {
  TrustPolicy,
  TrustEvaluation,
  TrustInput,
  DirectorySubscription,
} from "./policy.js";

export { fetchEndorsements } from "./endorsements.js";
export type { FetchEndorsementsOptions } from "./endorsements.js";

export {
  didWebResolver,
  directUrlResolver,
  trustDirectoryResolver,
  resolveKey,
  defaultResolverChain,
} from "./resolver.js";
export type { DefaultResolverChainOptions } from "./resolver.js";

export type {
  KeyResolver,
  ResolvedKey,
  Endorsement,
  SignatureBindingParts,
} from "./types.js";
