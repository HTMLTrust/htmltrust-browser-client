/**
 * Shared types for the HTMLTrust browser client.
 *
 * Re-exports the resolver/key types from @htmltrust/canonicalization so that
 * downstream consumers can import everything from a single package.
 */

export type {
  KeyResolver,
  ResolvedKey,
  Endorsement,
  SignatureBindingParts,
} from "@htmltrust/canonicalization";
