/**
 * Layer 1: Cryptographic verification of a <signed-section>.
 *
 * Implements spec §3.1 (browser behavior, cryptographic verification layer).
 * This module is browser-pure: it does NOT import from node:crypto. SHA-256
 * is performed via SubtleCrypto when available, or via a caller-supplied
 * hash callback (the e2e harness uses the latter when running over plain
 * HTTP, where SubtleCrypto is unavailable).
 */

import {
  buildSignatureBinding,
  canonicalizeClaims,
  extractCanonicalText,
  resolveKey,
  verifySignature,
} from "@htmltrust/canonicalization";
import type { KeyResolver } from "@htmltrust/canonicalization";

export interface VerifyOptions {
  /** Resolver chain used to map keyid -> public key. Required. */
  keyResolvers: KeyResolver[];
  /**
   * Domain bound to the signature. Defaults to window.location.hostname when
   * running in a browser; required when running outside a browser context.
   */
  domain?: string;
  /**
   * Optional override for SHA-256. Receives a UTF-8 string, returns the
   * digest as unpadded Base64 per HTMLTrust spec §2.1 (the implementation
   * prefixes it with "sha256:"). Provide this when SubtleCrypto is
   * unavailable (e.g. plain HTTP origins in test harnesses).
   */
  hash?: (canonical: string) => Promise<string>;
  /**
   * When true, write a console.warn diagnostic each time verification
   * fails, including the canonical text, computed vs embedded hashes, and
   * the signature binding. Useful for debugging signer/verifier
   * mismatches in production deployments.
   */
  debug?: boolean;
}

export interface VerifyResult {
  valid: boolean;
  keyid: string;
  algorithm: string;
  contentHash: string;
  claimsHash: string;
  claims: Record<string, string>;
  signedAt: string;
  domain: string;
  /** Populated when valid === false. */
  reason?: string;
}

type ParsedSection = {
  signature: string;
  keyid: string;
  contentHashAttr: string;
  algorithm: string;
  signedAt: string;
  claims: Record<string, string>;
  innerHTML: string;
};

function bytesToUnpaddedBase64(bytes: Uint8Array): string {
  // HTMLTrust spec §2.1: hashes and signatures are unpadded standard Base64.
  let bin = "";
  for (let i = 0; i < bytes.length; i++) bin += String.fromCharCode(bytes[i]);
  return btoa(bin).replace(/=+$/, "");
}

async function defaultHash(canonical: string): Promise<string> {
  const subtle = (globalThis as { crypto?: { subtle?: SubtleCrypto } }).crypto?.subtle;
  if (!subtle) {
    throw new Error(
      "verifySignedSection: SubtleCrypto is unavailable; provide options.hash (e.g. a Node-side SHA-256 implementation) or run in a secure context",
    );
  }
  const buf = await subtle.digest("SHA-256", new TextEncoder().encode(canonical));
  return bytesToUnpaddedBase64(new Uint8Array(buf));
}

/**
 * Parse the signed-section attributes and inner <meta> claim metadata.
 *
 * Accepts either a DOM Element (the live signed-section node) or an HTML
 * fragment string. The string path is used in tests and SSR pipelines that
 * do not have a DOM available.
 */
function parseSection(input: Element | string): ParsedSection | null {
  if (typeof input === "string") {
    return parseSectionFromString(input);
  }
  const signature = input.getAttribute("signature") ?? "";
  const keyid = input.getAttribute("keyid") ?? "";
  const contentHashAttr = input.getAttribute("content-hash") ?? "";
  const algorithm = (input.getAttribute("algorithm") || "ed25519").toLowerCase();

  const claims: Record<string, string> = {};
  let signedAt = "";
  const metas = input.querySelectorAll("meta");
  metas.forEach((meta) => {
    const name = meta.getAttribute("name");
    const content = meta.getAttribute("content") ?? "";
    if (!name) return;
    if (name === "signed-at") signedAt = content;
    else if (name.startsWith("claim:")) claims[name.slice(6)] = content;
  });

  return {
    signature,
    keyid,
    contentHashAttr,
    algorithm,
    signedAt,
    claims,
    innerHTML: input.innerHTML,
  };
}

// ---- String-path parsing ----
//
// Mirrors the regex-based extraction used in the e2e prototype: it is
// intentionally regex-only (no DOM parser dependency) so this module remains
// browser-pure and free of polyfills. It handles the well-formed output of
// real CMS pipelines; pathological input should use the DOM-element path.

const SIGNED_SECTION_RE =
  /<signed-section\b([^>]*)>([\s\S]*?)<\/signed-section\s*>/i;
const ATTR_RE = /([a-z][a-z0-9-]*)\s*=\s*"([^"]*)"|([a-z][a-z0-9-]*)\s*=\s*'([^']*)'/gi;
const META_RE = /<meta\b([^>]*)\/?>(?:\s*<\/meta\s*>)?/gi;

function parseAttrs(attrSrc: string): Record<string, string> {
  const out: Record<string, string> = {};
  ATTR_RE.lastIndex = 0;
  let m: RegExpExecArray | null;
  while ((m = ATTR_RE.exec(attrSrc))) {
    const name = (m[1] ?? m[3] ?? "").toLowerCase();
    const value = m[2] ?? m[4] ?? "";
    if (name) out[name] = value;
  }
  return out;
}

function parseSectionFromString(html: string): ParsedSection | null {
  const m = SIGNED_SECTION_RE.exec(html);
  if (!m) return null;
  const attrs = parseAttrs(m[1]);
  const inner = m[2];

  const claims: Record<string, string> = {};
  let signedAt = "";
  META_RE.lastIndex = 0;
  let mm: RegExpExecArray | null;
  while ((mm = META_RE.exec(inner))) {
    const a = parseAttrs(mm[1]);
    const name = a.name;
    const content = a.content ?? "";
    if (!name) continue;
    if (name === "signed-at") signedAt = content;
    else if (name.startsWith("claim:")) claims[name.slice(6)] = content;
  }

  return {
    signature: attrs.signature ?? "",
    keyid: attrs.keyid ?? "",
    contentHashAttr: attrs["content-hash"] ?? "",
    algorithm: (attrs.algorithm || "ed25519").toLowerCase(),
    signedAt,
    claims,
    innerHTML: inner,
  };
}

function defaultDomain(opt?: string): string {
  if (opt) return opt;
  const loc = (globalThis as { location?: { hostname?: string } }).location;
  return loc?.hostname ?? "";
}

/**
 * Verify a signed-section element (or HTML fragment).
 *
 * Steps (spec §2.1, §3.1):
 *   1. Parse signed-section attributes and inner <meta> claim metadata.
 *   2. Apply extractCanonicalText to the innerHTML and SHA-256 hash it,
 *      prefixed as "sha256:<unpadded-base64>" per spec §2.1. Compare against the embedded
 *      content-hash attribute.
 *   3. Canonicalize claims (canonicalizeClaims) and hash them.
 *   4. Resolve keyid through the supplied resolver chain.
 *   5. Build the canonical signature binding and verify the signature.
 *
 * Failure paths populate `reason` so callers can surface the specific
 * failure mode (UI affordance, telemetry, debugging).
 */
export async function verifySignedSection(
  section: Element | string,
  options: VerifyOptions,
): Promise<VerifyResult> {
  const parsed = parseSection(section);
  const domain = defaultDomain(options.domain);
  const hashFn = options.hash ?? defaultHash;

  const empty = (reason: string, partial?: Partial<VerifyResult>): VerifyResult => ({
    valid: false,
    keyid: parsed?.keyid ?? "",
    algorithm: parsed?.algorithm ?? "",
    contentHash: parsed?.contentHashAttr ?? "",
    claimsHash: "",
    claims: parsed?.claims ?? {},
    signedAt: parsed?.signedAt ?? "",
    domain,
    reason,
    ...partial,
  });

  const debug = options.debug === true;
  const warn = (reason: string, details: Record<string, unknown>) => {
    if (debug) console.warn("[htmltrust] verify failed:", reason, details);
  };

  if (!parsed) {
    warn("missing required attributes", { input: typeof section === "string" ? section.slice(0, 200) : "(Element)" });
    return empty("missing required attributes");
  }

  const { signature, keyid, contentHashAttr, algorithm, signedAt, claims, innerHTML } = parsed;
  if (!signature || !keyid || !contentHashAttr || !signedAt) {
    warn("missing required attributes", { signature: !!signature, keyid, contentHashAttr, signedAt });
    return empty("missing required attributes");
  }

  // Step 2: content hash
  const canonicalContent = extractCanonicalText(innerHTML);
  const computedContentHash = `sha256:${await hashFn(canonicalContent)}`;
  if (computedContentHash !== contentHashAttr) {
    warn("content hash mismatch", {
      embeddedContentHash: contentHashAttr,
      computedContentHash,
      canonicalTextLength: canonicalContent.length,
      canonicalTextHead: canonicalContent.slice(0, 200),
      canonicalTextTail: canonicalContent.slice(-200),
      innerHTMLLength: innerHTML.length,
      innerHTMLHead: innerHTML.slice(0, 200),
    });
    return empty("content hash mismatch");
  }

  // Step 3: claims hash
  const claimsCanonical = canonicalizeClaims(claims);
  const claimsHash = `sha256:${await hashFn(claimsCanonical)}`;

  // Step 4: keyid -> public key. Treat thrown exceptions (e.g. network
  // errors from a resolver fetching a stale or invalid keyid URL) the same
  // as a returned-null: "key not resolvable". Errors that bubble out of the
  // resolver chain are not the verifier's responsibility to surface.
  let resolved = null;
  let resolverError: unknown = null;
  try {
    resolved = await resolveKey(keyid, options.keyResolvers);
  } catch (e) {
    resolverError = e;
    resolved = null;
  }
  if (!resolved) {
    warn("key not resolvable", { keyid, resolverError: resolverError instanceof Error ? resolverError.message : resolverError });
    return empty("key not resolvable", { claimsHash });
  }

  // Step 5: signature binding + verify
  const binding = buildSignatureBinding({
    contentHash: contentHashAttr,
    claimsHash,
    domain,
    signedAt,
  });
  const sigOk = await verifySignature(
    binding,
    signature,
    resolved.publicKeyPem,
    resolved.algorithm || algorithm,
  );

  if (!sigOk) {
    warn("signature invalid", {
      binding,
      signature,
      keyid,
      algorithm: resolved.algorithm || algorithm,
      publicKeyPemHead: resolved.publicKeyPem.slice(0, 80),
    });
    return empty("signature invalid", {
      claimsHash,
      algorithm: resolved.algorithm || algorithm,
    });
  }

  return {
    valid: true,
    keyid,
    algorithm: resolved.algorithm || algorithm,
    contentHash: contentHashAttr,
    claimsHash,
    claims,
    signedAt,
    domain,
  };
}
