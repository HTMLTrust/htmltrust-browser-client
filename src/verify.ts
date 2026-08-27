/**
 * Layer 1: Cryptographic verification of a <signed-section>.
 *
 * This module keeps the browser-client aligned with the current HTMLTrust
 * drafts while continuing to use @htmltrust/canonicalization for shared text
 * normalization, key resolution, and signature verification primitives.
 */

import {
  extractCanonicalText,
  isKeyRevoked,
  resolveKey,
  verifySignature,
} from "@htmltrust/canonicalization";
import type { KeyResolver } from "@htmltrust/canonicalization";
import {
  SIGNED_SEMANTIC_ATTRIBUTES,
  bytesToUnpaddedBase64,
  canonicalizeClaimEntries,
  claimsToRecord,
  currentSerializedOrigin,
  isCanonicalBase64,
  normalizeClaimText,
  parseHash,
  serializeOrigin,
} from "./spec.js";
import type {
  ClaimEntry,
  VerificationFailureReason,
  VerificationInputState,
} from "./spec.js";

export interface VerifyOptions {
  /** Resolver chain used to map keyid -> public key. Required. */
  keyResolvers: KeyResolver[];
  /**
   * Serialized Web origin bound to the signature. The legacy field name is
   * retained for compatibility, but callers must pass an origin such as
   * "https://example.org", not a host-only domain.
   */
  domain?: string;
  /** Preferred spelling for new callers; equivalent to `domain`. */
  origin?: string;
  /** Base URL used to canonicalize signed href/src attribute values. */
  baseUrl?: string;
  /**
   * Optional rendered/live section to compare with a source snapshot string.
   * When supplied, `inputState` is "rendered-match" or "stale".
   */
  renderedSection?: Element | string;
  /**
   * Optional override for SHA-256. Receives a UTF-8 string, returns the
   * digest as canonical unpadded standard Base64 (not base64url).
   */
  hash?: (canonical: string) => Promise<string>;
  /**
   * When true, write a console.warn diagnostic each time verification fails.
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
  /**
   * Legacy field name retained for API compatibility. Value is a serialized
   * Web origin, matching window.location.origin semantics.
   */
  domain: string;
  /** Same value as `domain`, exposed with the current spec terminology. */
  origin: string;
  inputState: VerificationInputState;
  /** Populated when valid === false. */
  reason?: VerificationFailureReason;
}

type ParsedSection = {
  signature: string;
  keyid: string;
  contentHashAttr: string;
  algorithm: string;
  signedAt: string;
  claims: Record<string, string>;
  claimEntries: ClaimEntry[];
  innerHTML: string;
  parseFailure?: VerificationFailureReason;
};

const SIGNED_SECTION_RE =
  /<signed-section\b([^>]*)>([\s\S]*?)<\/signed-section\s*>/i;
const SIGNED_SECTION_RE_GLOBAL =
  /<signed-section\b([^>]*)>([\s\S]*?)<\/signed-section\s*>/gi;
const ATTR_RE = /([a-z_:][a-z0-9_:.-]*)\s*=\s*"([^"]*)"|([a-z_:][a-z0-9_:.-]*)\s*=\s*'([^']*)'/gi;
const TAG_RE = /<\/?([a-z][a-z0-9-]*)\b([^>]*)>/gi;
const VOID_ELEMENTS = new Set([
  "area",
  "base",
  "br",
  "col",
  "embed",
  "hr",
  "img",
  "input",
  "link",
  "meta",
  "param",
  "source",
  "track",
  "wbr",
]);
const EXCLUDED_ELEMENTS = new Set(["script", "style", "template", "noscript", "iframe", "meta"]);
// Spec §7.1 signature algorithm registry, plus the two legacy generic
// spellings ("ecdsa", "rsa") earlier releases of this library emitted. An
// algorithm outside this set is an "algorithm-not-supported" failure, never a
// generic one (spec §7.1).
const SUPPORTED_ALGORITHMS = new Set([
  "ed25519",
  "ecdsa",
  "ecdsa-p256",
  "ecdsa-p384",
  "rsa",
  "rsa-pss-sha256",
  "rsa-pkcs1-sha256",
]);
// The generic spellings name a family and leave the parameter set to the key,
// so they are compatible with any registry identifier in the same family.
const GENERIC_ALGORITHMS = new Set(["ecdsa", "rsa"]);

async function defaultHash(canonical: string): Promise<string> {
  const subtle = (globalThis as { crypto?: { subtle?: SubtleCrypto } }).crypto?.subtle;
  if (!subtle) {
    throw new Error(
      "verifySignedSection: SubtleCrypto is unavailable; provide options.hash or run in a secure context",
    );
  }
  const buf = await subtle.digest("SHA-256", new TextEncoder().encode(canonical));
  return bytesToUnpaddedBase64(new Uint8Array(buf));
}

export function extractSignedSections(html: string): string[] {
  if (typeof html !== "string") {
    throw new TypeError("extractSignedSections expects a string");
  }
  const out: string[] = [];
  SIGNED_SECTION_RE_GLOBAL.lastIndex = 0;
  let m: RegExpExecArray | null;
  while ((m = SIGNED_SECTION_RE_GLOBAL.exec(html))) out.push(m[0]);
  return out;
}

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

function directMetaAttrsFromString(inner: string): Array<Record<string, string>> {
  const out: Array<Record<string, string>> = [];
  TAG_RE.lastIndex = 0;
  let depth = 0;
  let m: RegExpExecArray | null;
  while ((m = TAG_RE.exec(inner))) {
    const raw = m[0];
    const name = m[1].toLowerCase();
    const closing = raw.startsWith("</");
    if (closing) {
      if (!VOID_ELEMENTS.has(name)) depth = Math.max(0, depth - 1);
      continue;
    }
    if (depth === 0 && name === "meta") out.push(parseAttrs(m[2]));
    const selfClosing = raw.endsWith("/>") || VOID_ELEMENTS.has(name);
    if (!selfClosing) depth += 1;
  }
  return out;
}

function normalizeClaimEntries(rawEntries: Array<Record<string, string | undefined>>): {
  entries: ClaimEntry[];
  failure?: VerificationFailureReason;
} {
  const entries: ClaimEntry[] = [];
  const seen = new Set<string>();
  for (const raw of rawEntries) {
    if (raw.name === undefined || raw.content === undefined) return { entries, failure: "claim-malformed" };
    const name = normalizeClaimText(raw.name);
    const content = normalizeClaimText(raw.content);
    if (!name) return { entries, failure: "claim-malformed" };
    if (seen.has(name)) return { entries, failure: "claim-duplicate" };
    seen.add(name);
    entries.push({ name, content });
  }
  return { entries };
}

function parseSection(input: Element | string): ParsedSection | null {
  if (typeof input === "string") return parseSectionFromString(input);

  const signature = input.getAttribute("signature") ?? "";
  const keyid = input.getAttribute("keyid") ?? "";
  const contentHashAttr = input.getAttribute("content-hash") ?? "";
  const algorithm = (input.getAttribute("algorithm") ?? "").toLowerCase();
  const rawMetas = Array.from(input.children)
    .filter((child) => child.localName.toLowerCase() === "meta")
    .map((meta) => ({
      name: meta.hasAttribute("name") ? meta.getAttribute("name") ?? "" : undefined,
      content: meta.hasAttribute("content") ? meta.getAttribute("content") ?? "" : undefined,
    }));
  const normalized = normalizeClaimEntries(rawMetas);
  const signedAt = normalized.entries.find((entry) => entry.name === "signed-at")?.content ?? "";

  return {
    signature,
    keyid,
    contentHashAttr,
    algorithm,
    signedAt,
    claimEntries: normalized.entries,
    claims: claimsToRecord(normalized.entries),
    innerHTML: input.innerHTML,
    parseFailure: normalized.failure,
  };
}

function parseSectionFromString(html: string): ParsedSection | null {
  const m = SIGNED_SECTION_RE.exec(html);
  if (!m) return null;
  const attrs = parseAttrs(m[1]);
  const inner = m[2];
  const normalized = normalizeClaimEntries(directMetaAttrsFromString(inner));
  const signedAt = normalized.entries.find((entry) => entry.name === "signed-at")?.content ?? "";
  return {
    signature: attrs.signature ?? "",
    keyid: attrs.keyid ?? "",
    contentHashAttr: attrs["content-hash"] ?? "",
    algorithm: (attrs.algorithm ?? "").toLowerCase(),
    signedAt,
    claimEntries: normalized.entries,
    claims: claimsToRecord(normalized.entries),
    innerHTML: inner,
    parseFailure: normalized.failure,
  };
}

function resolvedOrigin(options: VerifyOptions): string {
  const explicit = options.origin ?? options.domain;
  if (explicit) return serializeOrigin(explicit);
  return currentSerializedOrigin();
}

function normalizeUrlAttribute(value: string, baseUrl: string | undefined): string | null {
  try {
    const url = new URL(value, baseUrl);
    const serialized = url.href;
    return serialized.includes("\n") ? null : serialized;
  } catch {
    return null;
  }
}

function semanticAttributeRecords(innerHTML: string, baseUrl: string | undefined): string | null {
  const records: string[] = [];
  TAG_RE.lastIndex = 0;
  let m: RegExpExecArray | null;
  while ((m = TAG_RE.exec(innerHTML))) {
    const raw = m[0];
    if (raw.startsWith("</")) continue;
    const elementName = m[1].toLowerCase();
    if (EXCLUDED_ELEMENTS.has(elementName)) continue;
    const attrs = parseAttrs(m[2]);
    for (const attr of SIGNED_SEMANTIC_ATTRIBUTES) {
      if (!(attr in attrs)) continue;
      const value =
        attr === "href" || attr === "src"
          ? normalizeUrlAttribute(attrs[attr], baseUrl)
          : normalizeClaimText(attrs[attr]);
      if (value === null || value.includes("\n")) return null;
      records.push(`@attr:${elementName}:${attr}:${value}\n`);
    }
  }
  return records.join("");
}

export function canonicalizeSignedContent(innerHTML: string, baseUrl?: string): string {
  const attrRecords = semanticAttributeRecords(innerHTML, baseUrl);
  if (attrRecords === null) throw new Error("attribute-canonicalization-failed");
  // The installed canonicalization implementation already emits the signed
  // semantic attribute records. Passing baseUrl keeps href/src deterministic.
  void attrRecords;
  return extractCanonicalText(innerHTML, { baseUrl } as Parameters<typeof extractCanonicalText>[1] & { baseUrl?: string });
}

function snapshotMatches(source: ParsedSection, rendered: ParsedSection, baseUrl: string | undefined): boolean {
  if (
    source.signature !== rendered.signature ||
    source.keyid !== rendered.keyid ||
    source.contentHashAttr !== rendered.contentHashAttr ||
    source.algorithm !== rendered.algorithm ||
    source.signedAt !== rendered.signedAt
  ) {
    return false;
  }
  if (source.parseFailure || rendered.parseFailure) return false;
  if (canonicalizeClaimEntries(source.claimEntries) !== canonicalizeClaimEntries(rendered.claimEntries)) return false;
  try {
    return (
      canonicalizeSignedContent(source.innerHTML, baseUrl) ===
      canonicalizeSignedContent(rendered.innerHTML, baseUrl)
    );
  } catch {
    return false;
  }
}

function inferInputState(
  section: Element | string,
  parsed: ParsedSection | null,
  options: VerifyOptions,
): VerificationInputState {
  if (typeof section !== "string") return "rendered-match";
  if (!options.renderedSection || !parsed) return "source-only";
  const rendered = parseSection(options.renderedSection);
  return rendered && snapshotMatches(parsed, rendered, options.baseUrl ?? options.origin ?? options.domain)
    ? "rendered-match"
    : "stale";
}

function algorithmFamily(value: string): string {
  if (value.startsWith("ecdsa")) return "ecdsa";
  if (value.startsWith("rsa")) return "rsa";
  return value;
}

/**
 * Decide whether the algorithm advertised by the resolved key can be used for
 * the algorithm declared on the signed section (spec §11 step 5).
 *
 * Exact matches always pass. A generic family spelling on either side matches
 * any identifier in that family, because it carries no parameter set to
 * conflict with. RSA key material is padding-agnostic, so PKCS#1 v1.5 and PSS
 * are interchangeable for the same key. Two different pinned ECDSA curves are
 * a mismatch.
 */
function algorithmsCompatible(resolved: string, declared: string): boolean {
  if (resolved === declared) return true;
  const resolvedFamily = algorithmFamily(resolved);
  const declaredFamily = algorithmFamily(declared);
  if (resolvedFamily !== declaredFamily) return false;
  if (GENERIC_ALGORITHMS.has(resolved) || GENERIC_ALGORITHMS.has(declared)) return true;
  return resolvedFamily === "rsa";
}

export async function verifySignedSection(
  section: Element | string,
  options: VerifyOptions,
): Promise<VerifyResult> {
  const parsed = parseSection(section);
  const origin = resolvedOrigin(options);
  const baseUrl = options.baseUrl ?? origin;
  const inputState = inferInputState(section, parsed, options);
  const hashFn = options.hash ?? defaultHash;

  const empty = (
    reason: VerificationFailureReason,
    partial?: Partial<VerifyResult>,
  ): VerifyResult => ({
    valid: false,
    keyid: parsed?.keyid ?? "",
    algorithm: parsed?.algorithm ?? "",
    contentHash: parsed?.contentHashAttr ?? "",
    claimsHash: "",
    claims: parsed?.claims ?? {},
    signedAt: parsed?.signedAt ?? "",
    domain: origin,
    origin,
    inputState,
    reason,
    ...partial,
  });

  const debug = options.debug === true;
  const warn = (reason: VerificationFailureReason, details: Record<string, unknown>) => {
    if (debug) console.warn("[htmltrust] verify failed:", reason, details);
  };

  if (!parsed) {
    warn("incomplete", { input: typeof section === "string" ? section.slice(0, 200) : "(Element)" });
    return empty("incomplete");
  }

  const { signature, keyid, contentHashAttr, algorithm, signedAt, claims, claimEntries, innerHTML } = parsed;
  if (!signature || !keyid || !contentHashAttr || !algorithm) {
    warn("incomplete", { signature: !!signature, keyid, contentHashAttr, algorithm });
    return empty("incomplete");
  }
  if (!SUPPORTED_ALGORITHMS.has(algorithm)) {
    warn("algorithm-not-supported", { algorithm });
    return empty("algorithm-not-supported");
  }
  if (parsed.parseFailure) {
    warn(parsed.parseFailure, { claims });
    return empty(parsed.parseFailure);
  }
  if (!signedAt) {
    warn("claim-missing", { claim: "signed-at" });
    return empty("claim-missing");
  }
  if (!parseHash(contentHashAttr)) {
    warn("content-hash-mismatch", { contentHashAttr });
    return empty("content-hash-mismatch");
  }
  if (!isCanonicalBase64(signature)) {
    warn("signature-malformed", { signatureLength: signature.length });
    return empty("signature-malformed");
  }

  let canonicalContent: string;
  try {
    canonicalContent = canonicalizeSignedContent(innerHTML, baseUrl);
  } catch {
    warn("attribute-canonicalization-failed", { baseUrl });
    return empty("attribute-canonicalization-failed");
  }
  const computedDigest = await hashFn(canonicalContent);
  if (!isCanonicalBase64(computedDigest)) {
    warn("content-hash-mismatch", { computedDigest });
    return empty("content-hash-mismatch");
  }
  const computedContentHash = `sha256:${computedDigest}`;
  if (computedContentHash !== contentHashAttr) {
    warn("content-hash-mismatch", {
      embeddedContentHash: contentHashAttr,
      computedContentHash,
      canonicalTextLength: canonicalContent.length,
      canonicalTextHead: canonicalContent.slice(0, 200),
    });
    return empty("content-hash-mismatch");
  }

  const claimsCanonical = canonicalizeClaimEntries(claimEntries);
  const claimsHash = `sha256:${await hashFn(claimsCanonical)}`;

  let resolved = null;
  let resolverError: unknown = null;
  try {
    resolved = await resolveKey(keyid, options.keyResolvers);
  } catch (e) {
    resolverError = e;
  }
  if (!resolved) {
    warn("key-resolution-failed", {
      keyid,
      resolverError: resolverError instanceof Error ? resolverError.message : resolverError,
    });
    return empty("key-resolution-failed", { claimsHash });
  }

  // Spec §8.2: a revoked key, or one whose `expires` has passed, is a
  // "key-revoked" failure and MUST NOT reach signature verification. This is
  // checked before the algorithm comparison so a revoked key cannot be
  // reported as some milder failure.
  if (isKeyRevoked(resolved)) {
    warn("key-revoked", { keyid, revoked: resolved.revoked, expires: resolved.expires });
    return empty("key-revoked", { claimsHash });
  }

  const resolvedAlgorithm = (resolved.algorithm || algorithm).toLowerCase();
  if (!algorithmsCompatible(resolvedAlgorithm, algorithm)) {
    warn("algorithm-mismatch", { resolvedAlgorithm, algorithm });
    return empty("algorithm-mismatch", { claimsHash, algorithm: resolvedAlgorithm });
  }

  const binding = `${contentHashAttr}:${claimsHash}:${origin}:${signedAt}`;
  // Pass the declared identifier through verbatim so the verifier pins the
  // curve and hash the section committed to, rather than a coerced default.
  const sigOk = await verifySignature(
    binding,
    signature,
    resolved.publicKeyPem,
    algorithm,
  );
  if (!sigOk) {
    warn("signature-invalid", {
      binding,
      signature,
      keyid,
      algorithm,
      publicKeyPemHead: resolved.publicKeyPem.slice(0, 80),
    });
    return empty("signature-invalid", {
      claimsHash,
      algorithm,
    });
  }

  return {
    valid: true,
    keyid,
    algorithm,
    contentHash: contentHashAttr,
    claimsHash,
    claims,
    signedAt,
    domain: origin,
    origin,
    inputState,
  };
}
