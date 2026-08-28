/**
 * Layer 1: Cryptographic verification of a <signed-section>.
 *
 * This module keeps the browser-client aligned with the current HTMLTrust
 * drafts while continuing to use @htmltrust/canonicalization for shared text
 * normalization, key resolution, and signature verification primitives.
 */

import {
  buildSigningPayloadV1,
  canonicalizeClaims,
  decodeCanonicalBase64,
  extractCanonicalText,
  extractClaimsFromSignedSection,
  isKeyRevoked,
  resolveKey,
  validateSignedAtV1,
  verifySignature,
} from "@htmltrust/canonicalization";
import type { KeyResolver } from "@htmltrust/canonicalization";
import * as parse5 from "parse5";
import {
  bytesToUnpaddedBase64,
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
  /** Base URL of the current rendered document when comparing a source. */
  renderedBaseUrl?: string;
  /** Final response URL of the signed document, used for the v1 location. */
  documentUrl?: string;
  /**
   * Optional rendered/live section to compare with a source snapshot.
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
  profile: string;
  signatureScope: string;
  signature: string;
  keyid: string;
  contentHashAttr: string;
  algorithm: string;
  signedAt: string;
  claims: Record<string, string>;
  claimEntries: ClaimEntry[];
  innerHTML: string;
  /** Complete source slice, retained so the canonicalizer can preflight the opening tag. */
  sourceHTML: string;
  parseFailure?: VerificationFailureReason;
};

const SIGNED_SECTION_RE =
  /<signed-section\b([^>]*)>([\s\S]*?)<\/signed-section\s*>/i;
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
// Spec §7.1 signature algorithm registry. Legacy generic spellings are not
// part of the frozen v1 profile and must not be accepted as a fallback.
const SUPPORTED_ALGORITHMS = new Set([
  "ed25519",
  "ecdsa-p256",
  "ecdsa-p384",
  "rsa-pss-sha256",
  "rsa-pkcs1-sha256",
]);

/** Parse source HTML with the browser's HTML parser when available. */
export function parseSignedSectionElements(html: string): Element[] {
  if (typeof html !== "string") throw new TypeError("parseSignedSectionElements expects a string");
  const Parser = (globalThis as { DOMParser?: typeof DOMParser }).DOMParser;
  if (!Parser) throw new Error("parser-profile-unsupported");
  const document = new Parser().parseFromString(html, "text/html");
  return Array.from(document.querySelectorAll("signed-section"));
}

function tagEnd(source: string, start: number): number {
  let quote = "";
  for (let i = start + 1; i < source.length; i++) {
    const char = source[i];
    if (quote) {
      if (char === quote) quote = "";
    } else if (char === "\"" || char === "'") {
      quote = char;
    } else if (char === ">") {
      return i + 1;
    }
  }
  return -1;
}

/**
 * Extract balanced signed-section source slices for non-DOM environments.
 * This is deliberately a strict lexical fallback for the Node-compatible
 * helper; browser verification uses parseSignedSectionElements instead.
 */
function extractBalancedSignedSections(html: string): string[] {
  const found: Array<{ start: number; end: number }> = [];
  const openSections: number[] = [];
  let scan = 0;
  let rawName: string | null = null;
  while (scan < html.length) {
    const tagStart = html.indexOf("<", scan);
    if (tagStart < 0) break;
    if (rawName) {
      const close = new RegExp(`^<\\/\\s*${rawName}\\b`, "i").test(html.slice(tagStart));
      if (!close) {
        scan = tagStart + 1;
        continue;
      }
    }
    if (html.startsWith("<!--", tagStart)) {
      const commentEnd = html.indexOf("-->", tagStart + 4);
      if (commentEnd < 0) break;
      scan = commentEnd + 3;
      continue;
    }
    const end = tagEnd(html, tagStart);
    if (end < 0) break;
    const token = html.slice(tagStart, end);
    if (/^<!--/.test(token) || /^<!/.test(token)) {
      scan = end;
      continue;
    }
    const nameMatch = /^<\/\s*([a-z][a-z0-9-]*)|^<\s*([a-z][a-z0-9-]*)/i.exec(token);
    if (!nameMatch) {
      scan = end;
      continue;
    }
    const name = (nameMatch[1] ?? nameMatch[2]).toLowerCase();
    const closing = /^<\//.test(token);
    if (rawName) {
      rawName = null;
    } else if (closing && name === "signed-section") {
      const start = openSections.pop();
      if (start !== undefined) found.push({ start, end });
    } else if (!closing && name === "signed-section" && !/\/\s*>$/.test(token)) {
      openSections.push(tagStart);
    } else if (!closing && ["script", "style", "textarea", "title", "iframe"].includes(name) && !/\/\s*>$/.test(token)) {
      rawName = name;
    }
    scan = end;
  }
  return found
    .sort((a, b) => a.start - b.start)
    .map(({ start, end }) => html.slice(start, end));
}

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
  // Preserve the exact source slice. DOM outerHTML is a serialization of the
  // repaired tree and discards diagnostics such as duplicate attributes.
  return extractBalancedSignedSections(html);
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
    const name = normalizeClaimText(raw.name).trim();
    const content = normalizeClaimText(raw.content).trim();
    if (!name) return { entries, failure: "claim-malformed" };
    if (seen.has(name)) return { entries, failure: "claim-duplicate" };
    seen.add(name);
    entries.push({ name, content });
  }
  return { entries };
}

function parseSectionElement(input: Element): ParsedSection {
  const profile = input.getAttribute("profile") ?? "";
  const signatureScope = input.getAttribute("signature-scope") ?? "";
  const signature = input.getAttribute("signature") ?? "";
  const keyid = input.getAttribute("keyid") ?? "";
  const contentHashAttr = input.getAttribute("content-hash") ?? "";
  const algorithm = input.getAttribute("algorithm") ?? "";
  const rawMetas = Array.from(input.children)
    .filter((child) => child.localName.toLowerCase() === "meta")
    .map((meta) => ({
      name: meta.hasAttribute("name") ? meta.getAttribute("name") ?? "" : undefined,
      content: meta.hasAttribute("content") ? meta.getAttribute("content") ?? "" : undefined,
    }));
  const normalized = normalizeClaimEntries(rawMetas);
  const signedAt = normalized.entries.find((entry) => entry.name === "signed-at")?.content ?? "";

  return {
    profile,
    signatureScope,
    signature,
    keyid,
    contentHashAttr,
    algorithm,
    signedAt,
    claimEntries: normalized.entries,
    claims: claimsToRecord(normalized.entries),
    innerHTML: input.innerHTML,
    sourceHTML: input.outerHTML,
    parseFailure: normalized.failure,
  };
}

function parseSection(input: Element | string): ParsedSection | null {
  if (typeof input !== "string") return parseSectionElement(input);
  const source = extractBalancedSignedSections(input)[0];
  if (!source) return parseSectionFromString(input);
  // Browser callers still use HTML5 tree construction for attribute values
  // and direct-child mapping, while retaining the exact source slice for the
  // portable-profile preflight.
  const Parser = (globalThis as { DOMParser?: typeof DOMParser }).DOMParser;
  if (Parser) {
    const elements = parseSignedSectionElements(source);
    if (elements[0]) return { ...parseSectionElement(elements[0]), sourceHTML: source };
  }
  return parseSectionFromString(source);
}

function parseSectionFromString(html: string): ParsedSection | null {
  const source = extractBalancedSignedSections(html)[0];
  if (!source) {
    const m = SIGNED_SECTION_RE.exec(html);
    if (!m) return null;
    return parseSectionParts(m[1], m[2], m[0]);
  }
  const openEnd = tagEnd(source, 0);
  const closeStart = source.toLowerCase().lastIndexOf("</signed-section");
  if (openEnd < 0 || closeStart < openEnd) return null;
  // Use the same HTML tokenizer for Node and browser callers. The lexical
  // source slice remains authoritative for preflight and canonicalization,
  // while parse5 supplies HTML's unquoted-attribute and character-reference
  // rules for protocol attributes.
  const parsedAttrs = parseSectionAttributesWithParser(source);
  const attrs = parsedAttrs ?? parseAttrs(source.slice("<signed-section".length, openEnd - 1));
  const inner = source.slice(openEnd, closeStart);
  return parseSectionParts(attrs, inner, source);
}

function parseSectionAttributesWithParser(source: string): Record<string, string> | null {
  try {
    const fragment = parse5.parseFragment(source) as unknown as { childNodes?: Array<Record<string, unknown>> };
    const find = (nodes: Array<Record<string, unknown>>): Record<string, unknown> | null => {
      for (const node of nodes) {
        if (String(node.tagName ?? "").toLowerCase() === "signed-section") return node;
        const children = node.childNodes;
        if (Array.isArray(children)) {
          const nested = find(children as Array<Record<string, unknown>>);
          if (nested) return nested;
        }
      }
      return null;
    };
    const section = find(fragment.childNodes ?? []);
    if (!section) return null;
    const attrs: Record<string, string> = {};
    for (const attr of (section.attrs as Array<{ name?: string; value?: string }> | undefined) ?? []) {
      if (attr.name) attrs[attr.name.toLowerCase()] = attr.value ?? "";
    }
    return attrs;
  } catch {
    return null;
  }
}

function parseSectionParts(
  attrsOrSource: Record<string, string> | string,
  inner: string,
  sourceHTML: string,
): ParsedSection {
  const attrs = typeof attrsOrSource === "string" ? parseAttrs(attrsOrSource) : attrsOrSource;
  const normalized = normalizeClaimEntries(directMetaAttrsFromString(inner));
  const signedAt = normalized.entries.find((entry) => entry.name === "signed-at")?.content ?? "";
  return {
    profile: attrs.profile ?? "",
    signatureScope: attrs["signature-scope"] ?? "",
    signature: attrs.signature ?? "",
    keyid: attrs.keyid ?? "",
    contentHashAttr: attrs["content-hash"] ?? "",
    algorithm: attrs.algorithm ?? "",
    signedAt,
    claimEntries: normalized.entries,
    claims: claimsToRecord(normalized.entries),
    innerHTML: inner,
    sourceHTML,
    parseFailure: normalized.failure,
  };
}

function documentUrl(options: VerifyOptions): string {
  if (options.documentUrl) return options.documentUrl;
  const href = (globalThis as { location?: Location }).location?.href;
  if (href) return href;
  // Keep the old origin option usable as a source-only fallback. New callers
  // should always provide the final response URL explicitly.
  return options.origin ?? options.domain ?? "";
}

function resolvedOrigin(options: VerifyOptions, url = documentUrl(options)): string {
  try {
    if (url) return serializeOrigin(url);
  } catch {
    // The verifier reports origin-not-supported after the content and claims
    // stages, rather than throwing while constructing a failure result.
  }
  const explicit = options.origin ?? options.domain;
  try {
    if (explicit) return serializeOrigin(explicit);
  } catch {
    // Keep failure results total even for malformed caller context.
  }
  return currentSerializedOrigin();
}

export function canonicalizeSignedContent(innerHTML: string, baseUrl?: string): string {
  // v0.3 owns the frozen safe-URL and parser profile. In particular, it checks
  // C0 controls before URL() can silently remove them and distinguishes policy
  // violations from malformed URLs.
  return extractCanonicalText(innerHTML, { baseUrl });
}

function snapshotMatches(
  source: ParsedSection,
  rendered: ParsedSection,
  sourceBaseUrl: string | undefined,
  renderedBaseUrl: string | undefined,
): boolean {
  if (
    source.profile !== rendered.profile ||
    source.signatureScope !== rendered.signatureScope ||
    source.signature !== rendered.signature ||
    source.keyid !== rendered.keyid ||
    source.contentHashAttr !== rendered.contentHashAttr ||
    source.algorithm !== rendered.algorithm ||
    source.signedAt !== rendered.signedAt
  ) {
    return false;
  }
  if (source.parseFailure || rendered.parseFailure) return false;
  try {
    if (canonicalizeClaims(source.claims) !== canonicalizeClaims(rendered.claims)) return false;
  } catch {
    return false;
  }
  try {
    return (
      canonicalizeSignedContent(source.innerHTML, sourceBaseUrl) ===
      canonicalizeSignedContent(rendered.innerHTML, renderedBaseUrl)
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
  if (!options.renderedSection || !parsed) {
    return typeof section === "string" ? "source-only" : "rendered-match";
  }
  const rendered = parseSection(options.renderedSection);
  return rendered && snapshotMatches(
    parsed,
    rendered,
    options.baseUrl ?? documentUrl(options),
    options.renderedBaseUrl ?? options.baseUrl ?? documentUrl(options),
  )
    ? "rendered-match"
    : "stale";
}

function protocolAttributeHasEdgeWhitespace(value: string): boolean {
  return /^[\u0009-\u000D\u0020]|[\u0009-\u000D\u0020]$/u.test(value);
}

function canonicalizationFailure(error: unknown): VerificationFailureReason {
  const message = error instanceof Error ? error.message : String(error);
  if (message.startsWith("url-policy-violation")) return "url-policy-violation";
  if (message.startsWith("parser-profile-unsupported")) return "parser-profile-unsupported";
  if (message.startsWith("resource-limit-exceeded")) return "resource-limit-exceeded";
  if (message.startsWith("claim-malformed")) return "claim-malformed";
  if (message.startsWith("claim-duplicate")) return "claim-duplicate";
  return "attribute-canonicalization-failed";
}

function resolverFailure(error: unknown): VerificationFailureReason {
  const message = error instanceof Error ? error.message : String(error ?? "");
  if (message.startsWith("network-policy-blocked")) return "network-policy-blocked";
  if (message.startsWith("resource-limit-exceeded")) return "resource-limit-exceeded";
  if (message.startsWith("malformed-key-document")) return "malformed-key-document";
  return "key-resolution-failed";
}

/**
 * Run the source-only portion of the canonicalization profile. The shared
 * claims parser performs the portable source preflight and resource checks
 * without walking signed text or resolving signed URLs. Claim-shape failures
 * are intentionally deferred to the claims step below.
 */
function preflightSignedSource(sourceHTML: string): void {
  try {
    extractClaimsFromSignedSection(sourceHTML);
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    if (message.startsWith("claim-malformed") || message.startsWith("claim-duplicate")) return;
    throw error;
  }
}

type DerValue = { contentStart: number; contentEnd: number; next: number };

function readDerValue(bytes: Uint8Array, offset: number, expectedTag: number): DerValue | null {
  if (offset + 2 > bytes.length || bytes[offset] !== expectedTag) return null;
  const firstLength = bytes[offset + 1];
  let length = firstLength;
  let contentStart = offset + 2;
  if ((firstLength & 0x80) !== 0) {
    const octets = firstLength & 0x7f;
    if (octets < 1 || octets > 4 || contentStart + octets > bytes.length) return null;
    length = 0;
    for (let i = 0; i < octets; i++) length = (length * 256) + bytes[contentStart + i];
    contentStart += octets;
  }
  const contentEnd = contentStart + length;
  if (contentEnd > bytes.length) return null;
  return { contentStart, contentEnd, next: contentEnd };
}

/** Return the RSA modulus width from an SPKI PEM key, or null for malformed input. */
function rsaModulusWidth(publicKeyPem: string): number | null {
  const match = /-----BEGIN PUBLIC KEY-----([A-Za-z0-9+/=\s]+)-----END PUBLIC KEY-----/u.exec(publicKeyPem);
  if (!match) return null;
  let bytes: Uint8Array;
  try {
    const binary = atob(match[1].replace(/\s+/gu, ""));
    bytes = Uint8Array.from(binary, (character) => character.charCodeAt(0));
  } catch {
    return null;
  }
  const spki = readDerValue(bytes, 0, 0x30);
  if (!spki || spki.next !== bytes.length) return null;
  const algorithm = readDerValue(bytes, spki.contentStart, 0x30);
  if (!algorithm) return null;
  const bitString = readDerValue(bytes, algorithm.next, 0x03);
  if (!bitString || bitString.next !== spki.contentEnd || bytes[bitString.contentStart] !== 0) return null;
  const rsaKey = readDerValue(bytes, bitString.contentStart + 1, 0x30);
  if (!rsaKey || rsaKey.next !== bitString.contentEnd) return null;
  const modulus = readDerValue(bytes, rsaKey.contentStart, 0x02);
  if (!modulus || modulus.contentStart === modulus.contentEnd) return null;
  const leadingSignByte = bytes[modulus.contentStart] === 0 ? 1 : 0;
  const width = modulus.contentEnd - modulus.contentStart - leadingSignByte;
  return width > 0 ? width : null;
}

export async function verifySignedSection(
  /**
   * Full v1 conformance requires a source string. An Element has already been
   * parsed and serialized by the caller, so source-level ambiguity checks such
   * (for example duplicate attributes) cannot be recovered from it.
   */
  section: Element | string,
  options: VerifyOptions,
): Promise<VerifyResult> {
  const parsed = parseSection(section);
  const finalDocumentUrl = documentUrl(options);
  const origin = resolvedOrigin(options, finalDocumentUrl);
  // The HTML base URL controls relative href/src canonicalization. The final
  // response URL controls only the v1 signed location and may differ when a
  // document contains a <base> element or was reached through redirects.
  const baseUrl = (options.baseUrl ?? finalDocumentUrl) || undefined;
  const inputState = inferInputState(section, parsed, options);
  const hashFn = options.hash ?? defaultHash;
  let resultClaims = parsed?.claims ?? {};
  let resultSignedAt = parsed?.signedAt ?? "";

  const empty = (
    reason: VerificationFailureReason,
    partial?: Partial<VerifyResult>,
  ): VerifyResult => ({
    valid: false,
    keyid: parsed?.keyid ?? "",
    algorithm: parsed?.algorithm ?? "",
    contentHash: parsed?.contentHashAttr ?? "",
    claimsHash: "",
    claims: resultClaims,
    signedAt: resultSignedAt,
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

  // Source preflight and resource ceilings are the only canonicalization work
  // permitted before protocol-attribute validation. Content extraction and URL
  // handling happen only after the exact v1 profile and encodings are selected.
  try {
    preflightSignedSource(parsed.sourceHTML);
  } catch (error) {
    const reason = canonicalizationFailure(error);
    warn(reason, { baseUrl });
    return empty(reason);
  }

  const { profile, signatureScope, signature, keyid, contentHashAttr, algorithm, sourceHTML } = parsed;
  const protocolAttributes = { profile, "signature-scope": signatureScope, keyid, signature, "content-hash": contentHashAttr, algorithm };
  if (Object.values(protocolAttributes).some((value) => !value || protocolAttributeHasEdgeWhitespace(value))) {
    warn("incomplete", { attributes: Object.fromEntries(Object.entries(protocolAttributes).map(([name, value]) => [name, value !== ""])) });
    return empty("incomplete");
  }
  if (profile !== "htmltrust-signature-v1") {
    warn("profile-unsupported", { profile });
    return empty("profile-unsupported");
  }
  if (signatureScope !== "url" && signatureScope !== "origin") {
    warn("scope-unsupported", { signatureScope });
    return empty("scope-unsupported");
  }
  const parsedHash = parseHash(contentHashAttr);
  if (!parsedHash) {
    warn("invalid-encoding", { contentHashAttr });
    return empty("invalid-encoding");
  }
  if (!isCanonicalBase64(signature)) {
    warn("invalid-encoding", { signatureLength: signature.length });
    return empty("invalid-encoding");
  }
  if (parsedHash.algorithm !== "sha256" || !SUPPORTED_ALGORITHMS.has(algorithm)) {
    warn("algorithm-not-supported", { hashAlgorithm: parsedHash.algorithm, algorithm });
    return empty("algorithm-not-supported");
  }
  const signatureBytes = decodeCanonicalBase64(signature);
  const expectedSignatureLength = algorithm === "ed25519"
    ? 64
    : algorithm === "ecdsa-p256"
      ? 64
      : algorithm === "ecdsa-p384"
        ? 96
        : null;
  if (expectedSignatureLength !== null && signatureBytes.byteLength !== expectedSignatureLength) {
    warn("malformed-signature", { algorithm, signatureLength: signatureBytes.byteLength });
    return empty("malformed-signature");
  }

  let canonicalContent: string;
  try {
    canonicalContent = canonicalizeSignedContent(parsed.sourceHTML, baseUrl);
  } catch (error) {
    const reason = canonicalizationFailure(error);
    warn(reason, { baseUrl });
    return empty(reason);
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

  let claims: Record<string, string>;
  try {
    claims = extractClaimsFromSignedSection(sourceHTML);
    resultClaims = claims;
  } catch (error) {
    const reason = canonicalizationFailure(error);
    warn(reason, {});
    return empty(reason);
  }
  const signedAt = claims["signed-at"] ?? "";
  resultSignedAt = signedAt;
  if (!signedAt) {
    warn("claim-missing", { claim: "signed-at" });
    return empty("claim-missing");
  }
  try {
    validateSignedAtV1(signedAt);
  } catch {
    warn("timestamp-invalid", { signedAt });
    return empty("timestamp-invalid");
  }

  let claimsCanonical: string;
  try {
    claimsCanonical = canonicalizeClaims(claims);
  } catch (error) {
    const reason = canonicalizationFailure(error);
    warn(reason, { claims });
    return empty(reason);
  }
  const claimsHash = `sha256:${await hashFn(claimsCanonical)}`;

  let signingPayload: string;
  try {
    signingPayload = buildSigningPayloadV1({
      contentHash: contentHashAttr,
      claimsHash,
      documentURL: finalDocumentUrl,
      scope: signatureScope,
      keyid,
      algorithm,
      signedAt,
    });
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    const reason: VerificationFailureReason = message.startsWith("scope-unsupported")
      ? "scope-unsupported"
      : message.startsWith("timestamp-invalid")
        ? "timestamp-invalid"
        : message.startsWith("resource-limit-exceeded")
          ? "resource-limit-exceeded"
          : "origin-not-supported";
    warn(reason, { documentUrl: finalDocumentUrl, signatureScope });
    return empty(reason, { claimsHash });
  }

  let resolved = null;
  let resolverError: unknown = null;
  try {
    resolved = await resolveKey(keyid, options.keyResolvers);
  } catch (e) {
    resolverError = e;
  }
  if (!resolved) {
    const reason = resolverFailure(resolverError);
    warn(reason, {
      keyid,
      resolverError: resolverError instanceof Error ? resolverError.message : resolverError,
    });
    return empty(reason, { claimsHash });
  }

  // Spec §8.2: a revoked key, or one whose `expires` has passed, is a
  // "key-revoked" failure and MUST NOT reach signature verification. This is
  // checked before the algorithm comparison so a revoked key cannot be
  // reported as some milder failure.
  if (isKeyRevoked(resolved)) {
    warn("key-revoked", { keyid, revoked: resolved.revoked, expires: resolved.expires });
    return empty("key-revoked", { claimsHash });
  }

  const resolvedAlgorithm = resolved.algorithm || "";
  if (resolvedAlgorithm !== algorithm) {
    warn("algorithm-mismatch", { resolvedAlgorithm, algorithm });
    return empty("algorithm-mismatch", { claimsHash, algorithm: resolvedAlgorithm });
  }

  if (algorithm.startsWith("rsa-")) {
    const modulusWidth = rsaModulusWidth(resolved.publicKeyPem);
    if (modulusWidth === null) {
      warn("malformed-key-document", { keyid });
      return empty("malformed-key-document", { claimsHash });
    }
    if (signatureBytes.byteLength !== modulusWidth) {
      warn("malformed-signature", { algorithm, signatureLength: signatureBytes.byteLength, modulusWidth });
      return empty("malformed-signature", { claimsHash });
    }
  }
  const sigOk = await verifySignature(
    signingPayload,
    signature,
    resolved.publicKeyPem,
    algorithm,
  );
  if (!sigOk) {
    warn("signature-invalid", {
      signingPayload,
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
