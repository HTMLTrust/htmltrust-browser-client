import { normalizeText } from "@htmltrust/canonicalization";

export const SIGNED_SEMANTIC_ATTRIBUTES = [
  "href",
  "src",
  "alt",
  "aria-label",
] as const;

export type VerificationFailureReason =
  | "incomplete"
  | "profile-unsupported"
  | "scope-unsupported"
  | "content-hash-mismatch"
  | "claim-malformed"
  | "claim-duplicate"
  | "claim-missing"
  | "timestamp-invalid"
  | "attribute-canonicalization-failed"
  | "parser-profile-unsupported"
  | "url-policy-violation"
  | "invalid-encoding"
  | "malformed-signature"
  | "key-resolution-failed"
  | "key-revoked"
  | "algorithm-mismatch"
  | "algorithm-not-supported"
  | "signature-invalid"
  | "malformed-key-document"
  | "origin-not-supported"
  | "resource-limit-exceeded"
  | "directory-unavailable"
  | "source-refetch-failed"
  | "network-policy-blocked";

export type VerificationInputState = "source-only" | "stale" | "rendered-match";

const BASE64_RE = /^[A-Za-z0-9+/]*$/;

export function bytesToUnpaddedBase64(bytes: Uint8Array): string {
  let bin = "";
  for (let i = 0; i < bytes.length; i++) bin += String.fromCharCode(bytes[i]);
  return btoa(bin).replace(/=+$/, "");
}

export function decodeCanonicalBase64(value: string): Uint8Array | null {
  if (!value || value.includes("=") || !BASE64_RE.test(value) || value.length % 4 === 1) {
    return null;
  }
  try {
    const padded = value + "=".repeat((4 - (value.length % 4)) % 4);
    const bin = atob(padded);
    const out = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
    return bytesToUnpaddedBase64(out) === value ? out : null;
  } catch {
    return null;
  }
}

export function isCanonicalBase64(value: string): boolean {
  return decodeCanonicalBase64(value) !== null;
}

export function parseHash(value: string): { algorithm: string; digest: string } | null {
  const i = value.indexOf(":");
  if (i <= 0) return null;
  const algorithm = value.slice(0, i);
  const digest = value.slice(i + 1);
  const outputLengths: Record<string, number> = {
    sha256: 32,
    sha384: 48,
    sha512: 64,
  };
  const outputLength = outputLengths[algorithm];
  if (!outputLength) return null;
  const bytes = decodeCanonicalBase64(digest);
  if (!bytes || bytes.byteLength !== outputLength) return null;
  return { algorithm, digest };
}

export function serializeOrigin(value: string): string {
  const url = new URL(value);
  return url.origin;
}

export function currentSerializedOrigin(): string {
  const loc = (globalThis as { location?: Location }).location;
  return loc?.origin ?? "";
}

export function normalizeClaimText(value: string): string {
  return normalizeText(value);
}

export interface ClaimEntry {
  name: string;
  content: string;
}

export function canonicalizeClaimEntries(entries: ClaimEntry[]): string {
  return [...entries]
    .sort((a, b) => {
      const aa = new TextEncoder().encode(a.name);
      const bb = new TextEncoder().encode(b.name);
      const len = Math.min(aa.length, bb.length);
      for (let i = 0; i < len; i++) {
        if (aa[i] !== bb[i]) return aa[i] - bb[i];
      }
      return aa.length - bb.length;
    })
    .map((entry) => `${entry.name}:${entry.content}\n`)
    .join("");
}

export function claimsToRecord(entries: ClaimEntry[]): Record<string, string> {
  const out: Record<string, string> = {};
  for (const entry of entries) out[entry.name] = entry.content;
  return out;
}

export function canonicalJson(value: unknown): string {
  if (value === null || typeof value === "string" || typeof value === "boolean") {
    return JSON.stringify(value);
  }
  if (typeof value === "number") {
    if (!Number.isFinite(value)) throw new TypeError("canonicalJson: non-finite number");
    return JSON.stringify(value);
  }
  if (Array.isArray(value)) {
    return `[${value.map((item) => canonicalJson(item)).join(",")}]`;
  }
  if (value && typeof value === "object") {
    const obj = value as Record<string, unknown>;
    const keys = Object.keys(obj)
      .filter((key) => obj[key] !== undefined)
      .sort();
    return `{${keys.map((key) => `${JSON.stringify(key)}:${canonicalJson(obj[key])}`).join(",")}}`;
  }
  throw new TypeError(`canonicalJson: unsupported value ${typeof value}`);
}

export interface VerificationFetchOptions {
  fetch?: typeof fetch;
  allowInsecureHttpForTesting?: boolean;
  sameOriginSourceRefetch?: boolean;
  origin?: string;
}

/** Strip the brackets an IPv6 literal carries in URL.hostname. */
function unbracket(hostname: string): string {
  return hostname.startsWith("[") && hostname.endsWith("]")
    ? hostname.slice(1, -1)
    : hostname;
}

/**
 * A trailing-dot FQDN (`localhost.`, the DNS root-relative form) is
 * preserved verbatim by URL parsing rather than normalized away, so
 * `"localhost."` and `"localhost"` are different strings by the time they
 * reach here even though they name the identical host. Strip at most one
 * trailing dot before matching so both spellings are caught alike.
 */
function stripTrailingDot(host: string): string {
  return host.endsWith(".") ? host.slice(0, -1) : host;
}

function parseIPv4(host: string): number[] | null {
  const parts = host.split(".");
  if (parts.length !== 4) return null;
  const octets: number[] = [];
  for (const part of parts) {
    if (!/^\d{1,3}$/.test(part)) return null;
    const n = Number(part);
    if (n > 255) return null;
    octets.push(n);
  }
  return octets;
}

/**
 * Extract the embedded IPv4 address from an IPv4-mapped IPv6 literal, in
 * either the dotted-decimal form a hand-written literal might use
 * (`::ffff:10.0.0.1`) or the hex-group form the URL Standard's own
 * serializer always produces for `url.hostname` (`::ffff:a00:1`): WHATWG
 * IPv6 serialization never preserves an embedded dotted-decimal form, so
 * checking only the dotted form here would never actually match what
 * `new URL(...).hostname` produces for a mapped address like
 * `169.254.169.254` (cloud metadata), which serializes as `::ffff:a9fe:a9fe`.
 */
function ipv4FromMappedIPv6(host: string): number[] | null {
  const dotted = /^::ffff:(\d{1,3}(?:\.\d{1,3}){3})$/.exec(host);
  if (dotted) return parseIPv4(dotted[1]);
  const hex = /^::ffff:([0-9a-f]{1,4}):([0-9a-f]{1,4})$/.exec(host);
  if (!hex) return null;
  const hi = parseInt(hex[1], 16);
  const lo = parseInt(hex[2], 16);
  if (hi > 0xffff || lo > 0xffff) return null;
  return [(hi >> 8) & 0xff, hi & 0xff, (lo >> 8) & 0xff, lo & 0xff];
}

/**
 * Extract the embedded IPv4 address from a NAT64 (RFC 6052) literal in the
 * `64:ff9b::/96` well-known prefix, in the compressed hex-group form the
 * URL Standard's serializer produces (`64:ff9b::a9fe:a9fe`). A NAT64
 * gateway routes this straight to the embedded IPv4 destination, so it
 * needs the same private-range check as any other IPv4-embedding form.
 */
function ipv4FromNat64(host: string): number[] | null {
  const hex = /^64:ff9b::([0-9a-f]{1,4}):([0-9a-f]{1,4})$/.exec(host);
  if (!hex) return null;
  const hi = parseInt(hex[1], 16);
  const lo = parseInt(hex[2], 16);
  if (hi > 0xffff || lo > 0xffff) return null;
  return [(hi >> 8) & 0xff, hi & 0xff, (lo >> 8) & 0xff, lo & 0xff];
}

/** 127.0.0.0/8, ::1, and the `localhost` name reserved by RFC 6761. */
export function isLoopbackHost(hostname: string): boolean {
  const host = stripTrailingDot(unbracket(hostname).toLowerCase());
  if (host === "localhost" || host.endsWith(".localhost")) return true;
  if (host === "::1" || host === "0:0:0:0:0:0:0:1") return true;
  const v4 = parseIPv4(host) ?? ipv4FromMappedIPv6(host) ?? ipv4FromNat64(host);
  return v4 !== null && v4[0] === 127;
}

/**
 * Hosts a verifier must never resolve a keyid or directory URL to: loopback,
 * link-local, unique-local, and the RFC 1918 private ranges. Reaching any of
 * them turns key resolution into an SSRF primitive against whatever the
 * verifier can see but the attacker cannot.
 *
 * This inspects the literal host in the URL. A hostname that resolves to a
 * private address through DNS is not caught here; that requires resolution
 * control the Fetch API does not expose. Extension and native verifiers that
 * do control resolution should apply the same rules post-resolution.
 */
export function isPrivateHost(hostname: string): boolean {
  const host = stripTrailingDot(unbracket(hostname).toLowerCase());
  if (isLoopbackHost(host)) return true;
  // IPv6 unspecified address: not a routable destination, but not a
  // safe one to hand to a fetch implementation either.
  if (host === "::" || host === "0:0:0:0:0:0:0:0") return true;
  // IPv6 unique-local (fc00::/7) and link-local (fe80::/10).
  if (/^f[cd][0-9a-f]{2}:/.test(host)) return true;
  if (/^fe[89ab][0-9a-f]:/.test(host)) return true;
  // IPv4-mapped IPv6 and NAT64 (RFC 6052), either literal form -- see
  // ipv4FromMappedIPv6 and ipv4FromNat64.
  const v4 = parseIPv4(host) ?? ipv4FromMappedIPv6(host) ?? ipv4FromNat64(host);
  if (!v4) return false;
  const [a, b, c, d] = v4;
  if (a === 0 || a === 10 || a === 127) return true;
  if (a === 169 && b === 254) return true; // link-local, incl. cloud metadata
  if (a === 172 && b >= 16 && b <= 31) return true;
  if (a === 192 && b === 168) return true;
  if (a === 100 && b >= 64 && b <= 127) return true; // RFC 6598 carrier-grade NAT
  if (a === 168 && b === 63 && c === 129 && d === 16) return true; // Azure platform metadata/DNS
  if (a === 192 && b === 0 && c === 0) return true; // RFC 6890 IETF Protocol Assignments (incl. NAT64/DNS64 discovery, AMT)
  return false;
}

/**
 * Build the fetch used for keyid and trust-directory resolution (spec §11.8).
 *
 * HTTPS only, no ambient credentials, no referrer, and no redirect following:
 * a redirect chain is an attacker-controlled way to reach a host the initial
 * URL check already rejected, so we fail rather than re-check each hop.
 * Private and loopback hosts are refused outright unless a test explicitly
 * opts in via `allowInsecureHttpForTesting`.
 */
export function makeVerificationFetch(options: VerificationFetchOptions = {}): typeof fetch {
  const fetchImpl = options.fetch ?? globalThis.fetch;
  if (!fetchImpl) throw new Error("no fetch implementation available");
  const testing = options.allowInsecureHttpForTesting === true;
  return async (input: RequestInfo | URL, init?: RequestInit): Promise<Response> => {
    const url = new URL(
      typeof input === "string" || input instanceof URL ? input.toString() : input.url,
      options.origin || currentSerializedOrigin() || undefined,
    );
    const sameOrigin = options.origin ? url.origin === options.origin : false;
    const maySendCredentials = options.sameOriginSourceRefetch === true && sameOrigin;
    // Fixture servers in the test suite are plain HTTP on loopback; that is the
    // only case `allowInsecureHttpForTesting` unlocks.
    const testingLoopback = testing && isLoopbackHost(url.hostname);
    if (url.protocol !== "https:" && !testingLoopback) {
      throw new Error("network-policy-blocked");
    }
    if (isPrivateHost(url.hostname) && !testingLoopback) {
      throw new Error("network-policy-blocked");
    }
    return fetchImpl(url.toString(), {
      ...init,
      credentials: maySendCredentials ? "same-origin" : "omit",
      referrerPolicy: "no-referrer",
      redirect: "error",
    });
  };
}
