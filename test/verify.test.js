/**
 * Layer 1 round-trip and failure-mode tests.
 *
 * We sign a fake signed-section binding using a freshly generated ed25519
 * keypair, expose the public key through a directUrlResolver-compatible
 * fixture server, and assert verifySignedSection produces the expected
 * VerifyResult for each scenario.
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import { generateKeyPairSync } from "node:crypto";
import {
  verifySignedSection,
  canonicalizeSignedContent,
  directUrlResolver,
  trustDirectoryResolver,
  isPrivateHost,
  isLoopbackHost,
} from "../dist/index.js";
import { generateKey, sha256Hex, sha256HexAsync, signEd25519, startServer, stopServer } from "./_helpers.js";
import { buildSigningPayloadV1, canonicalizeClaims as canonicalizeClaimsV1 } from "@htmltrust/canonicalization";

function canonicalizeClaims(claims) {
  return canonicalizeClaimsV1(claims);
}

function buildSignedSectionHtml({ keyid, contentHash, signature, claims, body, algorithm = "ed25519", profile = "htmltrust-signature-v1", scope = "url" }) {
  const metas = Object.entries(claims).map(([k, v]) => `<meta name="${k}" content="${v}">`).join("");
  return `<signed-section profile="${profile}" signature-scope="${scope}" keyid="${keyid}" content-hash="${contentHash}" signature="${signature}" algorithm="${algorithm}">${metas}${body}</signed-section>`;
}

async function buildSigned({ pem, privateKey, body, claims, signedAt, domain, keyid, documentUrl = domain, baseUrl = domain, scope = "url", algorithm = "ed25519" }) {
  const allClaims = { ...claims, "signed-at": signedAt };
  const canonicalContent = canonicalizeSignedContent(body, baseUrl);
  const contentHash = `sha256:${sha256Hex(canonicalContent)}`;
  const claimsHash = `sha256:${sha256Hex(canonicalizeClaims(allClaims))}`;
  const signingPayload = buildSigningPayloadV1({
    contentHash,
    claimsHash,
    documentURL: documentUrl,
    scope,
    keyid,
    algorithm,
    signedAt,
  });
  const signature = signEd25519(privateKey, signingPayload);
  return {
    html: buildSignedSectionHtml({ keyid, contentHash, signature, claims: allClaims, body, algorithm, scope }),
    contentHash,
    claimsHash,
  };
  // pem unused here but accepted for symmetry with the caller's data flow
}

test("verifySignedSection: round-trip valid", async () => {
  const { privateKey, pem } = generateKey();
  const { server, base } = await startServer({
    "/key.json": () => ({ body: { publicKey: pem, algorithm: "ed25519" } }),
  });
  try {
    const keyid = `${base}/key.json`;
    const domain = "https://example.org";
    const signedAt = "2026-04-28T12:00:00Z";
    const claims = { author: "Alice", "claim:title": "Hello" };
    const body = '<p>Hello, <a href="/signed">signed world</a>.</p>';
    const { html, contentHash } = await buildSigned({ pem, privateKey, body, claims, signedAt, domain, keyid });

    const result = await verifySignedSection(html, {
      keyResolvers: [directUrlResolver({ allowInsecureHttpForTesting: true })],
      domain,
      hash: sha256HexAsync,
    });

    assert.equal(result.valid, true, result.reason);
    assert.equal(result.keyid, keyid);
    assert.equal(result.domain, domain);
    assert.equal(result.origin, domain);
    assert.equal(result.contentHash, contentHash);
    assert.equal(result.claims.author, "Alice");
    assert.equal(result.claims["claim:title"], "Hello");
    assert.equal(result.signedAt, signedAt);
    assert.equal(result.inputState, "source-only");
  } finally {
    await stopServer(server);
  }
});

test("verifySignedSection: missing required attributes", async () => {
  const result = await verifySignedSection(
    `<signed-section keyid="x"><meta name="signed-at" content="t"></signed-section>`,
    { keyResolvers: [], domain: "https://example.org", hash: sha256HexAsync },
  );
  assert.equal(result.valid, false);
  assert.equal(result.reason, "incomplete");
});

test("verifySignedSection: content hash mismatch", async () => {
  const { privateKey, pem } = generateKey();
  const { server, base } = await startServer({
    "/key.json": () => ({ body: { publicKey: pem, algorithm: "ed25519" } }),
  });
  try {
    const keyid = `${base}/key.json`;
    const domain = "https://example.org";
    const signedAt = "2026-04-28T12:00:00Z";
    const claims = { author: "Alice" };
    const body = "<p>Original content.</p>";
    const { html } = await buildSigned({ pem, privateKey, body, claims, signedAt, domain, keyid });
    // Tamper with the body AFTER signing.
    const tampered = html.replace("Original content.", "Tampered content.");
    const result = await verifySignedSection(tampered, {
      keyResolvers: [directUrlResolver({ allowInsecureHttpForTesting: true })],
      domain,
      hash: sha256HexAsync,
    });
    assert.equal(result.valid, false);
    assert.equal(result.reason, "content-hash-mismatch");
  } finally {
    await stopServer(server);
  }
});

test("verifySignedSection: key not resolvable", async () => {
  const { privateKey, pem } = generateKey();
  // Build a valid signed section but point keyid at a URL we won't serve.
  // Port 9 (Discard) is reliably closed; any port outside the WHATWG "bad
  // ports" list works — port 1 is rejected by fetch up front.
  const keyid = "http://127.0.0.1:9/nonexistent.json";
  const domain = "https://example.org";
  const signedAt = "2026-04-28T12:00:00Z";
  const claims = { author: "Alice" };
  const body = "<p>Body.</p>";
  const { html } = await buildSigned({ pem, privateKey, body, claims, signedAt, domain, keyid });
  const result = await verifySignedSection(html, {
    keyResolvers: [directUrlResolver({ allowInsecureHttpForTesting: true })],
    domain,
    hash: sha256HexAsync,
  });
  assert.equal(result.valid, false);
  assert.equal(result.reason, "key-resolution-failed");
});

test("verifySignedSection: preserves resolver policy and resource failures", async () => {
  const { privateKey, pem } = generateKey();
  const common = {
    pem,
    privateKey,
    body: "<p>Body.</p>",
    claims: { author: "Alice" },
    signedAt: "2026-04-28T12:00:00Z",
    domain: "https://example.org",
    keyid: "https://example.org/key.json",
  };
  const { html } = await buildSigned(common);
  for (const [error, reason] of [
    ["network-policy-blocked: HTTPS required", "network-policy-blocked"],
    ["resource-limit-exceeded", "resource-limit-exceeded"],
    ["malformed-key-document", "malformed-key-document"],
  ]) {
    const result = await verifySignedSection(html, {
      documentUrl: "https://example.org/article",
      hash: sha256HexAsync,
      keyResolvers: [{ resolve: async () => { throw new Error(error); } }],
    });
    assert.equal(result.reason, reason);
  }
});

test("verifySignedSection: signature invalid", async () => {
  const { privateKey, pem } = generateKey();
  const { server, base } = await startServer({
    "/key.json": () => ({ body: { publicKey: pem, algorithm: "ed25519" } }),
  });
  try {
    const keyid = `${base}/key.json`;
    const domain = "https://example.org";
    const signedAt = "2026-04-28T12:00:00Z";
    const claims = { author: "Alice" };
    const body = "<p>Body.</p>";
    const { html } = await buildSigned({ pem, privateKey, body, claims, signedAt, domain, keyid });
    // Surgically replace the signature attribute with a different (also-valid)
    // base64 string of the same shape but signing a different message.
    const otherSig = signEd25519(privateKey, "different message");
    const broken = html.replace(/signature="[^"]*"/, `signature="${otherSig}"`);
    const result = await verifySignedSection(broken, {
      keyResolvers: [directUrlResolver({ allowInsecureHttpForTesting: true })],
      domain,
      hash: sha256HexAsync,
    });
    assert.equal(result.valid, false);
    assert.equal(result.reason, "signature-invalid");
  } finally {
    await stopServer(server);
  }
});

test("verifySignedSection: detects source snapshot stale against rendered section", async () => {
  const { privateKey, pem } = generateKey();
  const { server, base } = await startServer({
    "/key.json": () => ({ body: { publicKey: pem, algorithm: "ed25519" } }),
  });
  try {
    const keyid = `${base}/key.json`;
    const domain = "https://example.org";
    const signedAt = "2026-04-28T12:00:00Z";
    const body = '<p><img src="/img.png" alt="Original"> Caption</p>';
    const { html } = await buildSigned({ pem, privateKey, body, claims: { author: "Alice" }, signedAt, domain, keyid });
    const rendered = html.replace('alt="Original"', 'alt="Changed"');
    const result = await verifySignedSection(html, {
      keyResolvers: [directUrlResolver({ allowInsecureHttpForTesting: true })],
      domain,
      hash: sha256HexAsync,
      renderedSection: rendered,
    });
    assert.equal(result.valid, true, result.reason);
    assert.equal(result.inputState, "stale");
  } finally {
    await stopServer(server);
  }
});

test("verifySignedSection: compares rendered relative URLs against the live base URL", async () => {
  const { privateKey, pem } = generateKey();
  const { server, base } = await startServer({
    "/key.json": () => ({ body: { publicKey: pem, algorithm: "ed25519" } }),
  });
  try {
    const keyid = `${base}/key.json`;
    const domain = "https://example.org";
    const body = '<p><a href="signed">Signed link</a></p>';
    const { html } = await buildSigned({
      pem,
      privateKey,
      body,
      claims: { author: "Alice" },
      signedAt: "2026-04-28T12:00:00Z",
      domain,
      keyid,
    });
    const result = await verifySignedSection(html, {
      keyResolvers: [directUrlResolver({ allowInsecureHttpForTesting: true })],
      domain,
      baseUrl: `${domain}/article`,
      renderedBaseUrl: `${domain}/other/`,
      renderedSection: html,
      hash: sha256HexAsync,
    });
    assert.equal(result.valid, true, result.reason);
    assert.equal(result.inputState, "stale");
  } finally {
    await stopServer(server);
  }
});

// Spec §8.2: `revoked: true` or an `expires` in the past is a key-revoked
// failure, and the verifier must not reach signature verification. Each case
// below signs a section that is otherwise perfectly valid, so only the key
// document's lifecycle fields can produce the failure.
async function verifyWithKeyDocument(keyDocument) {
  const { privateKey, pem } = generateKey();
  const { server, base } = await startServer({
    "/key.json": () => ({ body: { publicKey: pem, algorithm: "ed25519", ...keyDocument } }),
  });
  try {
    const keyid = `${base}/key.json`;
    const domain = "https://example.org";
    const signedAt = "2026-04-28T12:00:00Z";
    const { html } = await buildSigned({
      pem,
      privateKey,
      body: "<p>Body.</p>",
      claims: { author: "Alice" },
      signedAt,
      domain,
      keyid,
    });
    return await verifySignedSection(html, {
      keyResolvers: [directUrlResolver({ allowInsecureHttpForTesting: true })],
      domain,
      hash: sha256HexAsync,
    });
  } finally {
    await stopServer(server);
  }
}

test("verifySignedSection: revoked key fails closed", async () => {
  const result = await verifyWithKeyDocument({ revoked: true });
  assert.equal(result.valid, false);
  assert.equal(result.reason, "key-revoked");
});

test("verifySignedSection: expired key fails closed", async () => {
  const result = await verifyWithKeyDocument({ expires: "2020-01-01T00:00:00Z" });
  assert.equal(result.valid, false);
  assert.equal(result.reason, "key-revoked");
});

test("verifySignedSection: unparseable expires fails closed", async () => {
  const result = await verifyWithKeyDocument({ expires: "not-a-timestamp" });
  assert.equal(result.valid, false);
  assert.equal(result.reason, "key-revoked");
});

test("verifySignedSection: key with a future expires still verifies", async () => {
  const result = await verifyWithKeyDocument({ revoked: false, expires: "2999-01-01T00:00:00Z" });
  assert.equal(result.valid, true, result.reason);
});

test("verifySignedSection: unregistered algorithm is algorithm-not-supported", async () => {
  const result = await verifySignedSection(
    `<signed-section profile="htmltrust-signature-v1" signature-scope="url" keyid="https://k.example/k" content-hash="sha256:47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU" signature="abc" algorithm="ecdsa-p521"><meta name="signed-at" content="2026-01-01T00:00:00Z"></signed-section>`,
    { keyResolvers: [], domain: "https://example.org", hash: sha256HexAsync },
  );
  assert.equal(result.valid, false);
  assert.equal(result.reason, "algorithm-not-supported");
});

test("verifySignedSection: two different pinned ECDSA curves are a mismatch", async () => {
  const { server, base } = await startServer({
    "/key.json": () => ({ body: { publicKey: "-----BEGIN PUBLIC KEY-----\nAA==\n-----END PUBLIC KEY-----\n", algorithm: "ecdsa-p384" } }),
  });
  try {
    const { privateKey, pem } = generateKey();
    const keyid = `${base}/key.json`;
    const domain = "https://example.org";
    const { html } = await buildSigned({
      pem,
      privateKey,
      body: "<p>Body.</p>",
      claims: { author: "Alice" },
      signedAt: "2026-04-28T12:00:00Z",
      domain,
      keyid,
    });
    const result = await verifySignedSection(html.replace('algorithm="ed25519"', 'algorithm="ecdsa-p256"'), {
      keyResolvers: [directUrlResolver({ allowInsecureHttpForTesting: true })],
      domain,
      hash: sha256HexAsync,
    });
    assert.equal(result.valid, false);
    assert.equal(result.reason, "algorithm-mismatch");
  } finally {
    await stopServer(server);
  }
});

test("isPrivateHost: classifies loopback, link-local, and RFC 1918 hosts", () => {
  for (const host of [
    "127.0.0.1",
    "127.1.2.3",
    "localhost",
    "[::1]",
    "169.254.169.254",
    "10.0.0.1",
    "172.16.0.1",
    "172.31.255.255",
    "192.168.1.1",
    "[fd00::1]",
    "[fe80::1]",
    "[::ffff:10.0.0.1]",
  ]) {
    assert.equal(isPrivateHost(host), true, `${host} should be private`);
  }
  for (const host of ["example.org", "8.8.8.8", "172.32.0.1", "192.169.0.1", "[2606:4700::1]"]) {
    assert.equal(isPrivateHost(host), false, `${host} should be public`);
  }
});

test("isPrivateHost: catches the hex-group IPv4-mapped IPv6 form the URL Standard's own serializer actually produces", () => {
  // new URL("http://[::ffff:10.0.0.1]/x").hostname is "[::ffff:a00:1]", not
  // the dotted-decimal literal a caller might type -- WHATWG IPv6
  // serialization never preserves the dotted form. A guard that only
  // recognizes the dotted form never actually fires on real url.hostname
  // output.
  assert.equal(new URL("http://[::ffff:10.0.0.1]/x").hostname, "[::ffff:a00:1]");
  assert.equal(isPrivateHost("[::ffff:a00:1]"), true, "10.0.0.1 in hex-group form");
  assert.equal(isPrivateHost("[::ffff:a9fe:a9fe]"), true, "169.254.169.254 (cloud metadata) in hex-group form");
  assert.equal(isPrivateHost("[::ffff:7f00:1]"), true, "127.0.0.1 in hex-group form");
  assert.equal(isPrivateHost("[::ffff:808:808]"), false, "8.8.8.8 in hex-group form should be public");
});

test("isLoopbackHost: catches the hex-group IPv4-mapped IPv6 loopback form too", () => {
  assert.equal(isLoopbackHost("[::ffff:7f00:1]"), true);
  assert.equal(isLoopbackHost("[::ffff:a00:1]"), false, "10.0.0.1 is private but not loopback");
});

test("trustDirectoryResolver: refuses a private-network directory base URL", () => {
  assert.throws(
    () => trustDirectoryResolver({ baseUrls: ["https://10.0.0.5/directory"] }),
    /network-policy-blocked/,
  );
  assert.throws(
    () => trustDirectoryResolver({ baseUrls: ["https://169.254.169.254/directory"] }),
    /network-policy-blocked/,
  );
});

test("verifySignedSection: rejects duplicate normalized claim names", async () => {
  const signature = Buffer.alloc(64).toString("base64").replace(/=+$/u, "");
  const result = await verifySignedSection(
    `<signed-section profile="htmltrust-signature-v1" signature-scope="url" keyid="https://k.example/k" content-hash="sha256:47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU" signature="${signature}" algorithm="ed25519"><meta name="signed-at" content="2026-01-01T00:00:00Z"><meta name="author" content="Alice"><meta name="author" content="Bob"></signed-section>`,
    { keyResolvers: [], domain: "https://example.org", hash: sha256HexAsync },
  );
  assert.equal(result.valid, false);
  assert.equal(result.reason, "claim-duplicate");
});

test("verifySignedSection: preserves raw source for opening-tag parser rejection", async () => {
  const signature = Buffer.alloc(64).toString("base64").replace(/=+$/u, "");
  const result = await verifySignedSection(
    `<signed-section profile="htmltrust-signature-v1" profile="htmltrust-signature-v0" signature-scope="url" keyid="https://k.example/k" content-hash="sha256:47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU" signature="${signature}" algorithm="ed25519"><meta name="signed-at" content="2026-01-01T00:00:00Z"></signed-section>`,
    { keyResolvers: [], documentUrl: "https://example.org/article", hash: sha256HexAsync },
  );
  assert.equal(result.reason, "parser-profile-unsupported");
});

test("verifySignedSection: Node string parsing accepts HTML unquoted and escaped attributes", async () => {
  const signature = Buffer.alloc(64).toString("base64").replace(/=+$/u, "");
  let resolvedKeyid = null;
  // A path segment containing an HTML-entity-escaped "&", not a query
  // string: a URL-form keyid with a query or fragment is now forbidden
  // outright (spec §5.1), so this fixture exercises unquoted-attribute and
  // entity decoding without relying on a keyid shape that is no longer
  // valid.
  const keyid = "https://example.org/key/a&b";
  const html = `<signed-section profile=htmltrust-signature-v1 signature-scope=url keyid="https://example.org/key/a&amp;b" content-hash=sha256:47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU signature=${signature} algorithm=ed25519><meta name=signed-at content=2026-01-01T00:00:00Z></signed-section>`;
  const result = await verifySignedSection(html, {
    documentUrl: "https://example.org/article",
    hash: sha256HexAsync,
    keyResolvers: [{ resolve: async (candidate) => {
      resolvedKeyid = candidate;
      return null;
    } }],
  });
  assert.equal(resolvedKeyid, keyid);
  assert.equal(result.reason, "key-resolution-failed");
});

test("verifySignedSection: Element input cannot recover source-level ambiguity", async () => {
  const signature = Buffer.alloc(64).toString("base64").replace(/=+$/u, "");
  const source = `<signed-section profile="htmltrust-signature-v1" profile="htmltrust-signature-v0" signature-scope="url" keyid="https://example.org/key" content-hash="sha256:47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU" signature="${signature}" algorithm="ed25519"></signed-section>`;
  const sourceResult = await verifySignedSection(source, {
    documentUrl: "https://example.org/article",
    hash: sha256HexAsync,
    keyResolvers: [],
  });
  assert.equal(sourceResult.reason, "parser-profile-unsupported");

  // This is the repaired representation a browser Element exposes. The
  // duplicate source attribute is no longer observable by the verifier.
  const attrs = {
    profile: "htmltrust-signature-v1",
    "signature-scope": "url",
    keyid: "https://example.org/key",
    "content-hash": "sha256:47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU",
    signature,
    algorithm: "ed25519",
  };
  const element = {
    children: [],
    innerHTML: "",
    outerHTML: `<signed-section ${Object.entries(attrs).map(([name, value]) => `${name}="${value}"`).join(" ")}></signed-section>`,
    getAttribute(name) { return attrs[name] ?? null; },
  };
  const elementResult = await verifySignedSection(element, {
    documentUrl: "https://example.org/article",
    hash: sha256HexAsync,
    keyResolvers: [],
  });
  assert.notEqual(elementResult.reason, "parser-profile-unsupported");
});

test("verifySignedSection: applies the shared direct-claim count ceiling", async () => {
  const signature = Buffer.alloc(64).toString("base64").replace(/=+$/u, "");
  const metas = [
    '<meta name="signed-at" content="2026-01-01T00:00:00Z">',
    ...Array.from({ length: 64 }, (_, index) => `<meta name="claim:${index}" content="x">`),
  ].join("");
  const result = await verifySignedSection(
    `<signed-section profile="htmltrust-signature-v1" signature-scope="url" keyid="https://k.example/k" content-hash="sha256:47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU" signature="${signature}" algorithm="ed25519">${metas}</signed-section>`,
    { keyResolvers: [], documentUrl: "https://example.org/article", hash: sha256HexAsync },
  );
  assert.equal(result.reason, "resource-limit-exceeded");
});

test("verifySignedSection: rejects a non-registry hash identifier spelling", async () => {
  const signature = Buffer.alloc(64).toString("base64").replace(/=+$/u, "");
  const result = await verifySignedSection(
    `<signed-section profile="htmltrust-signature-v1" signature-scope="url" keyid="https://k.example/k" content-hash="SHA256:47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU" signature="${signature}" algorithm="ed25519"><meta name="signed-at" content="2026-01-01T00:00:00Z"></signed-section>`,
    { keyResolvers: [], documentUrl: "https://example.org/article", hash: sha256HexAsync },
  );
  assert.equal(result.reason, "invalid-encoding");
});

test("verifySignedSection: checks RSA signature width after key resolution", async () => {
  const { publicKey } = generateKeyPairSync("rsa", { modulusLength: 2048 });
  const publicKeyPem = publicKey.export({ type: "spki", format: "pem" }).toString();
  const signature = Buffer.alloc(255).toString("base64").replace(/=+$/u, "");
  const result = await verifySignedSection(
    `<signed-section profile="htmltrust-signature-v1" signature-scope="url" keyid="https://k.example/rsa" content-hash="sha256:47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU" signature="${signature}" algorithm="rsa-pkcs1-sha256"><meta name="signed-at" content="2026-01-01T00:00:00Z"></signed-section>`,
    {
      keyResolvers: [{ resolve: async () => ({ keyid: "https://k.example/rsa", publicKeyPem, algorithm: "rsa-pkcs1-sha256" }) }],
      documentUrl: "https://example.org/article",
      hash: sha256HexAsync,
    },
  );
  assert.equal(result.reason, "malformed-signature");
});

test("verifySignedSection: requires the exact v1 profile and scope attributes", async () => {
  const common = `keyid="https://k.example/k" content-hash="sha256:47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU" signature="abc" algorithm="ed25519"><meta name="signed-at" content="2026-01-01T00:00:00Z"></signed-section>`;
  for (const [attribute, expected] of [
    [`profile="htmltrust-signature-v0"`, "profile-unsupported"],
    [`signature-scope="host"`, "scope-unsupported"],
    [`profile=" htmltrust-signature-v1"`, "incomplete"],
  ]) {
    const html = `<signed-section profile="htmltrust-signature-v1" signature-scope="url" ${common}`
      .replace(attribute === `profile="htmltrust-signature-v0"` ? `profile="htmltrust-signature-v1"` : attribute === `signature-scope="host"` ? `signature-scope="url"` : `profile="htmltrust-signature-v1"`, attribute);
    const result = await verifySignedSection(html, {
      keyResolvers: [],
      documentUrl: "https://example.org/article",
      baseUrl: "https://example.org/article",
      hash: sha256HexAsync,
    });
    assert.equal(result.reason, expected);
  }
});

test("verifySignedSection: validates the exact signed-at timestamp", async () => {
  const { privateKey, pem } = generateKey();
  const { server, base } = await startServer({
    "/key.json": () => ({ body: { publicKey: pem, algorithm: "ed25519" } }),
  });
  try {
    const keyid = `${base}/key.json`;
    const { html } = await buildSigned({
      pem,
      privateKey,
      body: "<p>Body.</p>",
      claims: { author: "Alice" },
      signedAt: "2026-01-01T00:00:00Z",
      domain: "https://example.org",
      keyid,
    });
    const invalid = html.replace("2026-01-01T00:00:00Z", "2026-02-29T00:00:00Z");
    const result = await verifySignedSection(invalid, {
      keyResolvers: [directUrlResolver({ allowInsecureHttpForTesting: true })],
      documentUrl: "https://example.org/article",
      baseUrl: "https://example.org/article",
      hash: sha256HexAsync,
    });
    assert.equal(result.reason, "timestamp-invalid");
  } finally {
    await stopServer(server);
  }
});

test("verifySignedSection: url scope binds the final document URL, while origin scope permits same-origin replay", async () => {
  const { privateKey, pem } = generateKey();
  const { server, base } = await startServer({
    "/key.json": () => ({ body: { publicKey: pem, algorithm: "ed25519" } }),
  });
  try {
    const keyid = `${base}/key.json`;
    const domain = "https://example.org";
    const urlSigned = await buildSigned({
      pem, privateKey, body: "<p>Body.</p>", claims: { author: "Alice" },
      signedAt: "2026-01-01T00:00:00Z", domain, keyid,
      documentUrl: `${domain}/article?edition=1`, baseUrl: `${domain}/assets/`, scope: "url",
    });
    const replay = await verifySignedSection(urlSigned.html, {
      keyResolvers: [directUrlResolver({ allowInsecureHttpForTesting: true })],
      documentUrl: `${domain}/article?edition=2`, baseUrl: `${domain}/assets/`, hash: sha256HexAsync,
    });
    assert.equal(replay.reason, "signature-invalid");

    const originSigned = await buildSigned({
      pem, privateKey, body: "<p>Body.</p>", claims: { author: "Alice" },
      signedAt: "2026-01-01T00:00:00Z", domain, keyid,
      documentUrl: `${domain}/article?edition=1`, baseUrl: `${domain}/assets/`, scope: "origin",
    });
    const sameOrigin = await verifySignedSection(originSigned.html, {
      keyResolvers: [directUrlResolver({ allowInsecureHttpForTesting: true })],
      documentUrl: `${domain}/other`, baseUrl: `${domain}/assets/`, hash: sha256HexAsync,
    });
    assert.equal(sameOrigin.valid, true, sameOrigin.reason);
  } finally {
    await stopServer(server);
  }
});

test("verifySignedSection: rejects algorithm substitution against the resolved key", async () => {
  const { privateKey, pem } = generateKey();
  const { server, base } = await startServer({
    "/key.json": () => ({ body: { publicKey: pem, algorithm: "ed25519" } }),
  });
  try {
    const keyid = `${base}/key.json`;
    const { html } = await buildSigned({
      pem, privateKey, body: "<p>Body.</p>", claims: { author: "Alice" },
      signedAt: "2026-01-01T00:00:00Z", domain: "https://example.org", keyid,
    });
    const substituted = html.replace('algorithm="ed25519"', 'algorithm="ecdsa-p256"');
    const result = await verifySignedSection(substituted, {
      keyResolvers: [directUrlResolver({ allowInsecureHttpForTesting: true })],
      documentUrl: "https://example.org/article", baseUrl: "https://example.org/article", hash: sha256HexAsync,
    });
    assert.equal(result.reason, "algorithm-mismatch");
  } finally {
    await stopServer(server);
  }
});

test("verifySignedSection: applies the frozen safe URL policy", async () => {
  const { privateKey, pem } = generateKey();
  const { server, base } = await startServer({
    "/key.json": () => ({ body: { publicKey: pem, algorithm: "ed25519" } }),
  });
  try {
    const keyid = `${base}/key.json`;
    const { html } = await buildSigned({
      pem, privateKey, body: '<p><a href="/safe">Body.</a></p>', claims: { author: "Alice" },
      signedAt: "2026-01-01T00:00:00Z", domain: "https://example.org", keyid,
    });
    const unsafe = html.replace('href="/safe"', 'href="javascript:alert(1)"');
    const result = await verifySignedSection(unsafe, {
      keyResolvers: [directUrlResolver({ allowInsecureHttpForTesting: true })],
      documentUrl: "https://example.org/article", baseUrl: "https://example.org/article", hash: sha256HexAsync,
    });
    assert.equal(result.reason, "url-policy-violation");
  } finally {
    await stopServer(server);
  }
});
