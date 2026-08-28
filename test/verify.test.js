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
import {
  verifySignedSection,
  canonicalizeSignedContent,
  directUrlResolver,
  trustDirectoryResolver,
  isPrivateHost,
} from "../dist/index.js";
import { generateKey, sha256Hex, sha256HexAsync, signEd25519, startServer, stopServer } from "./_helpers.js";

function canonicalizeClaims(claims) {
  return Object.entries(claims)
    .sort(([a], [b]) => a.localeCompare(b))
    .map(([name, content]) => `${name}:${content}\n`)
    .join("");
}

function buildSignedSectionHtml({ keyid, contentHash, signature, claims, body, algorithm = "ed25519" }) {
  const metas = Object.entries(claims).map(([k, v]) => `<meta name="${k}" content="${v}">`).join("");
  return `<signed-section keyid="${keyid}" content-hash="${contentHash}" signature="${signature}" algorithm="${algorithm}">${metas}${body}</signed-section>`;
}

async function buildSigned({ pem, privateKey, body, claims, signedAt, domain, keyid }) {
  const allClaims = { ...claims, "signed-at": signedAt };
  const canonicalContent = canonicalizeSignedContent(body, domain);
  const contentHash = `sha256:${sha256Hex(canonicalContent)}`;
  const claimsHash = `sha256:${sha256Hex(canonicalizeClaims(allClaims))}`;
  const binding = `${contentHash}:${claimsHash}:${domain}:${signedAt}`;
  const signature = signEd25519(privateKey, binding);
  return {
    html: buildSignedSectionHtml({ keyid, contentHash, signature, claims: allClaims, body }),
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
    `<signed-section keyid="https://k.example/k" content-hash="sha256:47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU" signature="abc" algorithm="ecdsa-p521"><meta name="signed-at" content="2026-01-01T00:00:00Z"></signed-section>`,
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
  const result = await verifySignedSection(
    `<signed-section keyid="x" content-hash="sha256:47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU" signature="abc" algorithm="ed25519"><meta name="signed-at" content="2026-01-01T00:00:00Z"><meta name="author" content="Alice"><meta name="author" content="Bob"></signed-section>`,
    { keyResolvers: [], domain: "https://example.org", hash: sha256HexAsync },
  );
  assert.equal(result.valid, false);
  assert.equal(result.reason, "claim-duplicate");
});
