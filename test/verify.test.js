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
import { extractCanonicalText, canonicalizeClaims } from "@htmltrust/canonicalization";
import { verifySignedSection, directUrlResolver } from "../dist/index.js";
import { generateKey, sha256Hex, sha256HexAsync, signEd25519, startServer, stopServer } from "./_helpers.js";

function buildSignedSectionHtml({ keyid, contentHash, signature, claims, signedAt, body, algorithm = "ed25519" }) {
  const metas = [
    `<meta name="signed-at" content="${signedAt}">`,
    ...Object.entries(claims).map(([k, v]) => `<meta name="claim:${k}" content="${v}">`),
  ].join("");
  return `<signed-section keyid="${keyid}" content-hash="${contentHash}" signature="${signature}" algorithm="${algorithm}">${metas}${body}</signed-section>`;
}

async function buildSigned({ pem, privateKey, body, claims, signedAt, domain, keyid }) {
  const canonicalContent = extractCanonicalText(body);
  const contentHash = `sha256:${sha256Hex(canonicalContent)}`;
  const claimsHash = `sha256:${sha256Hex(canonicalizeClaims(claims))}`;
  const binding = `${contentHash}:${claimsHash}:${domain}:${signedAt}`;
  const signature = signEd25519(privateKey, binding);
  return {
    html: buildSignedSectionHtml({ keyid, contentHash, signature, claims, signedAt, body }),
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
    const domain = "example.org";
    const signedAt = "2026-04-28T12:00:00Z";
    const claims = { author: "Alice", title: "Hello" };
    const body = "<p>Hello, signed world.</p>";
    const { html, contentHash } = await buildSigned({ pem, privateKey, body, claims, signedAt, domain, keyid });

    const result = await verifySignedSection(html, {
      keyResolvers: [directUrlResolver()],
      domain,
      hash: sha256HexAsync,
    });

    assert.equal(result.valid, true, result.reason);
    assert.equal(result.keyid, keyid);
    assert.equal(result.domain, domain);
    assert.equal(result.contentHash, contentHash);
    assert.equal(result.claims.author, "Alice");
    assert.equal(result.claims.title, "Hello");
    assert.equal(result.signedAt, signedAt);
  } finally {
    await stopServer(server);
  }
});

test("verifySignedSection: missing required attributes", async () => {
  const result = await verifySignedSection(
    `<signed-section keyid="x"><meta name="signed-at" content="t"></signed-section>`,
    { keyResolvers: [], domain: "example.org", hash: sha256HexAsync },
  );
  assert.equal(result.valid, false);
  assert.equal(result.reason, "missing required attributes");
});

test("verifySignedSection: content hash mismatch", async () => {
  const { privateKey, pem } = generateKey();
  const { server, base } = await startServer({
    "/key.json": () => ({ body: { publicKey: pem, algorithm: "ed25519" } }),
  });
  try {
    const keyid = `${base}/key.json`;
    const domain = "example.org";
    const signedAt = "2026-04-28T12:00:00Z";
    const claims = { author: "Alice" };
    const body = "<p>Original content.</p>";
    const { html } = await buildSigned({ pem, privateKey, body, claims, signedAt, domain, keyid });
    // Tamper with the body AFTER signing.
    const tampered = html.replace("Original content.", "Tampered content.");
    const result = await verifySignedSection(tampered, {
      keyResolvers: [directUrlResolver()],
      domain,
      hash: sha256HexAsync,
    });
    assert.equal(result.valid, false);
    assert.equal(result.reason, "content hash mismatch");
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
  const domain = "example.org";
  const signedAt = "2026-04-28T12:00:00Z";
  const claims = { author: "Alice" };
  const body = "<p>Body.</p>";
  const { html } = await buildSigned({ pem, privateKey, body, claims, signedAt, domain, keyid });
  const result = await verifySignedSection(html, {
    keyResolvers: [directUrlResolver()],
    domain,
    hash: sha256HexAsync,
  });
  assert.equal(result.valid, false);
  assert.equal(result.reason, "key not resolvable");
});

test("verifySignedSection: signature invalid", async () => {
  const { privateKey, pem } = generateKey();
  const { server, base } = await startServer({
    "/key.json": () => ({ body: { publicKey: pem, algorithm: "ed25519" } }),
  });
  try {
    const keyid = `${base}/key.json`;
    const domain = "example.org";
    const signedAt = "2026-04-28T12:00:00Z";
    const claims = { author: "Alice" };
    const body = "<p>Body.</p>";
    const { html } = await buildSigned({ pem, privateKey, body, claims, signedAt, domain, keyid });
    // Surgically replace the signature attribute with a different (also-valid)
    // base64 string of the same shape but signing a different message.
    const otherSig = signEd25519(privateKey, "different message");
    const broken = html.replace(/signature="[^"]*"/, `signature="${otherSig}"`);
    const result = await verifySignedSection(broken, {
      keyResolvers: [directUrlResolver()],
      domain,
      hash: sha256HexAsync,
    });
    assert.equal(result.valid, false);
    assert.equal(result.reason, "signature invalid");
  } finally {
    await stopServer(server);
  }
});
