/**
 * Publisher-served revocation list (spec §9.5-9.9): fetch outcomes, both
 * per-key states, caching, and the verifySignedSection opt-in integration.
 *
 * Route handlers below are written as closures over `let` variables that
 * are assigned right after `startServer` resolves (once `base` is known),
 * not at server-construction time: requests only arrive after that point,
 * so this avoids needing to guess a server's randomly-assigned port ahead
 * of building the signed fixtures whose content references it.
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import {
  checkKeyRevocation,
  createRevocationCache,
  revocationListOrigin,
  DEFAULT_MAX_STALENESS_MS,
  directUrlResolver,
  verifySignedSection,
  canonicalizeSignedContent,
} from "../dist/index.js";
import { canonicalizeJson, buildSigningPayloadV1, canonicalizeClaims } from "@htmltrust/canonicalization";
import { generateKey, sha256Hex, sha256HexAsync, signEd25519, startServer, stopServer } from "./_helpers.js";

function signRevocationDoc(doc, privateKey) {
  const payload = canonicalizeJson(doc);
  const signature = signEd25519(privateKey, payload);
  return { ...doc, signature };
}

function resolvers() {
  return [directUrlResolver({ allowInsecureHttpForTesting: true })];
}

// === Origin derivation (spec §9.5) ===

test("revocationListOrigin: did:web maps to https origin, ignoring any path", () => {
  assert.equal(revocationListOrigin("did:web:example.com"), "https://example.com");
  assert.equal(revocationListOrigin("did:web:example.com%3A3000"), "https://example.com:3000");
  assert.equal(revocationListOrigin("did:web:example.com:path:to:key"), "https://example.com");
});

test("revocationListOrigin: direct HTTPS key URL maps to its own origin", () => {
  assert.equal(
    revocationListOrigin("https://keys.example/alice-2026.json"),
    "https://keys.example",
  );
});

test("revocationListOrigin: rejects malformed did:web and non-URL keyids", () => {
  assert.equal(revocationListOrigin("did:web:"), null);
  assert.equal(revocationListOrigin("did:web:exa%mple.com"), null);
  assert.equal(revocationListOrigin("not-a-keyid-at-all"), null);
});

test("revocationListOrigin: a keyid whose origin matches a configured directory is not applicable", () => {
  const directories = ["https://directory.example/api"];
  assert.equal(
    revocationListOrigin("https://directory.example/keys/abc123", directories),
    null,
  );
  // A different origin is unaffected by the directory list.
  assert.equal(
    revocationListOrigin("https://keys.example/alice.json", directories),
    "https://keys.example",
  );
});

// === Fetch semantics (spec §9.9) ===

test("checkKeyRevocation: HTTP 404 is not-revoked", async () => {
  const { server, base } = await startServer({});
  try {
    const result = await checkKeyRevocation(`${base}/alice.json`, {
      keyResolvers: [],
      allowInsecureHttpForTesting: true,
    });
    assert.deepEqual(result, { status: "not-revoked", superseded: false });
  } finally {
    await stopServer(server);
  }
});

test("checkKeyRevocation: revoked entry matching the checked keyid", async () => {
  const { privateKey, pem } = generateKey();
  let doc; // assigned once `base` is known, read by the route closure at request time
  const { server, base } = await startServer({
    "/signer.json": () => ({ body: { publicKey: pem, algorithm: "ed25519" } }),
    "/.well-known/htmltrust-revocations.json": () => ({ body: doc }),
  });
  try {
    const signerKeyid = `${base}/signer.json`;
    const targetKeyid = `${base}/alice-2024.json`;
    doc = signRevocationDoc(
      {
        signer: signerKeyid,
        algorithm: "ed25519",
        timestamp: "2026-06-01T00:00:00Z",
        revocations: [{ keyid: targetKeyid, status: "revoked", revokedAt: "2026-05-30T00:00:00Z" }],
      },
      privateKey,
    );
    const result = await checkKeyRevocation(targetKeyid, {
      keyResolvers: resolvers(),
      allowInsecureHttpForTesting: true,
    });
    assert.deepEqual(result, { status: "revoked", superseded: false, revokedAt: "2026-05-30T00:00:00Z" });
  } finally {
    await stopServer(server);
  }
});

test("checkKeyRevocation: an entry naming a different keyid does not revoke this one", async () => {
  const { privateKey, pem } = generateKey();
  let doc;
  const { server, base } = await startServer({
    "/signer.json": () => ({ body: { publicKey: pem, algorithm: "ed25519" } }),
    "/.well-known/htmltrust-revocations.json": () => ({ body: doc }),
  });
  try {
    const signerKeyid = `${base}/signer.json`;
    doc = signRevocationDoc(
      {
        signer: signerKeyid,
        algorithm: "ed25519",
        timestamp: "2026-06-01T00:00:00Z",
        revocations: [{ keyid: `${base}/someone-else.json`, status: "revoked" }],
      },
      privateKey,
    );
    const result = await checkKeyRevocation(`${base}/alice.json`, {
      keyResolvers: resolvers(),
      allowInsecureHttpForTesting: true,
    });
    assert.deepEqual(result, { status: "not-revoked", superseded: false });
  } finally {
    await stopServer(server);
  }
});

test("checkKeyRevocation: superseded entry is not-revoked, with supersession as metadata", async () => {
  const { privateKey, pem } = generateKey();
  let doc;
  const { server, base } = await startServer({
    "/signer.json": () => ({ body: { publicKey: pem, algorithm: "ed25519" } }),
    "/.well-known/htmltrust-revocations.json": () => ({ body: doc }),
  });
  try {
    const signerKeyid = `${base}/signer.json`;
    const targetKeyid = `${base}/alice-2025.json`;
    const successorKeyid = `${base}/alice-2026.json`;
    doc = signRevocationDoc(
      {
        signer: signerKeyid,
        algorithm: "ed25519",
        timestamp: "2026-06-01T00:00:00Z",
        revocations: [{ keyid: targetKeyid, status: "superseded", supersededBy: successorKeyid }],
      },
      privateKey,
    );
    const result = await checkKeyRevocation(targetKeyid, {
      keyResolvers: resolvers(),
      allowInsecureHttpForTesting: true,
    });
    assert.deepEqual(result, {
      status: "not-revoked",
      superseded: true,
      supersededBy: successorKeyid,
    });
  } finally {
    await stopServer(server);
  }
});

test("checkKeyRevocation: key absent from an otherwise-valid list is not-revoked", async () => {
  const { privateKey, pem } = generateKey();
  let doc;
  const { server, base } = await startServer({
    "/signer.json": () => ({ body: { publicKey: pem, algorithm: "ed25519" } }),
    "/.well-known/htmltrust-revocations.json": () => ({ body: doc }),
  });
  try {
    const signerKeyid = `${base}/signer.json`;
    doc = signRevocationDoc(
      { signer: signerKeyid, algorithm: "ed25519", timestamp: "2026-06-01T00:00:00Z", revocations: [] },
      privateKey,
    );
    const result = await checkKeyRevocation(`${base}/someone-else.json`, {
      keyResolvers: resolvers(),
      allowInsecureHttpForTesting: true,
    });
    assert.deepEqual(result, { status: "not-revoked", superseded: false });
  } finally {
    await stopServer(server);
  }
});

test("checkKeyRevocation: invalid signature is revocation-unknown", async () => {
  const { pem } = generateKey();
  const { privateKey: wrongKey } = generateKey();
  let doc;
  const { server, base } = await startServer({
    "/signer.json": () => ({ body: { publicKey: pem, algorithm: "ed25519" } }),
    "/.well-known/htmltrust-revocations.json": () => ({ body: doc }),
  });
  try {
    const signerKeyid = `${base}/signer.json`;
    const targetKeyid = `${base}/alice.json`;
    // Sign with the WRONG key so verification against the signer's real
    // (published) public key fails.
    doc = signRevocationDoc(
      {
        signer: signerKeyid,
        algorithm: "ed25519",
        timestamp: "2026-06-01T00:00:00Z",
        revocations: [{ keyid: targetKeyid, status: "revoked" }],
      },
      wrongKey,
    );
    const result = await checkKeyRevocation(targetKeyid, {
      keyResolvers: resolvers(),
      allowInsecureHttpForTesting: true,
    });
    assert.deepEqual(result, { status: "revocation-unknown", superseded: false });
  } finally {
    await stopServer(server);
  }
});

test("checkKeyRevocation: malformed JSON body is revocation-unknown", async () => {
  const { server, base } = await startServer({
    "/.well-known/htmltrust-revocations.json": () => ({
      body: "{not json",
      headers: { "content-type": "application/json" },
    }),
  });
  try {
    const result = await checkKeyRevocation(`${base}/alice.json`, {
      keyResolvers: [],
      allowInsecureHttpForTesting: true,
    });
    assert.deepEqual(result, { status: "revocation-unknown", superseded: false });
  } finally {
    await stopServer(server);
  }
});

test("checkKeyRevocation: HTTP 500 is revocation-unknown", async () => {
  const { server, base } = await startServer({
    "/.well-known/htmltrust-revocations.json": () => ({ status: 500, body: {} }),
  });
  try {
    const result = await checkKeyRevocation(`${base}/alice.json`, {
      keyResolvers: [],
      allowInsecureHttpForTesting: true,
    });
    assert.deepEqual(result, { status: "revocation-unknown", superseded: false });
  } finally {
    await stopServer(server);
  }
});

test("checkKeyRevocation: network error is revocation-unknown", async () => {
  const result = await checkKeyRevocation("https://alice.example/key.json", {
    keyResolvers: [],
    fetch: async () => {
      throw new Error("simulated network failure");
    },
  });
  assert.deepEqual(result, { status: "revocation-unknown", superseded: false });
});

test("checkKeyRevocation: a list signed by an already-revoked signer key is revocation-unknown", async () => {
  const { privateKey, pem } = generateKey();
  let doc;
  const { server, base } = await startServer({
    // The signer's own key document says it is revoked.
    "/signer.json": () => ({ body: { publicKey: pem, algorithm: "ed25519", revoked: true } }),
    "/.well-known/htmltrust-revocations.json": () => ({ body: doc }),
  });
  try {
    const signerKeyid = `${base}/signer.json`;
    const targetKeyid = `${base}/alice.json`;
    doc = signRevocationDoc(
      {
        signer: signerKeyid,
        algorithm: "ed25519",
        timestamp: "2026-06-01T00:00:00Z",
        revocations: [{ keyid: targetKeyid, status: "revoked" }],
      },
      privateKey,
    );
    const result = await checkKeyRevocation(targetKeyid, {
      keyResolvers: resolvers(),
      allowInsecureHttpForTesting: true,
    });
    assert.deepEqual(result, { status: "revocation-unknown", superseded: false });
  } finally {
    await stopServer(server);
  }
});

test("checkKeyRevocation: a directory-resolved keyid is revocation-unknown, not not-revoked", async () => {
  const { server, base } = await startServer({});
  try {
    const result = await checkKeyRevocation(`${base}/keys/abc123`, {
      keyResolvers: [],
      allowInsecureHttpForTesting: true,
      directoryBaseUrls: [base],
    });
    assert.deepEqual(result, { status: "revocation-unknown", superseded: false });
  } finally {
    await stopServer(server);
  }
});

test("checkKeyRevocation: caches within maxStalenessMs and re-fetches after it", async () => {
  let fetchCount = 0;
  const { server, base } = await startServer({
    "/.well-known/htmltrust-revocations.json": () => {
      fetchCount += 1;
      return { status: 404, body: "" };
    },
  });
  try {
    const cache = createRevocationCache();
    let now = 1_000_000;
    const opts = {
      keyResolvers: [],
      allowInsecureHttpForTesting: true,
      cache,
      now: () => now,
      maxStalenessMs: 1000,
    };
    await checkKeyRevocation(`${base}/alice.json`, opts);
    await checkKeyRevocation(`${base}/alice.json`, opts);
    assert.equal(fetchCount, 1, "second call within staleness window should use the cache");

    now += 2000;
    await checkKeyRevocation(`${base}/alice.json`, opts);
    assert.equal(fetchCount, 2, "call after staleness window should re-fetch");
  } finally {
    await stopServer(server);
  }
});

test("checkKeyRevocation: default staleness is 24 hours", () => {
  assert.equal(DEFAULT_MAX_STALENESS_MS, 24 * 60 * 60 * 1000);
});

// === verifySignedSection integration (opt-in) ===

async function buildSigned({ privateKey, body, claims, signedAt, domain, keyid, scope = "url", algorithm = "ed25519" }) {
  const allClaims = { ...claims, "signed-at": signedAt };
  const canonicalContent = canonicalizeSignedContent(body, domain);
  const contentHash = `sha256:${sha256Hex(canonicalContent)}`;
  const claimsHash = `sha256:${sha256Hex(canonicalizeClaims(allClaims))}`;
  const signingPayload = buildSigningPayloadV1({
    contentHash,
    claimsHash,
    documentURL: domain,
    scope,
    keyid,
    algorithm,
    signedAt,
  });
  const signature = signEd25519(privateKey, signingPayload);
  const metas = Object.entries(allClaims).map(([k, v]) => `<meta name="${k}" content="${v}">`).join("");
  const html = `<signed-section profile="htmltrust-signature-v1" signature-scope="${scope}" keyid="${keyid}" content-hash="${contentHash}" signature="${signature}" algorithm="${algorithm}">${metas}${body}</signed-section>`;
  return { html, contentHash };
}

test("verifySignedSection: checkRevocationList off by default leaves revocationStatus undefined", async () => {
  const { privateKey, pem } = generateKey();
  const { server, base } = await startServer({
    "/key.json": () => ({ body: { publicKey: pem, algorithm: "ed25519" } }),
  });
  try {
    const keyid = `${base}/key.json`;
    const domain = "https://example.org";
    const { html } = await buildSigned({
      privateKey,
      body: "<p>Body.</p>",
      claims: { author: "Alice" },
      signedAt: "2026-04-28T12:00:00Z",
      domain,
      keyid,
    });
    const result = await verifySignedSection(html, {
      keyResolvers: [directUrlResolver({ allowInsecureHttpForTesting: true })],
      domain,
      hash: sha256HexAsync,
    });
    assert.equal(result.valid, true, result.reason);
    assert.equal(result.revocationStatus, undefined);
    assert.equal(result.keySuperseded, undefined);
  } finally {
    await stopServer(server);
  }
});

test("verifySignedSection: checkRevocationList on, key revoked via the list fails closed", async () => {
  const { privateKey, pem } = generateKey();
  let revocationDoc;
  const { server, base } = await startServer({
    "/key.json": () => ({ body: { publicKey: pem, algorithm: "ed25519" } }),
    "/.well-known/htmltrust-revocations.json": () => ({ body: revocationDoc }),
  });
  try {
    const keyid = `${base}/key.json`;
    const domain = "https://example.org";
    const { html } = await buildSigned({
      privateKey,
      body: "<p>Body.</p>",
      claims: { author: "Alice" },
      signedAt: "2026-04-28T12:00:00Z",
      domain,
      keyid,
    });
    revocationDoc = signRevocationDoc(
      {
        signer: keyid,
        algorithm: "ed25519",
        timestamp: "2026-06-01T00:00:00Z",
        revocations: [{ keyid, status: "revoked", revokedAt: "2026-05-30T00:00:00Z" }],
      },
      privateKey,
    );
    const result = await verifySignedSection(html, {
      keyResolvers: [directUrlResolver({ allowInsecureHttpForTesting: true })],
      domain,
      hash: sha256HexAsync,
      checkRevocationList: true,
      revocationOptions: { allowInsecureHttpForTesting: true },
    });
    assert.equal(result.valid, false);
    assert.equal(result.reason, "key-revoked");
    assert.equal(result.revocationStatus, "revoked");
  } finally {
    await stopServer(server);
  }
});

test("verifySignedSection: checkRevocationList on, no list published (404) still verifies with not-revoked", async () => {
  const { privateKey, pem } = generateKey();
  const { server, base } = await startServer({
    "/key.json": () => ({ body: { publicKey: pem, algorithm: "ed25519" } }),
  });
  try {
    const keyid = `${base}/key.json`;
    const domain = "https://example.org";
    const { html } = await buildSigned({
      privateKey,
      body: "<p>Body.</p>",
      claims: { author: "Alice" },
      signedAt: "2026-04-28T12:00:00Z",
      domain,
      keyid,
    });
    const result = await verifySignedSection(html, {
      keyResolvers: [directUrlResolver({ allowInsecureHttpForTesting: true })],
      domain,
      hash: sha256HexAsync,
      checkRevocationList: true,
      revocationOptions: { allowInsecureHttpForTesting: true },
    });
    assert.equal(result.valid, true, result.reason);
    assert.equal(result.revocationStatus, "not-revoked");
  } finally {
    await stopServer(server);
  }
});

test("verifySignedSection: checkRevocationList on, unreachable list is revocation-unknown but still valid", async () => {
  const { privateKey, pem } = generateKey();
  const { server, base } = await startServer({
    "/key.json": () => ({ body: { publicKey: pem, algorithm: "ed25519" } }),
    "/.well-known/htmltrust-revocations.json": () => ({ status: 500, body: {} }),
  });
  try {
    const keyid = `${base}/key.json`;
    const domain = "https://example.org";
    const { html } = await buildSigned({
      privateKey,
      body: "<p>Body.</p>",
      claims: { author: "Alice" },
      signedAt: "2026-04-28T12:00:00Z",
      domain,
      keyid,
    });
    const result = await verifySignedSection(html, {
      keyResolvers: [directUrlResolver({ allowInsecureHttpForTesting: true })],
      domain,
      hash: sha256HexAsync,
      checkRevocationList: true,
      revocationOptions: { allowInsecureHttpForTesting: true },
    });
    assert.equal(result.valid, true, result.reason);
    assert.equal(result.revocationStatus, "revocation-unknown");
  } finally {
    await stopServer(server);
  }
});

test("verifySignedSection: checkRevocationList on, superseded key still verifies with metadata", async () => {
  const { privateKey, pem } = generateKey();
  let revocationDoc;
  const { server, base } = await startServer({
    "/key.json": () => ({ body: { publicKey: pem, algorithm: "ed25519" } }),
    "/.well-known/htmltrust-revocations.json": () => ({ body: revocationDoc }),
  });
  try {
    const keyid = `${base}/key.json`;
    const successorKeyid = `${base}/key-2027.json`;
    const domain = "https://example.org";
    const { html } = await buildSigned({
      privateKey,
      body: "<p>Body.</p>",
      claims: { author: "Alice" },
      signedAt: "2026-04-28T12:00:00Z",
      domain,
      keyid,
    });
    revocationDoc = signRevocationDoc(
      {
        signer: keyid,
        algorithm: "ed25519",
        timestamp: "2026-06-01T00:00:00Z",
        revocations: [{ keyid, status: "superseded", supersededBy: successorKeyid }],
      },
      privateKey,
    );
    const result = await verifySignedSection(html, {
      keyResolvers: [directUrlResolver({ allowInsecureHttpForTesting: true })],
      domain,
      hash: sha256HexAsync,
      checkRevocationList: true,
      revocationOptions: { allowInsecureHttpForTesting: true },
    });
    assert.equal(result.valid, true, result.reason);
    assert.equal(result.revocationStatus, "not-revoked");
    assert.equal(result.keySuperseded, true);
    assert.equal(result.supersededBy, successorKeyid);
  } finally {
    await stopServer(server);
  }
});
