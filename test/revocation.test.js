/**
 * Publisher-served revocation list (spec §9.5-9.9): fetch outcomes, both
 * per-key states, caching, keyid-alias immunity, and the
 * verifySignedSection opt-in integration.
 *
 * Route handlers below are written as closures over `let` variables that
 * are assigned right after `startServer` resolves (once `base` is known),
 * not at server-construction time: requests only arrive after that point,
 * so this avoids needing to guess a server's randomly-assigned port ahead
 * of building the signed fixtures whose content references it.
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import {
  checkKeyRevocation,
  createRevocationCache,
  revocationListOrigin,
  canonicalKeyidForm,
  keyidHasForbiddenUrlSyntax,
  spkiHash,
  DEFAULT_MAX_STALENESS_MS,
  UNKNOWN_RETRY_MS,
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

/** Independent SHA-256 SPKI-DER hash, computed without going through the module under test. */
function nodeSpkiHash(publicKey) {
  const der = publicKey.export({ type: "spki", format: "der" });
  return createHash("sha256").update(der).digest("base64").replace(/=+$/, "");
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

test("revocationListOrigin: a DID method other than did:web has no derivable origin", () => {
  // did:key and similar have no HTTPS origin at all; there is nothing to
  // consult, not an "unknown" fetch outcome for a fetch never attempted.
  assert.equal(revocationListOrigin("did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK"), null);
});

test("revocationListOrigin: a directory-hosted keyid derives an origin exactly like a direct URL keyid", () => {
  // The verifier already disclosed the key to this origin via GET
  // /keys/{id}, and the directory already controls this key's own
  // `revoked` field, so a revocation list there carries no additional
  // authority. No special-casing: same rule as any other HTTPS keyid.
  assert.equal(
    revocationListOrigin("https://directory.example/keys/abc123"),
    "https://directory.example",
  );
});

// === Canonical keyid comparison form (spec §8.5) ===

test("canonicalKeyidForm: URL aliases (dot-segments, host case, default port) collapse to one form", () => {
  const canonical = canonicalKeyidForm("https://keys.example/alice-2024.json");
  assert.equal(canonicalKeyidForm("https://keys.example/./alice-2024.json"), canonical);
  assert.equal(canonicalKeyidForm("https://keys.example/x/../alice-2024.json"), canonical);
  assert.equal(canonicalKeyidForm("https://KEYS.EXAMPLE/alice-2024.json"), canonical);
  assert.equal(canonicalKeyidForm("https://keys.example:443/alice-2024.json"), canonical);
});

test("canonicalKeyidForm: strips a URL keyid's fragment", () => {
  assert.equal(
    canonicalKeyidForm("https://keys.example/alice.json#x"),
    canonicalKeyidForm("https://keys.example/alice.json"),
  );
});

test("canonicalKeyidForm: lowercases a did:web host but preserves path and fragment verbatim", () => {
  assert.equal(canonicalKeyidForm("did:web:EXAMPLE.com"), "did:web:example.com");
  assert.equal(
    canonicalKeyidForm("did:web:EXAMPLE.com#Key-1"),
    "did:web:example.com#Key-1",
    "a did:web fragment selects a verification method and must not be case-folded away",
  );
  assert.equal(
    canonicalKeyidForm("did:web:EXAMPLE.com:Path:Segment"),
    "did:web:example.com:Path:Segment",
    "did:web path segments are not host components and are preserved verbatim",
  );
});

// === keyid syntax restriction (spec §5.1) ===

test("keyidHasForbiddenUrlSyntax: rejects a query or fragment on a URL-form keyid", () => {
  assert.equal(keyidHasForbiddenUrlSyntax("https://keys.example/alice.json?"), true);
  assert.equal(keyidHasForbiddenUrlSyntax("https://keys.example/alice.json?x=1"), true);
  assert.equal(keyidHasForbiddenUrlSyntax("https://keys.example/alice.json#x"), true);
});

test("keyidHasForbiddenUrlSyntax: does not flag a plain URL keyid or any did:web keyid", () => {
  assert.equal(keyidHasForbiddenUrlSyntax("https://keys.example/alice.json"), false);
  assert.equal(keyidHasForbiddenUrlSyntax("did:web:example.com"), false);
  assert.equal(
    keyidHasForbiddenUrlSyntax("did:web:example.com#key-1"),
    false,
    "a did:web fragment selects a verification method and is normal, not forbidden",
  );
});

// === publicKeyHash (spec §9.6) ===

test("spkiHash: two different keys hash differently; the same key hashes the same way twice", async () => {
  const a = generateKey();
  const b = generateKey();
  const hashA1 = await spkiHash(a.pem);
  const hashA2 = await spkiHash(a.pem);
  const hashB = await spkiHash(b.pem);
  assert.equal(hashA1, hashA2);
  assert.notEqual(hashA1, hashB);
  assert.equal(hashA1, nodeSpkiHash(a.publicKey), "must match an independent computation");
});

// === Fetch semantics (spec §9.9) ===

test("checkKeyRevocation: HTTP 404 is not-revoked", async () => {
  const { server, base } = await startServer({});
  try {
    // Resolved key is irrelevant here: a 404 short-circuits before any hash
    // comparison is attempted.
    const result = await checkKeyRevocation(`${base}/alice.json`, { publicKeyPem: "unused" }, {
      keyResolvers: [],
      allowInsecureHttpForTesting: true,
    });
    assert.deepEqual(result, { status: "not-revoked", superseded: false });
  } finally {
    await stopServer(server);
  }
});

test("checkKeyRevocation: matches a revoked entry by publicKeyHash, not by keyid text", async () => {
  const { privateKey, pem } = generateKey();
  const { pem: targetPem, publicKey: targetPublicKey } = generateKey();
  const targetHash = nodeSpkiHash(targetPublicKey);
  let doc;
  const { server, base } = await startServer({
    "/signer.json": () => ({ body: { publicKey: pem, algorithm: "ed25519" } }),
    "/.well-known/htmltrust-revocations.json": () => ({ body: doc }),
  });
  try {
    const signerKeyid = `${base}/signer.json`;
    const entryKeyid = `${base}/alice-2024.json`;
    doc = signRevocationDoc(
      {
        signer: signerKeyid,
        algorithm: "ed25519",
        timestamp: "2026-06-01T00:00:00Z",
        revocations: [{ keyid: entryKeyid, status: "revoked", revokedAt: "2026-05-30T00:00:00Z", publicKeyHash: targetHash }],
      },
      privateKey,
    );
    const result = await checkKeyRevocation(entryKeyid, { publicKeyPem: targetPem }, {
      keyResolvers: resolvers(),
      allowInsecureHttpForTesting: true,
    });
    assert.deepEqual(result, { status: "revoked", superseded: false, revokedAt: "2026-05-30T00:00:00Z" });
  } finally {
    await stopServer(server);
  }
});

test("checkKeyRevocation: KEYID-ALIAS REGRESSION -- a differently-spelled keyid resolving to the SAME key material is still revoked", async () => {
  // This is the exact attack the adversarial review ran: a revocation list
  // names one keyid spelling; a signature carries a different, differently
  // resolved-through-URL-normalization spelling of the identical resource.
  // The fix must catch this by key material regardless of which spelling
  // reaches checkKeyRevocation.
  const { privateKey, pem } = generateKey();
  const { pem: targetPem, publicKey: targetPublicKey } = generateKey();
  const targetHash = nodeSpkiHash(targetPublicKey);
  let doc;
  const { server, base } = await startServer({
    "/signer.json": () => ({ body: { publicKey: pem, algorithm: "ed25519" } }),
    "/.well-known/htmltrust-revocations.json": () => ({ body: doc }),
  });
  try {
    const signerKeyid = `${base}/signer.json`;
    const canonicalEntryKeyid = `${base}/alice-2024.json`;
    doc = signRevocationDoc(
      {
        signer: signerKeyid,
        algorithm: "ed25519",
        timestamp: "2026-06-01T00:00:00Z",
        revocations: [{ keyid: canonicalEntryKeyid, status: "revoked", publicKeyHash: targetHash }],
      },
      privateKey,
    );
    // A dot-segment alias of canonicalEntryKeyid: a different literal
    // string, same resolved resource under the URL Standard.
    const aliasKeyid = `${base}/./alice-2024.json`;
    assert.notEqual(aliasKeyid, canonicalEntryKeyid, "must actually be a different literal string");
    const result = await checkKeyRevocation(aliasKeyid, { publicKeyPem: targetPem }, {
      keyResolvers: resolvers(),
      allowInsecureHttpForTesting: true,
    });
    assert.equal(result.status, "revoked", "hash-based matching must catch the alias regardless of the keyid string checked");
  } finally {
    await stopServer(server);
  }
});

test("checkKeyRevocation: a publicKeyHash mismatch does not fall back to a false-positive keyid match", async () => {
  const { privateKey, pem } = generateKey();
  const { pem: targetPem } = generateKey();
  const { publicKey: unrelatedPublicKey } = generateKey();
  let doc;
  const { server, base } = await startServer({
    "/signer.json": () => ({ body: { publicKey: pem, algorithm: "ed25519" } }),
    "/.well-known/htmltrust-revocations.json": () => ({ body: doc }),
  });
  try {
    const signerKeyid = `${base}/signer.json`;
    const entryKeyid = `${base}/alice-2024.json`;
    // The entry's keyid textually matches what will be checked, but its
    // publicKeyHash names a DIFFERENT key than the one that actually
    // resolved. The primary match must win: this must NOT be revoked.
    doc = signRevocationDoc(
      {
        signer: signerKeyid,
        algorithm: "ed25519",
        timestamp: "2026-06-01T00:00:00Z",
        revocations: [{ keyid: entryKeyid, status: "revoked", publicKeyHash: nodeSpkiHash(unrelatedPublicKey) }],
      },
      privateKey,
    );
    const result = await checkKeyRevocation(entryKeyid, { publicKeyPem: targetPem }, {
      keyResolvers: resolvers(),
      allowInsecureHttpForTesting: true,
    });
    assert.deepEqual(result, { status: "not-revoked", superseded: false });
  } finally {
    await stopServer(server);
  }
});

test("checkKeyRevocation: a revoked entry omitting publicKeyHash still matches by canonical keyid (secondary match)", async () => {
  const { privateKey, pem } = generateKey();
  const { pem: targetPem } = generateKey();
  let doc;
  const { server, base } = await startServer({
    "/signer.json": () => ({ body: { publicKey: pem, algorithm: "ed25519" } }),
    "/.well-known/htmltrust-revocations.json": () => ({ body: doc }),
  });
  try {
    const signerKeyid = `${base}/signer.json`;
    const entryKeyid = `${base}/alice-2024.json`;
    doc = signRevocationDoc(
      {
        signer: signerKeyid,
        algorithm: "ed25519",
        timestamp: "2026-06-01T00:00:00Z",
        revocations: [{ keyid: entryKeyid, status: "revoked" }],
      },
      privateKey,
    );
    const result = await checkKeyRevocation(entryKeyid, { publicKeyPem: targetPem }, {
      keyResolvers: resolvers(),
      allowInsecureHttpForTesting: true,
    });
    assert.equal(result.status, "revoked");
  } finally {
    await stopServer(server);
  }
});

test("checkKeyRevocation: an entry naming a different keyid does not revoke this one", async () => {
  const { privateKey, pem } = generateKey();
  const { pem: targetPem } = generateKey();
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
    const result = await checkKeyRevocation(`${base}/alice.json`, { publicKeyPem: targetPem }, {
      keyResolvers: resolvers(),
      allowInsecureHttpForTesting: true,
    });
    assert.deepEqual(result, { status: "not-revoked", superseded: false });
  } finally {
    await stopServer(server);
  }
});

test("checkKeyRevocation: superseded entry matched by canonical keyid is not-revoked, with supersession as metadata", async () => {
  const { privateKey, pem } = generateKey();
  const { pem: targetPem } = generateKey();
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
    const result = await checkKeyRevocation(targetKeyid, { publicKeyPem: targetPem }, {
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

test("checkKeyRevocation: superseded entry matched by publicKeyHash when present", async () => {
  const { privateKey, pem } = generateKey();
  const { pem: targetPem, publicKey: targetPublicKey } = generateKey();
  const targetHash = nodeSpkiHash(targetPublicKey);
  let doc;
  const { server, base } = await startServer({
    "/signer.json": () => ({ body: { publicKey: pem, algorithm: "ed25519" } }),
    "/.well-known/htmltrust-revocations.json": () => ({ body: doc }),
  });
  try {
    const signerKeyid = `${base}/signer.json`;
    const successorKeyid = `${base}/alice-2026.json`;
    // A completely different keyid string from the one being checked, so
    // only the publicKeyHash match can find this entry.
    doc = signRevocationDoc(
      {
        signer: signerKeyid,
        algorithm: "ed25519",
        timestamp: "2026-06-01T00:00:00Z",
        revocations: [{ keyid: `${base}/some-other-spelling.json`, status: "superseded", supersededBy: successorKeyid, publicKeyHash: targetHash }],
      },
      privateKey,
    );
    const result = await checkKeyRevocation(`${base}/alice-2025.json`, { publicKeyPem: targetPem }, {
      keyResolvers: resolvers(),
      allowInsecureHttpForTesting: true,
    });
    assert.deepEqual(result, { status: "not-revoked", superseded: true, supersededBy: successorKeyid });
  } finally {
    await stopServer(server);
  }
});

test("checkKeyRevocation: key absent from an otherwise-valid list is not-revoked", async () => {
  const { privateKey, pem } = generateKey();
  const { pem: targetPem } = generateKey();
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
    const result = await checkKeyRevocation(`${base}/someone-else.json`, { publicKeyPem: targetPem }, {
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
  const { pem: targetPem } = generateKey();
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
    const result = await checkKeyRevocation(targetKeyid, { publicKeyPem: targetPem }, {
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
    const result = await checkKeyRevocation(`${base}/alice.json`, { publicKeyPem: "unused" }, {
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
    const result = await checkKeyRevocation(`${base}/alice.json`, { publicKeyPem: "unused" }, {
      keyResolvers: [],
      allowInsecureHttpForTesting: true,
    });
    assert.deepEqual(result, { status: "revocation-unknown", superseded: false });
  } finally {
    await stopServer(server);
  }
});

test("checkKeyRevocation: network error is revocation-unknown", async () => {
  // Isolated cache: the default module-level cache is shared across this
  // whole test file, and a fixed hostname like this one is exactly the
  // kind of key other tests could otherwise collide on.
  const result = await checkKeyRevocation("https://alice.example/key.json", { publicKeyPem: "unused" }, {
    keyResolvers: [],
    cache: createRevocationCache(),
    fetch: async () => {
      throw new Error("simulated network failure");
    },
  });
  assert.deepEqual(result, { status: "revocation-unknown", superseded: false });
});

test("checkKeyRevocation: a list signed by an already-revoked signer key is revocation-unknown", async () => {
  const { privateKey, pem } = generateKey();
  const { pem: targetPem } = generateKey();
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
    const result = await checkKeyRevocation(targetKeyid, { publicKeyPem: targetPem }, {
      keyResolvers: resolvers(),
      allowInsecureHttpForTesting: true,
    });
    assert.deepEqual(result, { status: "revocation-unknown", superseded: false });
  } finally {
    await stopServer(server);
  }
});

test("checkKeyRevocation: a directory-resolved keyid is checked against its own origin like any other URL keyid", async () => {
  const { server, base } = await startServer({});
  try {
    const result = await checkKeyRevocation(`${base}/keys/abc123`, { publicKeyPem: "unused" }, {
      keyResolvers: [],
      allowInsecureHttpForTesting: true,
    });
    // No revocation list published at the directory's origin: not-revoked,
    // exactly as a 404 means for a direct-URL keyid.
    assert.deepEqual(result, { status: "not-revoked", superseded: false });
  } finally {
    await stopServer(server);
  }
});

test("checkKeyRevocation: a keyid with no derivable origin returns undefined, not revocation-unknown", async () => {
  const result = await checkKeyRevocation(
    "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK",
    { publicKeyPem: "unused" },
    { keyResolvers: [] },
  );
  assert.equal(result, undefined);
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
    await checkKeyRevocation(`${base}/alice.json`, { publicKeyPem: "unused" }, opts);
    await checkKeyRevocation(`${base}/alice.json`, { publicKeyPem: "unused" }, opts);
    assert.equal(fetchCount, 1, "second call within staleness window should use the cache");

    now += 2000;
    await checkKeyRevocation(`${base}/alice.json`, { publicKeyPem: "unused" }, opts);
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

test("verifySignedSection: checkRevocationList on, key revoked via the list (by publicKeyHash) fails closed", async () => {
  // Signer and target are deliberately different keys: a list whose signer
  // is also the entry it revokes is itself rejected (spec §9.6) and would
  // not exercise this path.
  const { privateKey, pem } = generateKey();
  const { privateKey: signerPrivateKey, pem: signerPem } = generateKey();
  let revocationDoc;
  const { server, base } = await startServer({
    "/key.json": () => ({ body: { publicKey: pem, algorithm: "ed25519" } }),
    "/signer.json": () => ({ body: { publicKey: signerPem, algorithm: "ed25519" } }),
    "/.well-known/htmltrust-revocations.json": () => ({ body: revocationDoc }),
  });
  try {
    const keyid = `${base}/key.json`;
    const signerKeyid = `${base}/signer.json`;
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
        signer: signerKeyid,
        algorithm: "ed25519",
        timestamp: "2026-06-01T00:00:00Z",
        revocations: [{ keyid, status: "revoked", revokedAt: "2026-05-30T00:00:00Z", publicKeyHash: await spkiHash(pem) }],
      },
      signerPrivateKey,
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

test("verifySignedSection: KEYID-ALIAS REGRESSION -- a section signed with the SAME key but an aliased dot-segment keyid still fails closed", async () => {
  const { privateKey, pem } = generateKey();
  const { privateKey: signerPrivateKey, pem: signerPem } = generateKey();
  let revocationDoc;
  const { server, base } = await startServer({
    "/key.json": () => ({ body: { publicKey: pem, algorithm: "ed25519" } }),
    "/signer.json": () => ({ body: { publicKey: signerPem, algorithm: "ed25519" } }),
    "/.well-known/htmltrust-revocations.json": () => ({ body: revocationDoc }),
  });
  try {
    const canonicalKeyid = `${base}/key.json`;
    const signerKeyid = `${base}/signer.json`;
    // A dot-segment alias: a different literal keyid string that the URL
    // Standard resolves to the identical key document.
    const aliasKeyid = `${base}/./key.json`;
    assert.notEqual(aliasKeyid, canonicalKeyid);
    const domain = "https://example.org";
    const { html } = await buildSigned({
      privateKey,
      body: "<p>Body.</p>",
      claims: { author: "Alice" },
      signedAt: "2026-04-28T12:00:00Z",
      domain,
      keyid: aliasKeyid,
    });
    // The revocation list names only the canonical spelling.
    revocationDoc = signRevocationDoc(
      {
        signer: signerKeyid,
        algorithm: "ed25519",
        timestamp: "2026-06-01T00:00:00Z",
        revocations: [{ keyid: canonicalKeyid, status: "revoked", publicKeyHash: await spkiHash(pem) }],
      },
      signerPrivateKey,
    );
    const result = await verifySignedSection(html, {
      keyResolvers: [directUrlResolver({ allowInsecureHttpForTesting: true })],
      domain,
      hash: sha256HexAsync,
      checkRevocationList: true,
      revocationOptions: { allowInsecureHttpForTesting: true },
    });
    assert.equal(result.valid, false, "hash-based matching must catch this even though the signed section used a differently-spelled keyid");
    assert.equal(result.reason, "key-revoked");
    assert.equal(result.revocationStatus, "revoked");
  } finally {
    await stopServer(server);
  }
});

test("verifySignedSection: a URL keyid carrying a query component is rejected before resolution (spec §5.1)", async () => {
  const { privateKey } = generateKey();
  const domain = "https://example.org";
  const keyid = "https://keys.example/alice.json?x=1";
  const { html } = await buildSigned({
    privateKey,
    body: "<p>Body.</p>",
    claims: { author: "Alice" },
    signedAt: "2026-04-28T12:00:00Z",
    domain,
    keyid,
  });
  let resolverCalled = false;
  const result = await verifySignedSection(html, {
    keyResolvers: [{ resolve: async () => { resolverCalled = true; return null; } }],
    domain,
    hash: sha256HexAsync,
  });
  assert.equal(result.valid, false);
  assert.equal(result.reason, "key-resolution-failed");
  assert.equal(resolverCalled, false, "resolution must not even be attempted");
});

test("verifySignedSection: a did:web keyid carrying a fragment is still accepted (fragment selects a verification method)", async () => {
  const domain = "https://example.org";
  const keyid = "did:web:example.com#key-1";
  const { privateKey } = generateKey();
  const { html } = await buildSigned({
    privateKey,
    body: "<p>Body.</p>",
    claims: { author: "Alice" },
    signedAt: "2026-04-28T12:00:00Z",
    domain,
    keyid,
  });
  let resolvedKeyid = null;
  const result = await verifySignedSection(html, {
    keyResolvers: [{ resolve: async (candidate) => { resolvedKeyid = candidate; return null; } }],
    domain,
    hash: sha256HexAsync,
  });
  assert.equal(resolvedKeyid, keyid, "resolution must still be attempted for a did:web fragment");
  assert.equal(result.reason, "key-resolution-failed");
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
  // The old (superseded) key signs the content under test; the new
  // (successor) key signs the revocation list -- a superseded key MUST
  // NOT sign new content, so the list itself has to come from the
  // successor, not from the key it is marking superseded.
  const { privateKey, pem } = generateKey();
  const { privateKey: successorPrivateKey, pem: successorPem } = generateKey();
  let revocationDoc;
  const { server, base } = await startServer({
    "/key.json": () => ({ body: { publicKey: pem, algorithm: "ed25519" } }),
    "/key-2027.json": () => ({ body: { publicKey: successorPem, algorithm: "ed25519" } }),
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
        signer: successorKeyid,
        algorithm: "ed25519",
        timestamp: "2026-06-01T00:00:00Z",
        revocations: [{ keyid, status: "superseded", supersededBy: successorKeyid }],
      },
      successorPrivateKey,
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

// === DEFECT 2: signer MUST be the same identity as the list (§9.5-derived origin) ===

test("checkKeyRevocation: CROSS-ORIGIN SIGNER REGRESSION -- a list naming a signer at a different origin is revocation-unknown", async () => {
  const { privateKey: hostileSignerKey, pem: hostileSignerPem } = generateKey();
  const { pem: targetPem } = generateKey();
  let hostileFetched = false;
  // Origin B: hosts a key document for a "signer" whose keyid claims to be
  // at this origin, but the list under test is served from origin A.
  const originB = await startServer({
    "/signer.json": () => {
      hostileFetched = true;
      return { body: { publicKey: hostileSignerPem, algorithm: "ed25519" } };
    },
  });
  let doc;
  // Origin A: serves the revocation list itself, naming a signer keyid
  // that actually points at origin B.
  const originA = await startServer({
    "/.well-known/htmltrust-revocations.json": () => ({ body: doc }),
  });
  try {
    const hostileSignerKeyid = `${originB.base}/signer.json`;
    const targetKeyid = `${originA.base}/alice.json`;
    doc = signRevocationDoc(
      {
        signer: hostileSignerKeyid,
        algorithm: "ed25519",
        timestamp: "2026-06-01T00:00:00Z",
        revocations: [{ keyid: targetKeyid, status: "revoked" }],
      },
      hostileSignerKey,
    );
    const result = await checkKeyRevocation(targetKeyid, { publicKeyPem: targetPem }, {
      keyResolvers: resolvers(),
      allowInsecureHttpForTesting: true,
    });
    assert.deepEqual(result, { status: "revocation-unknown", superseded: false });
    assert.equal(hostileFetched, false, "the cross-origin signer URL must never be fetched at all");
  } finally {
    await stopServer(originA.server);
    await stopServer(originB.server);
  }
});

test("checkKeyRevocation: a same-origin signer (the ordinary case) is accepted", async () => {
  const { privateKey, pem } = generateKey();
  const { pem: targetPem } = generateKey();
  let doc;
  const { server, base } = await startServer({
    "/signer.json": () => ({ body: { publicKey: pem, algorithm: "ed25519" } }),
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
    const result = await checkKeyRevocation(targetKeyid, { publicKeyPem: targetPem }, {
      keyResolvers: resolvers(),
      allowInsecureHttpForTesting: true,
    });
    assert.equal(result.status, "revoked");
  } finally {
    await stopServer(server);
  }
});

// === DEFECT 3: Cache-Control honored; a maximum staleness CEILING, not a fixed TTL; "unknown" gets a short backoff, not the full ceiling ===

test("checkKeyRevocation: Cache-Control max-age shorter than the staleness cap is honored", async () => {
  let fetchCount = 0;
  const { server, base } = await startServer({
    "/.well-known/htmltrust-revocations.json": () => {
      fetchCount += 1;
      return { status: 404, body: "", headers: { "cache-control": "max-age=1" } };
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
      maxStalenessMs: DEFAULT_MAX_STALENESS_MS, // the cap is generous; max-age=1s should still govern
    };
    await checkKeyRevocation(`${base}/alice.json`, { publicKeyPem: "unused" }, opts);
    now += 500; // well under the 24h cap, but past max-age=1s (1000ms)
    await checkKeyRevocation(`${base}/alice.json`, { publicKeyPem: "unused" }, opts);
    assert.equal(fetchCount, 1, "still within the 1-second max-age window");
    now += 1000;
    await checkKeyRevocation(`${base}/alice.json`, { publicKeyPem: "unused" }, opts);
    assert.equal(fetchCount, 2, "max-age=1 expired; must re-fetch despite the much longer staleness cap");
  } finally {
    await stopServer(server);
  }
});

test("checkKeyRevocation: Cache-Control no-store forces revalidation on the very next call", async () => {
  let fetchCount = 0;
  const { server, base } = await startServer({
    "/.well-known/htmltrust-revocations.json": () => {
      fetchCount += 1;
      return { status: 404, body: "", headers: { "cache-control": "no-store" } };
    },
  });
  try {
    const cache = createRevocationCache();
    const opts = { keyResolvers: [], allowInsecureHttpForTesting: true, cache };
    await checkKeyRevocation(`${base}/alice.json`, { publicKeyPem: "unused" }, opts);
    await checkKeyRevocation(`${base}/alice.json`, { publicKeyPem: "unused" }, opts);
    assert.equal(fetchCount, 2, "no-store must not be cached at all");
  } finally {
    await stopServer(server);
  }
});

test("checkKeyRevocation: a revocation-unknown outcome is not pinned for the full staleness cap, only a short backoff", async () => {
  let fetchCount = 0;
  const { server, base } = await startServer({
    "/.well-known/htmltrust-revocations.json": () => {
      fetchCount += 1;
      return { status: 500, body: {} };
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
      maxStalenessMs: DEFAULT_MAX_STALENESS_MS,
    };
    const first = await checkKeyRevocation(`${base}/alice.json`, { publicKeyPem: "unused" }, opts);
    assert.equal(first.status, "revocation-unknown");
    now += UNKNOWN_RETRY_MS - 1;
    await checkKeyRevocation(`${base}/alice.json`, { publicKeyPem: "unused" }, opts);
    assert.equal(fetchCount, 1, "still within the short backoff window");
    now += 2; // past UNKNOWN_RETRY_MS
    await checkKeyRevocation(`${base}/alice.json`, { publicKeyPem: "unused" }, opts);
    assert.equal(fetchCount, 2, "an unknown outcome must self-heal quickly, not sit for the full 24h cap");
  } finally {
    await stopServer(server);
  }
});

// === Minors ===

test("checkKeyRevocation: a revoked entry wins over a superseded entry for the same key, regardless of array order", async () => {
  const { privateKey, pem } = generateKey();
  const { pem: targetPem, publicKey: targetPublicKey } = generateKey();
  const targetHash = nodeSpkiHash(targetPublicKey);
  let doc;
  const { server, base } = await startServer({
    "/signer.json": () => ({ body: { publicKey: pem, algorithm: "ed25519" } }),
    "/.well-known/htmltrust-revocations.json": () => ({ body: doc }),
  });
  try {
    const signerKeyid = `${base}/signer.json`;
    const targetKeyid = `${base}/alice.json`;
    // The superseded entry for this exact key is listed FIRST; a naive
    // last-wins or first-wins scan must not let it suppress the revoked
    // entry that follows it.
    doc = signRevocationDoc(
      {
        signer: signerKeyid,
        algorithm: "ed25519",
        timestamp: "2026-06-01T00:00:00Z",
        revocations: [
          { keyid: targetKeyid, status: "superseded", supersededBy: `${base}/successor.json`, publicKeyHash: targetHash },
          { keyid: targetKeyid, status: "revoked", publicKeyHash: targetHash },
        ],
      },
      privateKey,
    );
    const result = await checkKeyRevocation(targetKeyid, { publicKeyPem: targetPem }, {
      keyResolvers: resolvers(),
      allowInsecureHttpForTesting: true,
    });
    assert.equal(result.status, "revoked", "a revoked entry for this key must win regardless of array order");
  } finally {
    await stopServer(server);
  }
});

test("checkKeyRevocation: a signer listed revoked within its own list (list content, not the key document) is rejected", async () => {
  const { privateKey, pem } = generateKey();
  let doc;
  const { server, base } = await startServer({
    // The signer's own key document is fine -- not revoked.
    "/signer.json": () => ({ body: { publicKey: pem, algorithm: "ed25519" } }),
    "/.well-known/htmltrust-revocations.json": () => ({ body: doc }),
  });
  try {
    const signerKeyid = `${base}/signer.json`;
    // The list's own content claims its signer is revoked (matched here by
    // keyid, exercising the secondary self-listing check).
    doc = signRevocationDoc(
      {
        signer: signerKeyid,
        algorithm: "ed25519",
        timestamp: "2026-06-01T00:00:00Z",
        revocations: [{ keyid: signerKeyid, status: "revoked" }],
      },
      privateKey,
    );
    const result = await checkKeyRevocation(`${base}/someone-else.json`, { publicKeyPem: pem }, {
      keyResolvers: resolvers(),
      allowInsecureHttpForTesting: true,
    });
    assert.equal(result.status, "revocation-unknown", "a self-contradictory list must not be applied at all");
  } finally {
    await stopServer(server);
  }
});

test("checkKeyRevocation: a signer listed superseded within its own list is rejected (a superseded key MUST NOT sign new content)", async () => {
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
        revocations: [{ keyid: signerKeyid, status: "superseded", supersededBy: `${base}/newer.json` }],
      },
      privateKey,
    );
    const result = await checkKeyRevocation(`${base}/someone-else.json`, { publicKeyPem: pem }, {
      keyResolvers: resolvers(),
      allowInsecureHttpForTesting: true,
    });
    assert.equal(result.status, "revocation-unknown");
  } finally {
    await stopServer(server);
  }
});

test("checkKeyRevocation: a malformed entry anywhere in the document invalidates the whole list (fail closed, not skip)", async () => {
  const { privateKey, pem } = generateKey();
  const { pem: targetPem } = generateKey();
  let doc;
  const { server, base } = await startServer({
    "/signer.json": () => ({ body: { publicKey: pem, algorithm: "ed25519" } }),
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
        revocations: [
          { keyid: targetKeyid, status: "revoked" },
          // A malformed entry: status is not one of the two valid values.
          { keyid: `${base}/malformed.json`, status: "not-a-real-status" },
        ],
      },
      privateKey,
    );
    const result = await checkKeyRevocation(targetKeyid, { publicKeyPem: targetPem }, {
      keyResolvers: resolvers(),
      allowInsecureHttpForTesting: true,
    });
    assert.equal(
      result.status,
      "revocation-unknown",
      "a malformed entry elsewhere in the document must invalidate the whole list, not just be skipped",
    );
  } finally {
    await stopServer(server);
  }
});

test("checkKeyRevocation: an entry with an unrecognized extra field is NOT malformed (extensibility)", async () => {
  const { privateKey, pem } = generateKey();
  const { pem: targetPem, publicKey: targetPublicKey } = generateKey();
  const targetHash = nodeSpkiHash(targetPublicKey);
  let doc;
  const { server, base } = await startServer({
    "/signer.json": () => ({ body: { publicKey: pem, algorithm: "ed25519" } }),
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
        revocations: [
          {
            keyid: targetKeyid,
            status: "revoked",
            publicKeyHash: targetHash,
            // A hypothetical future field this verifier does not
            // recognize. Must be tolerated, not treated as malformed.
            fromPeriod: 3,
          },
        ],
      },
      privateKey,
    );
    const result = await checkKeyRevocation(targetKeyid, { publicKeyPem: targetPem }, {
      keyResolvers: resolvers(),
      allowInsecureHttpForTesting: true,
    });
    assert.equal(result.status, "revoked", "an entry with an unrecognized extra field must still be applied normally");
  } finally {
    await stopServer(server);
  }
});

test("checkKeyRevocation: the fetch carries no credentials, no referrer, and disallows redirects", async () => {
  let capturedInit;
  const fetchImpl = async (url, init) => {
    capturedInit = init;
    return new Response("", { status: 404 });
  };
  await checkKeyRevocation("https://alice.example/key.json", { publicKeyPem: "unused" }, {
    keyResolvers: [],
    cache: createRevocationCache(),
    fetch: fetchImpl,
  });
  assert.ok(capturedInit, "the fetch must actually have been invoked");
  assert.equal(capturedInit.credentials, "omit");
  assert.equal(capturedInit.referrerPolicy, "no-referrer");
  assert.equal(capturedInit.redirect, "error");
});
