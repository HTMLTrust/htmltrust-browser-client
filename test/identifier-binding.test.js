/**
 * Key identifier binding (spec §8.1/§8.2, interim implementation): closes
 * the cross-host alias residual left after the keyid-alias fix. A key
 * document (or DID document) MUST name its own canonical identifier
 * (`kid` for a URL-form keyid, `id` for did:web), and resolution MUST fail
 * on any other spelling -- www vs apex, a CDN hostname, an IP literal, a
 * did:web host case variant, and so on.
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import { checkKeyIdentifierBinding, createIdentifierBindingCache } from "../dist/index.js";
import { startServer, stopServer } from "./_helpers.js";

test("checkKeyIdentifierBinding: URL form accepted when kid equals keyid byte for byte", async () => {
  const { server, base } = await startServer({
    "/key.json": () => ({ body: { publicKey: "unused", algorithm: "ed25519", kid: `${base}/key.json` } }),
  });
  try {
    const result = await checkKeyIdentifierBinding(`${base}/key.json`, {
      allowInsecureHttpForTesting: true,
      cache: createIdentifierBindingCache(),
    });
    assert.deepEqual(result, { ok: true });
  } finally {
    await stopServer(server);
  }
});

test("checkKeyIdentifierBinding: URL form rejected when kid is missing (now REQUIRED)", async () => {
  const { server, base } = await startServer({
    "/key.json": () => ({ body: { publicKey: "unused", algorithm: "ed25519" } }),
  });
  try {
    const result = await checkKeyIdentifierBinding(`${base}/key.json`, {
      allowInsecureHttpForTesting: true,
      cache: createIdentifierBindingCache(),
    });
    assert.deepEqual(result, { ok: false, reason: "malformed-key-document" });
  } finally {
    await stopServer(server);
  }
});

test("checkKeyIdentifierBinding: URL form rejected when kid names a different spelling (host alias)", async () => {
  // The key document is reachable under an alias hostname (simulated here
  // as a different path on the same test server, standing in for a www vs
  // apex or CDN-hostname alias in a real deployment), but kid still names
  // only its own canonical identity -- so resolving under the alias must
  // fail rather than silently succeed.
  const { server, base } = await startServer({
    "/alias/key.json": () => ({ body: { publicKey: "unused", algorithm: "ed25519", kid: `${base}/key.json` } }),
  });
  try {
    const result = await checkKeyIdentifierBinding(`${base}/alias/key.json`, {
      allowInsecureHttpForTesting: true,
      cache: createIdentifierBindingCache(),
    });
    assert.deepEqual(result, { ok: false, reason: "malformed-key-document" });
  } finally {
    await stopServer(server);
  }
});

test("checkKeyIdentifierBinding: URL form rejected on a fetch failure or non-JSON body", async () => {
  const { server, base } = await startServer({
    "/key.json": () => ({ status: 500, body: {} }),
  });
  try {
    const result = await checkKeyIdentifierBinding(`${base}/key.json`, {
      allowInsecureHttpForTesting: true,
      cache: createIdentifierBindingCache(),
    });
    assert.deepEqual(result, { ok: false, reason: "malformed-key-document" });
  } finally {
    await stopServer(server);
  }
});

test("checkKeyIdentifierBinding: did:web accepted when the DID document's id equals the DID portion of keyid", async () => {
  const { server, base } = await startServer({
    "/.well-known/did.json": () => ({ body: { id: "did:web:example.com" } }),
  });
  try {
    // did:web resolution always targets https://<host>/.well-known/did.json
    // regardless of test-server port, so this test fabricates the fetch
    // rather than relying on a real "example.com" -- same technique the
    // fetch-policy test in revocation.test.js uses.
    const calls = [];
    const fetchImpl = async (url, init) => {
      calls.push(url.toString());
      const res = await fetch(`${base}/.well-known/did.json`, init);
      return res;
    };
    const result = await checkKeyIdentifierBinding("did:web:example.com", {
      fetch: fetchImpl,
      cache: createIdentifierBindingCache(),
    });
    assert.deepEqual(result, { ok: true });
    assert.equal(calls[0], "https://example.com/.well-known/did.json");
  } finally {
    await stopServer(server);
  }
});

test("checkKeyIdentifierBinding: did:web rejected on a host-case variant (id would not match byte for byte)", async () => {
  // did:web:EXAMPLE.com and did:web:example.com resolve to the identical
  // DID document (host lowercased during resolution), but the DID
  // document's own `id` can only equal one spelling. A verifier checking
  // the case-variant keyid must see a mismatch against that one true id.
  const fetchImpl = async () => new Response(JSON.stringify({ id: "did:web:example.com" }), { status: 200 });
  const result = await checkKeyIdentifierBinding("did:web:EXAMPLE.com", {
    fetch: fetchImpl,
    cache: createIdentifierBindingCache(),
  });
  assert.deepEqual(result, { ok: false, reason: "key-resolution-failed" });
});

test("checkKeyIdentifierBinding: did:web rejected when id is missing or wrong", async () => {
  const fetchImpl = async () => new Response(JSON.stringify({ notAnId: true }), { status: 200 });
  const result = await checkKeyIdentifierBinding("did:web:example.com", {
    fetch: fetchImpl,
    cache: createIdentifierBindingCache(),
  });
  assert.deepEqual(result, { ok: false, reason: "key-resolution-failed" });
});

test("checkKeyIdentifierBinding: did:web rejected on a fetch failure", async () => {
  const fetchImpl = async () => {
    throw new Error("simulated network failure");
  };
  const result = await checkKeyIdentifierBinding("did:web:example.com", {
    fetch: fetchImpl,
    cache: createIdentifierBindingCache(),
  });
  assert.deepEqual(result, { ok: false, reason: "key-resolution-failed" });
});

test("checkKeyIdentifierBinding: caches a result and does not re-fetch within maxAgeMs", async () => {
  let fetchCount = 0;
  const { server, base } = await startServer({
    "/key.json": () => {
      fetchCount += 1;
      return { body: { publicKey: "unused", algorithm: "ed25519", kid: `${base}/key.json` } };
    },
  });
  try {
    const cache = createIdentifierBindingCache();
    let now = 1_000_000;
    const opts = { allowInsecureHttpForTesting: true, cache, now: () => now, maxAgeMs: 1000 };
    await checkKeyIdentifierBinding(`${base}/key.json`, opts);
    await checkKeyIdentifierBinding(`${base}/key.json`, opts);
    assert.equal(fetchCount, 1, "second call within maxAgeMs should use the cache");
    now += 2000;
    await checkKeyIdentifierBinding(`${base}/key.json`, opts);
    assert.equal(fetchCount, 2, "call after maxAgeMs should re-fetch");
  } finally {
    await stopServer(server);
  }
});

// === Cross-host alias forms explicitly, per the third-pass brief ===

test("checkKeyIdentifierBinding: CROSS-HOST REGRESSION -- www vs apex", async () => {
  // The canonical identity is the apex host; the same key document is also
  // reachable under a www subdomain (a real deployment might have both
  // point at the same origin server or CDN). kid names only the apex
  // spelling, so resolving through the www alias must fail.
  const canonicalKeyid = "https://example.com/key.json";
  const aliasKeyid = "https://www.example.com/key.json";
  const fetchImpl = async () =>
    new Response(JSON.stringify({ publicKey: "unused", algorithm: "ed25519", kid: canonicalKeyid }), { status: 200 });

  const canonicalResult = await checkKeyIdentifierBinding(canonicalKeyid, {
    fetch: fetchImpl,
    cache: createIdentifierBindingCache(),
  });
  assert.deepEqual(canonicalResult, { ok: true });

  const aliasResult = await checkKeyIdentifierBinding(aliasKeyid, {
    fetch: fetchImpl,
    cache: createIdentifierBindingCache(),
  });
  assert.deepEqual(aliasResult, { ok: false, reason: "malformed-key-document" });
});

test("checkKeyIdentifierBinding: CROSS-HOST REGRESSION -- IP literal alias of a hostname identity", async () => {
  const canonicalKeyid = "https://keys.example/key.json";
  const aliasKeyid = "https://93.184.216.34/key.json";
  const fetchImpl = async () =>
    new Response(JSON.stringify({ publicKey: "unused", algorithm: "ed25519", kid: canonicalKeyid }), { status: 200 });

  const aliasResult = await checkKeyIdentifierBinding(aliasKeyid, {
    fetch: fetchImpl,
    cache: createIdentifierBindingCache(),
  });
  assert.deepEqual(aliasResult, { ok: false, reason: "malformed-key-document" });
});
