/**
 * Endorsement fetching/verification tests.
 *
 * Spins up two endorsement-directory fixture servers and a key-resolution
 * fixture server, returns a mix of valid + invalid + duplicate endorsements,
 * and asserts fetchEndorsements returns only the verified-unique set.
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import { fetchEndorsements, fetchEndorsementsWithFailures, directUrlResolver } from "../dist/index.js";
import { generateKey, signEd25519, startServer, stopServer } from "./_helpers.js";

function canonicalJson(value) {
  if (value === null || typeof value === "string" || typeof value === "boolean") return JSON.stringify(value);
  if (typeof value === "number") return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map((item) => canonicalJson(item)).join(",")}]`;
  const keys = Object.keys(value).filter((key) => value[key] !== undefined).sort();
  return `{${keys.map((key) => `${JSON.stringify(key)}:${canonicalJson(value[key])}`).join(",")}}`;
}

function signEndorsement(privateKey, unsigned) {
  return {
    ...unsigned,
    signature: signEd25519(privateKey, canonicalJson(unsigned)),
  };
}

test("fetchEndorsements: returns only verified, deduped", async () => {
  const { privateKey: pkA, pem: pemA } = generateKey();
  const { privateKey: pkB, pem: pemB } = generateKey();
  const { privateKey: _pkBad, pem: pemBad } = generateKey();
  void _pkBad; // unused

  // Key-resolution fixture: serves the legitimate keys at known URLs.
  const { server: keyServer, base: keyBase } = await startServer({
    "/keys/alice": () => ({ body: { publicKey: pemA, algorithm: "ed25519" } }),
    "/keys/bob": () => ({ body: { publicKey: pemB, algorithm: "ed25519" } }),
    "/keys/carol": () => ({ body: { publicKey: pemBad, algorithm: "ed25519" } }),
  });

  const contentHash = "sha256:abc123";
  const tsA = "2026-04-28T10:00:00Z";
  const tsB = "2026-04-28T11:00:00Z";

  const aliceEnd = signEndorsement(pkA, {
    endorser: `${keyBase}/keys/alice`,
    endorsement: contentHash,
    timestamp: tsA,
    algorithm: "ed25519",
    claim: "Verified original publication.",
  });

  const bobEnd = signEndorsement(pkB, {
    endorser: `${keyBase}/keys/bob`,
    endorsement: contentHash,
    timestamp: tsB,
    algorithm: "ed25519",
  });

  // Forged Carol endorsement: the resolver returns pemBad, but the signature
  // was made with pkA (a different key entirely), so it MUST NOT verify.
  const forgedEnd = signEndorsement(pkA, {
    endorser: `${keyBase}/keys/carol`,
    endorsement: contentHash,
    timestamp: tsA,
    algorithm: "ed25519",
  });

  // Two endorsement-directory servers; one returns the array shape, the
  // other returns the { endorsements: [...] } envelope shape. Alice appears
  // in both directories (dedupe target).
  const dir1Url = `/api/endorsements?content-hash=${encodeURIComponent(contentHash)}`;
  const { server: dir1, base: dir1Base } = await startServer({
    [dir1Url]: () => ({ body: [aliceEnd, forgedEnd] }),
  });
  const { server: dir2, base: dir2Base } = await startServer({
    [dir1Url]: () => ({ body: { endorsements: [aliceEnd, bobEnd] } }),
  });

  try {
    const verified = await fetchEndorsements(contentHash, {
      directories: [dir1Base, dir2Base],
      keyResolvers: [directUrlResolver({ allowInsecureHttpForTesting: true })],
      allowInsecureHttpForTesting: true,
    });

    // Alice once (deduped across directories), Bob once. Forged Carol dropped.
    assert.equal(verified.length, 2);
    const endorsers = new Set(verified.map((e) => e.endorser));
    assert.ok(endorsers.has(`${keyBase}/keys/alice`));
    assert.ok(endorsers.has(`${keyBase}/keys/bob`));
    assert.ok(!endorsers.has(`${keyBase}/keys/carol`));
  } finally {
    await stopServer(dir1);
    await stopServer(dir2);
    await stopServer(keyServer);
  }
});

test("fetchEndorsements: rejects a missing or mismatched algorithm", async () => {
  const { privateKey, pem } = generateKey();
  const { server: keyServer, base: keyBase } = await startServer({
    "/keys/alice": () => ({ body: { publicKey: pem, algorithm: "ed25519" } }),
  });
  const unsigned = {
    endorser: `${keyBase}/keys/alice`,
    endorsement: "sha256:abc123",
    timestamp: "2026-04-28T10:00:00Z",
  };
  const missing = signEndorsement(privateKey, unsigned);
  const mismatched = signEndorsement(privateKey, { ...unsigned, algorithm: "rsa-pkcs1-sha256" });
  const dirUrl = `/api/endorsements?content-hash=${encodeURIComponent(unsigned.endorsement)}`;
  const { server: directory, base: directoryBase } = await startServer({
    [dirUrl]: () => ({ body: [missing, mismatched] }),
  });

  try {
    const verified = await fetchEndorsements(unsigned.endorsement, {
      directories: [directoryBase],
      keyResolvers: [directUrlResolver({ allowInsecureHttpForTesting: true })],
      allowInsecureHttpForTesting: true,
    });
    assert.deepEqual(verified, []);
  } finally {
    await stopServer(directory);
    await stopServer(keyServer);
  }
});

test("fetchEndorsements: empty/failed directories yield empty list", async () => {
  const out = await fetchEndorsements("sha256:nope", {
    directories: ["http://127.0.0.1:1"],
    keyResolvers: [directUrlResolver({ allowInsecureHttpForTesting: true })],
  });
  assert.deepEqual(out, []);
});

test("fetchEndorsementsWithFailures: reports network policy blocks", async () => {
  const out = await fetchEndorsementsWithFailures("sha256:nope", {
    directories: ["http://example.test"],
    keyResolvers: [],
  });
  assert.deepEqual(out.endorsements, []);
  assert.equal(out.failures[0].reason, "network-policy-blocked");
});
