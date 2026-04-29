/**
 * Layer 2 unit tests. We feed evaluateTrustPolicy synthetic VerifyResults +
 * policies and assert the score and indicator. Directory reputation tests
 * use a fixture HTTP server.
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import { evaluateTrustPolicy } from "../dist/index.js";
import { startServer, stopServer } from "./_helpers.js";

function vr(partial = {}) {
  return {
    valid: true,
    keyid: "did:web:alice.example",
    algorithm: "ed25519",
    contentHash: "sha256:abc",
    claimsHash: "sha256:def",
    claims: {},
    signedAt: "2026-04-28T00:00:00Z",
    domain: "alice.example",
    ...partial,
  };
}

test("invalid signature → score 0, red, single input", async () => {
  const ev = await evaluateTrustPolicy(vr({ valid: false, reason: "signature invalid" }), {});
  assert.equal(ev.score, 0);
  assert.equal(ev.indicator, "red");
  assert.equal(ev.inputs.length, 1);
  assert.equal(ev.inputs[0].source, "crypto");
});

test("verified-but-unknown → 50, yellow", async () => {
  const ev = await evaluateTrustPolicy(vr(), {});
  assert.equal(ev.score, 50);
  assert.equal(ev.indicator, "yellow");
});

test("personal trust list adds 40 → 90, green", async () => {
  const ev = await evaluateTrustPolicy(vr(), {
    personalTrustList: ["did:web:alice.example"],
  });
  assert.equal(ev.score, 90);
  assert.equal(ev.indicator, "green");
});

test("trusted domain adds 30 → 80, green", async () => {
  const ev = await evaluateTrustPolicy(vr(), {
    trustedDomains: ["alice.example"],
  });
  assert.equal(ev.score, 80);
  assert.equal(ev.indicator, "green");
});

test("personal + domain → clamps at 100, green", async () => {
  const ev = await evaluateTrustPolicy(vr(), {
    personalTrustList: ["did:web:alice.example"],
    trustedDomains: ["alice.example"],
  });
  assert.equal(ev.score, 100);
  assert.equal(ev.indicator, "green");
});

test("custom thresholds shift the indicator boundary", async () => {
  const ev = await evaluateTrustPolicy(vr(), {
    thresholds: { warning: 40, trusted: 90 },
  });
  // baseline 50 falls between 40 and 90 → yellow
  assert.equal(ev.score, 50);
  assert.equal(ev.indicator, "yellow");
});

test("directory positive reputation adds weighted contribution", async () => {
  const { server, base } = await startServer({
    [`/keys/${encodeURIComponent("did:web:alice.example")}/reputation`]: () => ({
      body: { trustScore: 1.0, reports: 0 },
    }),
  });
  try {
    const ev = await evaluateTrustPolicy(vr(), {
      directorySubscriptions: [{ url: base, weight: 1.0 }],
    });
    // 50 + (1.0 - 0.5) * 1.0 * 40 = 70 → green
    assert.equal(ev.score, 70);
    assert.equal(ev.indicator, "green");
  } finally {
    await stopServer(server);
  }
});

test("directory negative reputation subtracts", async () => {
  const { server, base } = await startServer({
    [`/keys/${encodeURIComponent("did:web:alice.example")}/reputation`]: () => ({
      body: { trustScore: 0.0, reports: 0 },
    }),
  });
  try {
    const ev = await evaluateTrustPolicy(vr(), {
      directorySubscriptions: [{ url: base, weight: 1.0 }],
    });
    // 50 + (0.0 - 0.5) * 1.0 * 40 = 30 → yellow
    assert.equal(ev.score, 30);
    assert.equal(ev.indicator, "yellow");
  } finally {
    await stopServer(server);
  }
});

test("any directory reports → indicator forced to red (override)", async () => {
  // Even with personal-trust + trusted-domain pushing score to 100, a single
  // report flips the indicator to red.
  const { server, base } = await startServer({
    [`/keys/${encodeURIComponent("did:web:alice.example")}/reputation`]: () => ({
      body: { trustScore: 0.5, reports: 1 },
    }),
  });
  try {
    const ev = await evaluateTrustPolicy(vr(), {
      personalTrustList: ["did:web:alice.example"],
      trustedDomains: ["alice.example"],
      directorySubscriptions: [{ url: base, weight: 1.0 }],
    });
    assert.equal(ev.score, 100); // numeric score still maxed
    assert.equal(ev.indicator, "red");
    assert.ok(ev.inputs.some((i) => i.source === "directory-reports-override"));
  } finally {
    await stopServer(server);
  }
});

test("directory failure is best-effort (no contribution, no throw)", async () => {
  const ev = await evaluateTrustPolicy(vr(), {
    directorySubscriptions: [{ url: "http://127.0.0.1:1", weight: 1.0 }],
  });
  // Network failure → directory simply doesn't contribute; baseline 50 stands.
  assert.equal(ev.score, 50);
  assert.equal(ev.indicator, "yellow");
});

test("multiple directories aggregate reports for override", async () => {
  const { server: s1, base: b1 } = await startServer({
    [`/keys/${encodeURIComponent("did:web:alice.example")}/reputation`]: () => ({
      body: { trustScore: 0.8, reports: 0 },
    }),
  });
  const { server: s2, base: b2 } = await startServer({
    [`/keys/${encodeURIComponent("did:web:alice.example")}/reputation`]: () => ({
      body: { trustScore: 0.5, reports: 2 },
    }),
  });
  try {
    const ev = await evaluateTrustPolicy(vr(), {
      directorySubscriptions: [
        { url: b1, weight: 0.5 },
        { url: b2, weight: 1.0 },
      ],
    });
    // 50 + (0.8-0.5)*0.5*40 + (0.5-0.5)*1.0*40 = 56 → yellow numerically
    assert.equal(Math.round(ev.score), 56);
    // ...but reports across all directories total > 0 → red override
    assert.equal(ev.indicator, "red");
  } finally {
    await stopServer(s1);
    await stopServer(s2);
  }
});
