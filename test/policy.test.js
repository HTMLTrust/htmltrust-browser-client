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
    domain: "https://alice.example",
    origin: "https://alice.example",
    inputState: "rendered-match",
    ...partial,
  };
}

test("invalid signature → score 0, red, single input", async () => {
  const ev = await evaluateTrustPolicy(vr({ valid: false, reason: "signature-invalid" }), {});
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
    trustedDomains: ["https://alice.example"],
  });
  assert.equal(ev.score, 80);
  assert.equal(ev.indicator, "green");
});

test("personal + domain → clamps at 100, green", async () => {
  const ev = await evaluateTrustPolicy(vr(), {
    personalTrustList: ["did:web:alice.example"],
    trustedDomains: ["https://alice.example"],
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
    [`/signers/${encodeURIComponent("did:web:alice.example")}/reputation`]: () => ({
      body: { score: 1.0 },
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
    [`/signers/${encodeURIComponent("did:web:alice.example")}/reputation`]: () => ({
      body: { score: 0.0 },
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
    [`/signers/${encodeURIComponent("did:web:alice.example")}/reputation`]: () => ({
      body: { score: 0.5, reports: 1 },
    }),
  });
  try {
    const ev = await evaluateTrustPolicy(vr(), {
      personalTrustList: ["did:web:alice.example"],
      trustedDomains: ["https://alice.example"],
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
    [`/signers/${encodeURIComponent("did:web:alice.example")}/reputation`]: () => ({
      body: { score: 0.8 },
    }),
  });
  const { server: s2, base: b2 } = await startServer({
    [`/signers/${encodeURIComponent("did:web:alice.example")}/reputation`]: () => ({
      body: { score: 0.5, reports: 2 },
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

test("conflicting directory scores are kept as separate weighted inputs", async () => {
  const calls = [];
  const ev = await evaluateTrustPolicy(vr(), {
    directorySubscriptions: [
      { url: "https://directory-a.example", weight: 1 },
      { url: "https://directory-b.example", weight: 1 },
    ],
    fetch: async (url) => {
      calls.push(String(url));
      const score = String(url).includes("directory-a") ? 1 : 0;
      return new Response(JSON.stringify({ score }), { status: 200 });
    },
  });
  assert.equal(ev.score, 50);
  assert.equal(ev.inputs.filter((input) => input.source.startsWith("directory:")).length, 2);
  assert.equal(calls.length, 2);
});

test("disabled and malformed subscriptions are not queried", async () => {
  const calls = [];
  const ev = await evaluateTrustPolicy(vr(), {
    directorySubscriptions: [
      { url: "https://disabled.example", weight: 1, enabled: false },
      { url: "https://malformed.example", weight: Number.NaN },
      { url: "https://overweight.example", weight: 1.01 },
      { url: "file:///local/directory", weight: 1 },
    ],
    fetch: async (url) => {
      calls.push(String(url));
      return new Response(JSON.stringify({ score: 1 }), { status: 200 });
    },
  });
  assert.equal(ev.score, 50);
  assert.deepEqual(calls, []);
});

test("normative score response with malformed score contributes nothing", async () => {
  const ev = await evaluateTrustPolicy(vr(), {
    directorySubscriptions: [{ url: "https://directory.example", weight: 1 }],
    fetch: async () => new Response(JSON.stringify({ score: "high" }), { status: 200 }),
  });
  assert.equal(ev.score, 50);
  assert.equal(ev.indicator, "yellow");
});

test("directory timeout is best-effort", async () => {
  const ev = await evaluateTrustPolicy(vr(), {
    directorySubscriptions: [{ url: "https://slow.example", weight: 1 }],
    directoryTimeoutMs: 5,
    fetch: async (_url, init) => new Promise((_resolve, reject) => {
      init.signal.addEventListener("abort", () => reject(new Error("aborted")), { once: true });
    }),
  });
  assert.equal(ev.score, 50);
  assert.equal(ev.indicator, "yellow");
});

test("directory timeout covers a response whose JSON body stalls", async () => {
  let aborted = false;
  const ev = await evaluateTrustPolicy(vr(), {
    directorySubscriptions: [{ url: "https://slow-json.example", weight: 1 }],
    directoryTimeoutMs: 5,
    fetch: async (_url, init) => ({
      ok: true,
      json: () => new Promise((_resolve, reject) => {
        init.signal.addEventListener("abort", () => {
          aborted = true;
          reject(new Error("aborted while parsing JSON"));
        }, { once: true });
      }),
    }),
  });
  assert.equal(aborted, true);
  assert.equal(ev.score, 50);
  assert.equal(ev.indicator, "yellow");
});

test("directory route construction preserves a path prefix and rejects query or fragment bases", async () => {
  const calls = [];
  const ev = await evaluateTrustPolicy(vr(), {
    directorySubscriptions: [
      { url: "https://directory.example/prefix/", weight: 1 },
      { url: "https://directory.example/query?tenant=one", weight: 1 },
      { url: "https://directory.example/fragment#tenant", weight: 1 },
    ],
    fetch: async (url) => {
      calls.push(String(url));
      return new Response(JSON.stringify({ score: 1 }), { status: 200 });
    },
  });
  assert.equal(ev.score, 70);
  assert.deepEqual(calls, [
    "https://directory.example/prefix/signers/did%3Aweb%3Aalice.example/reputation",
  ]);
});
