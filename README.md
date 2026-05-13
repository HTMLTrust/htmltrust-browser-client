# HTMLTrust Browser Client

Reference implementation of the HTMLTrust client-side verification and trust policy evaluation, as a language-neutral TypeScript library that can be used in browsers, Node.js crawlers, test harnesses, and any other verifying client.

## Status

Scaffolded -- implementation pending. A working prototype of the verification logic exists as an injected script in `htmltrust-e2e/src/lib/playwright-session.ts` and should be promoted to this package.

## Why a separate library?

The HTMLTrust browser extension (`htmltrust-browser-reference`) is one possible packaging of the verification logic. Other packagings include:

- Headless crawlers (e.g., the researcher bot in the E2E simulation)
- Server-side rendering pipelines that want to verify signed content before including it
- Test harnesses that exercise the protocol
- Command-line tools for manual content verification

All of these need the same core verification and trust policy logic. This package provides it once, in a single well-tested place, and all the packagings depend on it.

## Scope

Two layers, matching the specification's two-layer verification model:

### Layer 1: Cryptographic verification (local, deterministic)

```typescript
import { verifySignedSection, resolveKeyId } from "@htmltrust/browser-client";

// Given a <signed-section> DOM element (or a parsed HTML fragment):
const result = await verifySignedSection(element, {
  // Optional resolver chain; defaults try did:web, then direct URL, then configured directories
  keyResolvers: [didWebResolver, directUrlResolver, directoryResolver(myDirectories)],
});

// result: { valid: true, keyid, algorithm, contentHash, claims, signedAt, domain }
// or:     { valid: false, reason: "content hash mismatch" | "signature invalid" | "key not resolvable" }
```

### Layer 2: Trust decision (client policy)

```typescript
import { evaluateTrustPolicy } from "@htmltrust/browser-client";

// Given a verified Layer 1 result and a user trust policy:
const trust = await evaluateTrustPolicy(verifyResult, {
  personalTrustList: ["did:web:alice.example", "did:web:bob.example"],
  trustedDomains: ["nytimes.com", "propublica.org"],
  directorySubscriptions: [
    { url: "https://eff.org/directory", weight: 1.0 },
    { url: "https://aclu.org/directory", weight: 0.8 },
  ],
  // Future: trustedEndorsers, transitiveDepth, customScoreFn
});

// trust: {
//   score: 0.87,  // 0-100 graduated trust score
//   indicator: "green",  // "red" | "yellow" | "green", computed from score + thresholds
//   inputs: [
//     { source: "personalTrustList", contribution: 0.5, rationale: "keyid is in personal trust list" },
//     { source: "directory:eff.org", contribution: 0.37, rationale: "reputation score 0.9 weighted 1.0" },
//   ],
// }
```

The `inputs` breakdown is what the UI presents on hover to explain why a given piece of content earned its score.

### Endorsement support (deferred)

Endorsement fetching and verification (§2.5) will be added once option D (role-based endorser policy) is prioritized. The API will be:

```typescript
const endorsements = await fetchEndorsements(contentHash, directories);
// Each endorsement is verified locally before being returned.
```

## Planned dependencies

- Web standard `crypto.subtle` (SubtleCrypto) in browsers
- Node `node:crypto.webcrypto` in Node.js
- `@htmltrust/canonicalization` for text normalization and HTML text extraction
- No other runtime dependencies

## Conformance

A single test suite runs against this library in:

1. Browser environment (Playwright)
2. Node environment

Both MUST produce identical verification results for every vector in a shared test fixture set.

## License

This project is licensed under the [PolyForm Noncommercial License 1.0.0](https://polyformproject.org/licenses/noncommercial/1.0.0). You may use, modify, and share the software for any noncommercial purpose with attribution. Commercial use requires a separate agreement with the licensor.
