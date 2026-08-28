# HTMLTrust Browser Client

- Maintainer: Jason Grey
- Updated: 2026-08-28
- Version: 0.1.2, draft v1 profile
- Status: Reference implementation
- For: browser, crawler, and integration developers
- Reading time: 5 minutes

This TypeScript package verifies HTMLTrust v1 signed sections and evaluates local trust policy. It runs in browsers and Node.js.

## Quick start

Requirements: Node.js 22 or newer and npm.

Install from a fresh clone, run the Node test suite, check types, and build the package:

```sh
git clone https://github.com/HTMLTrust/htmltrust-browser-client.git
cd htmltrust-browser-client
npm ci
npm test
npm run typecheck
npm run build
```

The build writes JavaScript, declarations, and source maps to `dist/`. The package downloads canonicalization v0.3.0 from the immutable `760593d4a02e9fffa56dc4d002eb52ab2ade1b49` revision, so this repository installs without a sibling checkout.

When developing the client alongside the browser extension or E2E harness, use
the sibling layout below. The extension uses a pinned Git dependency, while the
E2E harness uses local `file:` dependencies, so build this package before
installing either sibling:

```sh
git clone https://github.com/HTMLTrust/htmltrust-canonicalization.git ../htmltrust-canonicalization
git clone https://github.com/HTMLTrust/htmltrust-browser-reference.git ../htmltrust-browser-reference
git clone https://github.com/HTMLTrust/htmltrust-e2e.git ../htmltrust-e2e
npm ci
npm run build
```

The canonicalization checkout is only needed for the E2E harness, whose local
dependency points at `../htmltrust-canonicalization/javascript`. It is not
needed for this package's own install or tests.

To install the package directly from Git in another project:

```sh
CLIENT_REV=REPLACE_WITH_REVIEWED_FULL_SHA
npm install "git+https://github.com/HTMLTrust/htmltrust-browser-client.git#$CLIENT_REV"
```

Use a 40-character commit SHA or a release tag that you reviewed. The
`prepare` script builds `dist/` during Git installation, so consumers do not
need a generated directory committed to the repository.

## Status

Reference TypeScript implementation for browser-client verification and policy evaluation. The API is still draft-aligned and may change with the HTMLTrust specifications.

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
import {
  defaultResolverChain,
  extractSignedSections,
  verifySignedSection,
} from "@htmltrust/browser-client";

// Keep this exact slice from the HTTP response body. A DOM Element has already
// lost duplicate attributes and other source-level parser evidence.
const response = await fetch("https://example.org/article");
const [rawSignedSection] = extractSignedSections(await response.text());
const documentUrl = response.url;
const liveSignedSection = document.querySelector("signed-section");

const result = await verifySignedSection(rawSignedSection, {
  keyResolvers: defaultResolverChain(),
  origin: new URL(documentUrl).origin,
  documentUrl,
  baseUrl: documentUrl,
  // Optional: compare the signed response source with the current DOM.
  renderedSection: liveSignedSection,
  renderedBaseUrl: window.location.href,
});

// result: { valid: true, keyid, algorithm, contentHash, claims, signedAt, origin, domain, inputState }
// or:     { valid: false, reason: "content-hash-mismatch" | "signature-invalid" | "key-resolution-failed" | ... }
```

Pass the original source string for full v1 checks. An `Element` input remains available for callers that only have a DOM, but it cannot recover source ambiguities that the browser parser repaired.

### Layer 2: Trust decision (client policy)

```typescript
import { evaluateTrustPolicy } from "@htmltrust/browser-client";

// Given a verified Layer 1 result and a user trust policy:
const trust = await evaluateTrustPolicy(verifyResult, {
  personalTrustList: ["did:web:alice.example", "did:web:bob.example"],
  trustedDomains: ["https://nytimes.com", "https://www.propublica.org"],
  directorySubscriptions: [
    { url: "https://eff.org/directory", weight: 1.0, enabled: true },
    { url: "https://aclu.org/directory", weight: 0.8, enabled: false },
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

Enabled directories are queried at the normative `GET /signers/{id}/reputation`
route. The response uses the directory-specific `score` value in the 0..1
range. Network failures, timeouts, and malformed responses contribute nothing;
the cryptographic verification result remains independent of directory policy.

### Endorsement support

Endorsements are fetched from configured directories and verified locally against the structured canonical JSON endorsement payload with `signature` omitted:

```typescript
const endorsements = await fetchEndorsements(contentHash, {
  directories: ["https://directory.example"],
  keyResolvers,
});
// Each endorsement is verified locally before being returned.

const detailed = await fetchEndorsementsWithFailures(contentHash, {
  directories: ["https://directory.example"],
  keyResolvers,
});
// detailed.failures carries spec-style reasons such as "directory-unavailable".
```

## Runtime requirements

- Web standard `crypto.subtle` (SubtleCrypto) in browsers
- Node `node:crypto.webcrypto` in Node.js
- `@htmltrust/canonicalization` for text normalization and HTML text extraction
- `parse5` for browser-equivalent source parsing in Node.js

## Tests

The test suite runs with Node's built-in test runner against the compiled package:

```sh
npm test
```

`npm test` builds `dist/` first, then runs the tests in `test/`. `npm run typecheck` checks the TypeScript sources without emitting files. This repository does not currently contain Playwright tests or a browser conformance fixture suite.

## License

This project is licensed under the [PolyForm Noncommercial License 1.0.0](https://polyformproject.org/licenses/noncommercial/1.0.0). You may use, modify, and share the software for any noncommercial purpose with attribution. Commercial use requires a separate agreement with the licensor.

## Origin & Contributions

HTMLTrust is an idea I (Jason Grey) have been working on since 2024. I am an engineer with a day job and a family. AI tools have helped as research assistants, technical writers, and pair programmers. I wrote the original architectural sketches and reviewed every line.

Contributions may be human-written or AI-assisted. Open a pull request with tests or conformance evidence for the change.

What this project is **not** a forum for:

- Debates about whether AI should be used to write code or specifications.
- Opinions on who is or isn't trustworthy on the web.
- Politics, religion, professional practice, or personal philosophy.

HTMLTrust lets publishers sign content and lets readers choose which keys they trust. The project does not define who deserves trust.

If this work is useful to you and you'd like to support it, see [GitHub Sponsors](https://github.com/sponsors/jt55401) or the other channels in [`.github/FUNDING.yml`](.github/FUNDING.yml).
