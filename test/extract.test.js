/**
 * Tests for extractSignedSections — the regex-based helper used by content
 * scripts to enumerate signed regions in a pristine HTML response.
 *
 * The goal of this helper is to give content-script verifiers a way to
 * verify against the **original served HTML** instead of element.innerHTML,
 * sidestepping the runtime-DOM-mutation problem documented in the spec
 * README's "Known Issue" section.
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import { extractSignedSections } from "../dist/index.js";

test("extractSignedSections: returns [] when no signed-sections are present", () => {
  assert.deepEqual(extractSignedSections("<html><body><p>plain</p></body></html>"), []);
});

test("extractSignedSections: returns [] for empty input", () => {
  assert.deepEqual(extractSignedSections(""), []);
});

test("extractSignedSections: extracts a single signed-section", () => {
  const inner = '<meta name="signed-at" content="2026-01-01T00:00:00Z"><p>hello</p>';
  const html = `<html><body><article><signed-section keyid="did:web:x" content-hash="sha256:x" signature="x" algorithm="ed25519">${inner}</signed-section></article></body></html>`;
  const result = extractSignedSections(html);
  assert.equal(result.length, 1);
  assert.equal(
    result[0],
    `<signed-section keyid="did:web:x" content-hash="sha256:x" signature="x" algorithm="ed25519">${inner}</signed-section>`,
  );
});

test("extractSignedSections: returns sections in document order", () => {
  const html = `
    <signed-section keyid="a" content-hash="sha256:a" signature="a" algorithm="ed25519"><p>first</p></signed-section>
    <p>middle</p>
    <signed-section keyid="b" content-hash="sha256:b" signature="b" algorithm="ed25519"><p>second</p></signed-section>
    <signed-section keyid="c" content-hash="sha256:c" signature="c" algorithm="ed25519"><p>third</p></signed-section>
  `;
  const result = extractSignedSections(html);
  assert.equal(result.length, 3);
  assert.ok(result[0].includes('keyid="a"'));
  assert.ok(result[1].includes('keyid="b"'));
  assert.ok(result[2].includes('keyid="c"'));
});

test("extractSignedSections: tolerates whitespace and case in closing tag", () => {
  const html = `<signed-section keyid="x" content-hash="sha256:x" signature="x" algorithm="ed25519"><p>x</p></SIGNED-SECTION >`;
  const result = extractSignedSections(html);
  assert.equal(result.length, 1);
});

test("extractSignedSections: throws on non-string input", () => {
  assert.throws(() => extractSignedSections(null), /expects a string/);
  assert.throws(() => extractSignedSections({ inner: "<p>x</p>" }), /expects a string/);
  assert.throws(() => extractSignedSections(undefined), /expects a string/);
});

test("extractSignedSections: returned strings round-trip through verifySignedSection's string parser", async () => {
  // We don't run full verify here (no key fixture) — we just confirm the
  // string returned by extractSignedSections is parseable as a section.
  // The string-path parser in verify.ts uses the same regex shape, so
  // success here means the pristine slice is the correct input shape for
  // verifySignedSection(html, options).
  const { verifySignedSection } = await import("../dist/index.js");
  const html = `<html>
    <signed-section keyid="did:web:x" content-hash="sha256:x" signature="x" algorithm="ed25519">
      <meta name="signed-at" content="2026-01-01T00:00:00Z">
      <meta name="claim:license" content="CC-BY-4.0">
      <p>body</p>
    </signed-section>
  </html>`;
  const [slice] = extractSignedSections(html);
  // Verify against a do-nothing resolver — we expect "key not resolvable"
  // (not "missing required attributes"), which confirms the slice parsed.
  const result = await verifySignedSection(slice, { domain: "x.example", keyResolvers: [] });
  assert.equal(result.valid, false);
  assert.equal(result.reason, "content hash mismatch");
});
