/**
 * Layer 2: Trust policy evaluation.
 *
 * Implements spec §3.1 (browser behavior, trust-decision layer). Given a
 * cryptographically valid Layer 1 result and a user trust policy, produces
 * a graduated 0..100 score, an indicator (red/yellow/green), and a fully
 * itemized rationale showing every input that contributed.
 *
 * The directory-reputation logic generalizes the e2e prototype's
 * single-directory model to N directories with configurable weights.
 */

import type { VerifyResult } from "./verify.js";

export interface DirectorySubscription {
  /** Base URL of the directory (e.g. "https://eff.org/directory"). */
  url: string;
  /** Multiplier applied to the directory's contribution (typically 0..1). */
  weight: number;
  /** Disabled subscriptions are retained in settings but never queried. */
  enabled?: boolean;
}

export interface TrustPolicy {
  /** Personal trust list of keyids (option A in the spec). */
  personalTrustList?: string[];
  /** Trusted publication origins (legacy option name retained). */
  trustedDomains?: string[];
  /** Trust directory subscriptions, each with a weight. */
  directorySubscriptions?: DirectorySubscription[];
  /**
   * Indicator thresholds. Score < warning → red; score >= trusted → green;
   * everything in between → yellow. Defaults: warning=20, trusted=70.
   */
  thresholds?: { warning: number; trusted: number };
  /** Optional fetch override (for tests, custom transports, etc.). */
  fetch?: typeof fetch;
  /** Maximum time to wait for one directory response. Defaults to 5 seconds. */
  directoryTimeoutMs?: number;
}

export interface TrustInput {
  source: string;
  contribution: number;
  rationale: string;
}

export interface TrustEvaluation {
  /** Graduated trust score, 0..100. */
  score: number;
  /** UI indicator derived from score + thresholds (with overrides applied). */
  indicator: "red" | "yellow" | "green";
  /** Per-input breakdown for hover/detail UI surfaces. */
  inputs: TrustInput[];
}

const DEFAULT_THRESHOLDS = { warning: 20, trusted: 70 };

interface DirectoryReputation {
  trustScore: number;
  reports: number;
}

const DEFAULT_DIRECTORY_TIMEOUT_MS = 5000;

function validScore(value: unknown): value is number {
  return typeof value === "number" && Number.isFinite(value) && value >= 0 && value <= 1;
}

async function fetchReputation(
  baseUrl: string,
  keyid: string,
  fetchImpl: typeof fetch,
  timeoutMs: number,
): Promise<DirectoryReputation | null> {
  // Best-effort: any failure (network, parsing, non-OK status) yields null
  // so the directory simply doesn't contribute. Reputation queries are an
  // optional input, never a hard dependency.
  let timer: ReturnType<typeof setTimeout> | undefined;
  try {
    const parsedBase = new URL(baseUrl.trim());
    if (
      (parsedBase.protocol !== "https:" && parsedBase.protocol !== "http:") ||
      parsedBase.username ||
      parsedBase.password ||
      parsedBase.search ||
      parsedBase.hash ||
      !parsedBase.hostname
    ) return null;
    parsedBase.pathname = `${parsedBase.pathname.replace(/\/+$/, "")}/signers/${encodeURIComponent(keyid)}/reputation`;
    const url = parsedBase.toString();
    const controller = typeof AbortController !== "undefined" ? new AbortController() : null;
    timer = setTimeout(() => controller?.abort(), timeoutMs);
    const res = await fetchImpl(url, {
        credentials: "omit",
        referrer: "",
        referrerPolicy: "no-referrer",
        redirect: "error",
        ...(controller ? { signal: controller.signal } : {}),
      });
    if (!res.ok) return null;
    const data = (await res.json()) as Partial<DirectoryReputation> & { score?: unknown };
    // The normative route uses `score`; accept the pre-v1 `trustScore` field
    // only for callers that still point at an older compatible directory.
    const trustScore = validScore(data.score) ? data.score : data.trustScore;
    if (!validScore(trustScore)) return null;
    return {
      trustScore,
      reports: typeof data.reports === "number" && Number.isFinite(data.reports) && data.reports >= 0
        ? data.reports
        : 0,
    };
  } catch {
    return null;
  } finally {
    if (timer !== undefined) clearTimeout(timer);
  }
}

function clamp(n: number, lo: number, hi: number): number {
  return Math.max(lo, Math.min(hi, n));
}

function indicatorFor(
  score: number,
  thresholds: { warning: number; trusted: number },
): "red" | "yellow" | "green" {
  if (score < thresholds.warning) return "red";
  if (score >= thresholds.trusted) return "green";
  return "yellow";
}

/**
 * Evaluate a user trust policy against a Layer 1 verify result.
 *
 * Logic:
 *   - If !verifyResult.valid → score 0, indicator red, single input.
 *   - Otherwise, start at 50 (neutral baseline for a verified-but-unknown
 *     signer), then add:
 *       +40 if keyid is in personalTrustList
 *       +30 if origin/domain is in trustedDomains
 *       For each directory subscription, GET reputation and add
 *         (trustScore - 0.5) * weight * 40 to the score.
 *   - Clamp to 0..100, map to indicator via thresholds.
 *   - If any directory reports > 0, force indicator to "red" regardless of
 *     score (override). This matches the e2e prototype's behavior: a
 *     researcher flag is a strong signal that should not be drowned out
 *     by personal-trust additions.
 */
export async function evaluateTrustPolicy(
  verifyResult: VerifyResult,
  policy: TrustPolicy,
): Promise<TrustEvaluation> {
  const thresholds = policy.thresholds ?? DEFAULT_THRESHOLDS;

  if (!verifyResult.valid) {
    return {
      score: 0,
      indicator: "red",
      inputs: [
        {
          source: "crypto",
          contribution: 0,
          rationale: `signature invalid (${verifyResult.reason ?? "unknown reason"})`,
        },
      ],
    };
  }

  const inputs: TrustInput[] = [
    { source: "crypto", contribution: 0, rationale: "signature valid" },
  ];
  let score = 50;

  if (policy.personalTrustList?.includes(verifyResult.keyid)) {
    score += 40;
    inputs.push({
      source: "personalTrustList",
      contribution: 40,
      rationale: `keyid ${verifyResult.keyid} is in personal trust list`,
    });
  }

  if (policy.trustedDomains?.includes(verifyResult.domain)) {
    score += 30;
    inputs.push({
      source: "trustedDomains",
      contribution: 30,
      rationale: `origin ${verifyResult.domain} is in trusted domain list`,
    });
  }

  // Directory reputation: query each subscribed directory in parallel,
  // collect their inputs, and aggregate the reports counter for the override.
  let totalReports = 0;
  const subs = policy.directorySubscriptions ?? [];
  if (subs.length > 0) {
    const fetchImpl = policy.fetch ?? globalThis.fetch;
    if (!fetchImpl) {
      throw new Error(
        "evaluateTrustPolicy: directorySubscriptions configured but no fetch implementation available",
      );
    }
    const timeoutMs = Number.isFinite(policy.directoryTimeoutMs) && (policy.directoryTimeoutMs ?? 0) > 0
      ? policy.directoryTimeoutMs!
      : DEFAULT_DIRECTORY_TIMEOUT_MS;
    const repPromises = subs
      .filter((sub) => sub.enabled !== false && typeof sub.url === "string" && sub.url.trim().length > 0)
      .filter((sub) => Number.isFinite(sub.weight) && sub.weight >= 0 && sub.weight <= 1)
      .map((sub) =>
      fetchReputation(sub.url, verifyResult.keyid, fetchImpl, timeoutMs).then((rep) => ({ sub, rep })),
    );
    const reps = await Promise.all(repPromises);
    for (const { sub, rep } of reps) {
      if (!rep) continue;
      const contribution = (rep.trustScore - 0.5) * sub.weight * 40;
      score += contribution;
      totalReports += rep.reports;
      inputs.push({
        source: `directory:${sub.url}`,
        contribution,
        rationale: `reputation ${rep.trustScore.toFixed(2)} weighted ${sub.weight}; ${rep.reports} report(s)`,
      });
    }
  }

  score = clamp(score, 0, 100);
  let indicator = indicatorFor(score, thresholds);

  // Override: any reports across subscribed directories force red. The
  // researcher-flagged signal outweighs personal-trust adds because the user
  // implicitly trusts the directory by subscribing to it.
  if (totalReports > 0) {
    indicator = "red";
    inputs.push({
      source: "directory-reports-override",
      contribution: 0,
      rationale: `${totalReports} report(s) across subscribed directories; indicator forced to red`,
    });
  }

  return { score, indicator, inputs };
}
