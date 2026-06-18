import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";
import "../test/setup-env";

import { validateBranchProtection } from "./checkBranchProtection";

test("branch protection validation accepts the required API CI policy", () => {
  const result = validateBranchProtection("develop", {
    required_status_checks: {
      strict: true,
      contexts: ["api"],
    },
    enforce_admins: {
      enabled: true,
    },
    required_pull_request_reviews: {
      required_approving_review_count: 1,
      dismiss_stale_reviews: true,
    },
    required_conversation_resolution: {
      enabled: true,
    },
    allow_force_pushes: {
      enabled: false,
    },
    allow_deletions: {
      enabled: false,
    },
  });

  assert.equal(result.ok, true);
  assert.deepEqual(result.failures, []);
});

test("branch protection validation rejects missing required controls", () => {
  const result = validateBranchProtection("develop", {
    required_status_checks: {
      strict: false,
      contexts: ["lint"],
    },
    enforce_admins: {
      enabled: false,
    },
    required_pull_request_reviews: {
      required_approving_review_count: 0,
      dismiss_stale_reviews: false,
    },
    required_conversation_resolution: {
      enabled: false,
    },
    allow_force_pushes: {
      enabled: true,
    },
    allow_deletions: {
      enabled: true,
    },
  });

  assert.equal(result.ok, false);
  assert.match(
    result.failures.join("\n"),
    /required status check "api" is missing/
  );
  assert.match(result.failures.join("\n"), /force pushes must be blocked/);
  assert.match(result.failures.join("\n"), /branch deletion must be blocked/);
});

test("branch protection runbook documents apply and verify commands", () => {
  const runbook = readFileSync(
    "docs/runbooks/github-branch-protection.md",
    "utf8"
  );

  assert.match(runbook, /branches\/develop\/protection/);
  assert.match(runbook, /branches\/main\/protection/);
  assert.match(runbook, /npm run github:branch-protection:check/);
  assert.match(runbook, /direct push/i);
});
