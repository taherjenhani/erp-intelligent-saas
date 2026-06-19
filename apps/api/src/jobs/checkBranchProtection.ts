type BranchProtectionPayload = {
  required_status_checks?: {
    strict?: boolean;
    contexts?: string[];
    checks?: Array<{ context?: string; app_id?: number | null }>;
  } | null;
  enforce_admins?: { enabled?: boolean } | null;
  required_pull_request_reviews?: {
    required_approving_review_count?: number;
    dismiss_stale_reviews?: boolean;
  } | null;
  required_conversation_resolution?: { enabled?: boolean } | null;
  allow_force_pushes?: { enabled?: boolean } | null;
  allow_deletions?: { enabled?: boolean } | null;
};

type BranchProtectionCheck = {
  ok: boolean;
  branch: string;
  failures: string[];
};

const REQUIRED_STATUS_CHECK = "api";

function protectionCheckNames(protection: BranchProtectionPayload) {
  const contexts = protection.required_status_checks?.contexts ?? [];
  const checks =
    protection.required_status_checks?.checks
      ?.map((check) => check.context)
      .filter((context): context is string => Boolean(context)) ?? [];

  return new Set([...contexts, ...checks]);
}

export function validateBranchProtection(
  branch: string,
  protection: BranchProtectionPayload
): BranchProtectionCheck {
  const failures: string[] = [];
  const checkNames = protectionCheckNames(protection);

  if (!protection.required_status_checks) {
    failures.push("required status checks are disabled");
  } else {
    if (protection.required_status_checks.strict !== true) {
      failures.push("required status checks must require up-to-date branches");
    }

    if (!checkNames.has(REQUIRED_STATUS_CHECK)) {
      failures.push(`required status check "${REQUIRED_STATUS_CHECK}" is missing`);
    }
  }

  if (!protection.required_pull_request_reviews) {
    failures.push("pull request reviews are not required");
  } else {
    if (
      (protection.required_pull_request_reviews
        .required_approving_review_count ?? 0) < 1
    ) {
      failures.push("at least one approving review is required");
    }

    if (
      protection.required_pull_request_reviews.dismiss_stale_reviews !== true
    ) {
      failures.push("stale approvals must be dismissed");
    }
  }

  if (protection.enforce_admins?.enabled !== true) {
    failures.push("admin enforcement must be enabled");
  }

  if (protection.required_conversation_resolution?.enabled !== true) {
    failures.push("conversation resolution must be required");
  }

  if (protection.allow_force_pushes?.enabled !== false) {
    failures.push("force pushes must be blocked");
  }

  if (protection.allow_deletions?.enabled !== false) {
    failures.push("branch deletion must be blocked");
  }

  return {
    ok: failures.length === 0,
    branch,
    failures,
  };
}

function requiredEnv(name: string) {
  const value = process.env[name];

  if (!value) {
    throw new Error(`${name} is required`);
  }

  return value;
}

async function fetchBranchProtection(repo: string, branch: string, token: string) {
  const response = await fetch(
    `https://api.github.com/repos/${repo}/branches/${branch}/protection`,
    {
      headers: {
        accept: "application/vnd.github+json",
        authorization: `Bearer ${token}`,
        "x-github-api-version": "2022-11-28",
      },
    }
  );

  if (!response.ok) {
    throw new Error(
      `GitHub branch protection read failed for ${branch}: HTTP ${response.status}`
    );
  }

  return (await response.json()) as BranchProtectionPayload;
}

async function main() {
  const repo = process.env.BRANCH_PROTECTION_REPOSITORY ??
    process.env.GITHUB_REPOSITORY ??
    "taherjenhani/erp-intelligent-saas";
  const token = process.env.GH_TOKEN ?? process.env.GITHUB_TOKEN;
  const branches = (
    process.env.BRANCH_PROTECTION_BRANCHES ?? "develop,main"
  )
    .split(",")
    .map((branch) => branch.trim())
    .filter(Boolean);

  if (!token) {
    console.error(
      [
        "GH_TOKEN or GITHUB_TOKEN is required to verify remote branch protection.",
        "",
        "Example:",
        "$env:GH_TOKEN='<github-token-with-repo-admin-read>'",
        "npm run github:branch-protection:check",
      ].join("\n")
    );
    process.exitCode = 2;
    return;
  }

  const results: BranchProtectionCheck[] = [];

  for (const branch of branches) {
    const protection = await fetchBranchProtection(repo, branch, token);
    results.push(validateBranchProtection(branch, protection));
  }

  console.log(JSON.stringify({ repo, results }, null, 2));

  if (results.some((result) => !result.ok)) {
    process.exitCode = 1;
  }
}

if (require.main === module) {
  main().catch((error) => {
    console.error(error);
    process.exitCode = 1;
  });
}
