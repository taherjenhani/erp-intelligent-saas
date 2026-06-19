# GitHub branch protection runbook

This runbook makes the API CI protection operationally verifiable for `develop`
and `main`.

## Required controls

- Require a pull request before merging.
- Require status checks before merging.
- Require branches to be up to date.
- Required status check: `api`.
- Dismiss stale approvals.
- Require at least one approving review.
- Require conversation resolution.
- Enforce the rule for administrators.
- Block force pushes.
- Block branch deletion.
- Block direct pushes to protected branches.

The repository can store the expected policy, but only GitHub can enforce the
remote branch state. Treat this as a semi-automated control.

## Files

- `.github/branch-protection-develop.json`
- `.github/branch-protection-main.json`
- `.github/workflows/api-ci.yml`

The workflow name is `API CI`; the required job context is `api`.

## Apply protection with GitHub CLI

PowerShell:

```powershell
gh api `
  --method PUT `
  repos/taherjenhani/erp-intelligent-saas/branches/develop/protection `
  --header "Accept: application/vnd.github+json" `
  --header "X-GitHub-Api-Version: 2022-11-28" `
  --input .github/branch-protection-develop.json

gh api `
  --method PUT `
  repos/taherjenhani/erp-intelligent-saas/branches/main/protection `
  --header "Accept: application/vnd.github+json" `
  --header "X-GitHub-Api-Version: 2022-11-28" `
  --input .github/branch-protection-main.json
```

Bash:

```bash
gh api \
  --method PUT \
  repos/taherjenhani/erp-intelligent-saas/branches/develop/protection \
  --header "Accept: application/vnd.github+json" \
  --header "X-GitHub-Api-Version: 2022-11-28" \
  --input .github/branch-protection-develop.json

gh api \
  --method PUT \
  repos/taherjenhani/erp-intelligent-saas/branches/main/protection \
  --header "Accept: application/vnd.github+json" \
  --header "X-GitHub-Api-Version: 2022-11-28" \
  --input .github/branch-protection-main.json
```

## Verify remote state

Read raw GitHub state:

```powershell
gh api repos/taherjenhani/erp-intelligent-saas/branches/develop/protection
gh api repos/taherjenhani/erp-intelligent-saas/branches/main/protection
```

Run the repository verifier:

```powershell
$env:GH_TOKEN="<github-token-with-repo-admin-read>"
npm run github:branch-protection:check
```

Expected proof:

```json
{
  "repo": "taherjenhani/erp-intelligent-saas",
  "results": [
    { "branch": "develop", "ok": true, "failures": [] },
    { "branch": "main", "ok": true, "failures": [] }
  ]
}
```

## Manual validation

1. Create a test branch.
2. Open a pull request to `develop`.
3. Confirm GitHub blocks merge until `api` passes.
4. Try a direct push to `develop` with a non-admin account.
5. Confirm GitHub rejects the push.
6. Repeat the policy check for `main`.

## Failure handling

If `npm run github:branch-protection:check` fails:

- Check whether the required status context is exactly `api`.
- Confirm the latest GitHub Actions run uses job id `api`.
- Reapply the JSON policy.
- Rerun the check.

Do not accept production changes while branch protection is missing or direct
push remains possible.
