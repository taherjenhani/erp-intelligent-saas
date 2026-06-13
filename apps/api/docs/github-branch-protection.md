# GitHub Branch Protection

Use this checklist to make API CI mandatory for `develop` and `main`.

## Required Settings

- Require a pull request before merging.
- Require status checks to pass before merging.
- Require branches to be up to date before merging.
- Required check: `api` from `.github/workflows/api-ci.yml`.
- Require conversation resolution.
- Block force pushes.
- Block branch deletion.
- Require at least one approving review.

## Apply With GitHub CLI

Confirm the exact check name from the latest GitHub Actions run before applying protection. GitHub commonly exposes the job in this repository as `api`.

```powershell
gh api `
  --method PUT `
  repos/taherjenhani/erp-intelligent-saas/branches/develop/protection `
  --header "Accept: application/vnd.github+json" `
  --header "X-GitHub-Api-Version: 2022-11-28" `
  --input .github/branch-protection-develop.json
```

Repeat for `main` with a matching JSON file or the same body after changing the branch path.

## Verify

```powershell
gh api repos/taherjenhani/erp-intelligent-saas/branches/develop/protection
```

A merge should be blocked when the `api` workflow has not passed.
