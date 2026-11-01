# Solo-maintainer manual approval

The repository is maintained by `jayekwere`. Native PR reviews cannot be self-approved, so human approval is enforced through protected GitHub environments and a native required-deployment rule instead.

## Before merge

1. Open or update a PR and let `tests`, `admission` and `trusted-candidate` pass. These required checks remain pinned to the GitHub Actions integration.
2. Mark the PR ready for review. The `maintainer-approval` job waits after the full test job succeeds.
3. Inspect the diff and evidence, then use **Review deployments** on the Actions run to approve `maintainer-approval` manually.
4. GitHub records a successful approval deployment for that revision. The main ruleset requires it before merge. New commits need new approval, and superseded CI runs are canceled.

The approval job checks out no repository code, has no secrets, has only read permissions and provisions nothing. The environment allows only PR merge refs, names `jayekwere` as its only reviewer and disables administrator bypass. Its successful deployment is a native merge requirement; a fabricated check with the same name cannot replace it.

GitHub's native approving-review count is zero and mandatory code-owner review is disabled because they would lock out the sole maintainer. CODEOWNERS remains as ownership documentation. Human review is enforced by the protected deployment gate. All Terraform, OPA, scanner, adversarial, dependency, secret and trusted-base checks remain required. Force push, branch deletion, automatic merge and administrator bypass stay disabled.

## Generation and publication

On main, manually dispatch **Trusted generation and review** in sample mode with paid API authorization disabled.

- Approve `ai-generation` through **Review deployments**. The generation job writes a candidate as data.
- The separate verification job runs the complete security pipeline without repository secrets.
- Inspect its evidence and approve `pr-publication`. Only then may the workflow open a draft PR.
- Mark that generated draft ready for review to run its checks and manual merge-approval gate.

Both main-only environments keep `jayekwere` as the required human reviewer, allow that maintainer to approve runs they initiated, and disable administrator bypass. No workflow approves a deployment, merges a PR, or runs Terraform apply automatically. A paid AI request still requires the separate explicit paid-API opt-in.
