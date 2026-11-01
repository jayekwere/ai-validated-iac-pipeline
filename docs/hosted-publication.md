# Hosted publication evidence

Published publicly on 2026-11-01 as `jayekwere/ai-validated-iac-pipeline`. GitHub authentication is valid; the earlier apparent authentication failure was caused by restricted network access.

Baseline source commit: `06a71a029cb31e63b5d276f0b8f6e0f94a0f024a`.

| Hosted check | Verified result |
| --- | --- |
| [Main independent verification](https://github.com/jayekwere/ai-validated-iac-pipeline/actions/runs/41307896006) | Success |
| [Main specification admission](https://github.com/jayekwere/ai-validated-iac-pipeline/actions/runs/41307896035) | Success |
| [PR independent verification](https://github.com/jayekwere/ai-validated-iac-pipeline/actions/runs/41307953715) | Success |
| [PR specification admission](https://github.com/jayekwere/ai-validated-iac-pipeline/actions/runs/41307953669) | Success |
| [PR trusted-base candidate validation](https://github.com/jayekwere/ai-validated-iac-pipeline/actions/runs/41307953705) | Success |

The hosted main evidence artifact was downloaded and checked: all seven AWS examples passed, and all fifteen adversarial demonstrations passed. Exact run metadata, step results, commit IDs and artifact metadata are preserved under `evidence/hosted/`.

## Active repository protections

`main` requires the `tests`, `admission` and `trusted-candidate` checks, an approving code-owner review, stale approval dismissal, resolved conversations and linear history. Administrator enforcement is enabled. Force pushes, branch deletion and automatic merge are disabled.

Both `ai-generation` and `pr-publication` require a named human reviewer, prevent self-review, restrict deployments to protected branches and disable administrator bypass. Default workflow tokens are read-only and cannot approve PR reviews. Secret scanning and secret-scanning push protection are enabled.

## Reviewable workflow correction

[PR #2](https://github.com/jayekwere/ai-validated-iac-pipeline/pull/2) contains the verified storage candidate and a correction for hosted boundary introspection. The REST branch-protection endpoint requires Administration:read, which is unavailable to a least-privilege workflow token. The correction queries the matching protection rule through GraphQL, requests only read access for environment inspection, and validates the result using the same fail-closed checks. The CI job exercises this query using its actual read-only GITHUB_TOKEN. Environment setup also disables administrator bypass explicitly.

## Remaining human boundary

The initial sample-generation run stopped at the expected `ai-generation` approval gate. It was started as `jayekwere`, who is also the only configured reviewer, so GitHub correctly reported that the current account could not approve it. That run was canceled while the permissions correction was prepared.

An independent reviewer must review PR #2 before it is merged and approve the protected generation/publication jobs afterward. Another account must be designated or an already-authorized collaborator must initiate a new run so `jayekwere` can review it. The review requirement is intentionally preserved. No generation, publication-job success, paid AI invocation or merge is claimed for the canceled run.
