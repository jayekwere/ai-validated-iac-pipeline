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

`main` requires the `tests`, `admission` and `trusted-candidate` checks, a successful protected `maintainer-approval` deployment, resolved conversations and linear history. Administrator enforcement is enabled. Force pushes, branch deletion and automatic merge are disabled.

`ai-generation` and `pr-publication` require the sole human maintainer, allow that maintainer to approve their own runs, restrict execution to protected branches and disable administrator bypass. The secret-free `maintainer-approval` environment is restricted to PR merge refs. Default workflow tokens are read-only. GitHub’s combined create/approve-PR repository switch is enabled because it is required for draft PR creation, while only the protected publication job receives pull-request write access. An automated status cannot satisfy the required protected human approval deployment. Action execution is restricted to GitHub-owned actions pinned to immutable commits. An active main ruleset pins required checks to the GitHub Actions integration and has no bypass actors. Secret scanning and secret-scanning push protection are enabled.

## Reviewable workflow correction

[PR #2](https://github.com/jayekwere/ai-validated-iac-pipeline/pull/2) contains the verified storage candidate and a correction for hosted boundary introspection. The REST branch-protection endpoint requires Administration:read, which is unavailable to a least-privilege workflow token. The correction uses the effective active branch-rules API, which needs only repository metadata read access, and validates protected manual approval, required check sources and history controls. The ruleset has no bypass actors; the administrative setup verifies that configuration. The runtime API does not reveal bypass actors to read-only callers, so that administrative assertion belongs to setup rather than the runtime checker. The CI job exercises this query using its actual read-only GITHUB_TOKEN. Environment setup also disables administrator bypass explicitly. Human transition of a generated draft PR to ready-for-review triggers all required checks, including for drafts created with GITHUB_TOKEN.

## Solo-maintainer update

The maintainer explicitly selected a solo approval flow. The prior independent-review requirement is superseded by [protected manual deployment approval](solo-maintainer.md). All security checks remain required, and no approval is performed by automation. The old generation run was canceled; a new run will exercise generation, independent verification and publication after the reviewed workflow correction reaches main.
