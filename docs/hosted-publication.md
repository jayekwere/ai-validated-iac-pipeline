# Hosted verification completed

Verified on 2026-11-01 with the solo-maintainer approval flow enabled.

Repository: [jayekwere/ai-validated-iac-pipeline](https://github.com/jayekwere/ai-validated-iac-pipeline).
Approved implementation: [PR #2](https://github.com/jayekwere/ai-validated-iac-pipeline/pull/2), merged as `8592e1265b097aa3c5f9ac6c827fc7406025fea0`.
Workflow-created candidate: [draft PR #7](https://github.com/jayekwere/ai-validated-iac-pipeline/pull/7), intentionally unmerged.

| Hosted workflow or boundary | Result and evidence |
| --- | --- |
| Independent verification on main | [Passed](https://github.com/jayekwere/ai-validated-iac-pipeline/actions/runs/41311661325) |
| Specification admission | [Passed](https://github.com/jayekwere/ai-validated-iac-pipeline/actions/runs/41311317551) |
| Trusted-base candidate validation | [Passed](https://github.com/jayekwere/ai-validated-iac-pipeline/actions/runs/41311317438) |
| Manual merge approval | [Approved and passed](https://github.com/jayekwere/ai-validated-iac-pipeline/actions/runs/41311317355) |
| Trusted generation and review | [All three jobs passed](https://github.com/jayekwere/ai-validated-iac-pipeline/actions/runs/41311662869): generation, independent verification, draft publication |

The published candidate contains 12 resources and passed all 18 verification gates. Terraform SHA-256: `e3755b2fdbbfef248b5eceafa4ec9ef526601a3efb22e38152afc137aa7ca4e9`. Downloaded artifacts and the actual PR files were independently checked against the approved specification, Terraform grammar and a clean archive of the exact committed verifier source.

The pipeline tests passed: 56 TypeScript tests, 30 Python tests, three OPA tests, seven AWS examples and fifteen adversarial demonstrations. Measured TypeScript coverage is 100% of loaded source lines and 91.98% of branches. Dependency and secret checks passed. Detailed hosted jobs, approval audit entries and effective rules are in [the verification record](../evidence/hosted/solo-maintainer-verification.json).

## Human decisions and protections

The maintainer explicitly approved three separate decisions: merge of the tested implementation revision, sample generation, and publication of the verified draft PR. Those decisions were recorded using normal GitHub environment approval endpoints under `jayekwere`, with audit comments identifying the maintainer's explicit confirmations. No administrator bypass or automatically granted approval was used.

The solo-maintainer flow keeps all three required security checks, pins them to GitHub Actions, and requires a native `maintainer-approval` deployment before merge. Each approval environment names only `jayekwere`, permits that maintainer to approve their own runs, and disables administrator bypass. The merge-approval environment has no secrets or write permissions and only accepts PR merge refs. Generation and publication stay main-only. See [the approval procedure](solo-maintainer.md).

No paid AI request, live AWS verification or cloud provisioning occurred. Generation used the clearly labeled deterministic non-AI mode. Plans use supported mock providers with real provider-schema validation. PR #7 is a reviewable artifact, not permission to merge or deploy it.
