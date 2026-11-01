# Publication and protected review

The repository is now public and baseline hosted CI passed. See [the publication record](hosted-publication.md) for exact runs and the remaining independent-review requirement. The instructions below also describe setup for a fresh copy.

The local implementation can be verified without GitHub authentication. Publication, repository settings, environment protection, hosted Actions runs and actual PR URLs require authenticated access to `jayekwere/ai-validated-iac-pipeline`.

After restoring `gh auth login`, create the public repository with the MIT license source already in this checkout, push `main`, and enable Actions. Use the prepared setup script to configure the required review boundaries. Reviewers must be able to approve environment deployments and PRs. GitHub plan restrictions may affect protected environment availability; publication must stay disabled if required review controls cannot be enabled.

```sh
gh repo create jayekwere/ai-validated-iac-pipeline --public --source=. --remote=origin --push
python3 scripts/configure_github.py
```

If the repository already exists, inspect it and push a review branch rather than overwriting existing history. Configure any paid API key only as the `OPENAI_API_KEY` secret on the protected `ai-generation` environment. No secret is needed for sample generation. Do not add cloud credentials.

The workflow boundary checker requires protected `main` and reviewer-protected `ai-generation` and `pr-publication` environments. Both generation and publication are default-branch-only. `workflow_dispatch` offers a strict specification choice, sample/AI mode, and an explicit paid API authorization boolean. Sample mode never calls an AI API.

The publication job uses `src/github.ts` to verify candidate hashes, mandatory gates, the current trusted source manifest and the closed Terraform grammar before creating a draft PR. It writes only `generated/main.tf.json`, `generated/spec.json` and `generated/verification.json`. Human approval and required checks are necessary to merge. No auto-merge, privileged PR trigger or apply workflow is included.

After publication, inspect every hosted job, record the actual run URL and immutable commit SHA, download the evidence artifact, and compare its hashes with local results. Do not claim hosted success until the run has finished successfully. These remote checks remain unverified until authentication is restored.
