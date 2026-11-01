# Security boundary

Treat infrastructure specifications, generated Terraform, pull requests and artifacts as untrusted. Only admitted values may enter the compiler. Security decisions belong to trusted verifier code, pinned tools, versioned policies and reviewers.

The generation vocabulary is closed. No module, data source, provisioner, backend, import, remote state, arbitrary Terraform expression, filesystem function or generated workflow is accepted. Secrets are excluded from specifications and tool subprocess environments. A generator can only return one JSON object. File bundles and paths are never accepted.

Threats covered include prompt injection, public infrastructure, broad IAM, missing encryption, unauthorized providers/modules, unsafe process execution, report HTML injection, dependency drift, unavailable scanners, missing decisions, privileged PR workflows and stale evidence substitution. Tests and reports show which layer rejects each fixture.

The local operator, host OS, repository maintainers, pinned verifier code, pinned tool release provenance and reviewed dependency locks are trusted. Source hash comparisons detect changes during a run but are not a signature or a substitute for protecting the verifier checkout. A compromised trusted compiler or malicious maintainer can defeat this system. PRs changing trusted code need human review. Run untrusted PR CI only on disposable GitHub-hosted runners with no secrets or cloud credentials. Never use a persistent self-hosted runner for untrusted PRs.

Verification uses mock-provider plans and real provider schemas. It does not contact AWS APIs or prove live-account deployability. A human must assess real identifiers, account policies, logging delivery permissions, key policy recovery, costs and operational requirements before adapting this project to a deployment process. No deployment process is included.

Dependency updates are reviewable Dependabot PRs. Tool versions and checksums change only by reviewed changes to `tools.lock.json` and the provider lock. Scanner exceptions must be exact by rule ID and resource address, explain the technical reason, and never permit missing encryption or public access.

Report vulnerabilities through a private GitHub security advisory once the repository is published. Do not include credentials or live account data in public issues.
