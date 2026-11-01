# Verified local results

Verified on 2026-10-31, America/Vancouver, using macOS arm64.

| Check | Result |
| --- | --- |
| TypeScript unit and real-tool integration tests | 56 passed |
| Python scanner and review-boundary tests | 19 passed |
| OPA policy unit tests | 3 passed |
| AWS end-to-end examples | 7 passed, 18 gates each |
| Adversarial demonstrations | 15 passed |
| Measured source line coverage | 100% |
| Measured branch coverage | 91.98% |
| Locked npm dependency audit | 0 vulnerabilities |
| Trivy dependency and secret scan | Passed, including development dependencies |
| Desktop/mobile HTML layout checks | Passed |
| Candidate workflow data handoff | Passed locally |
| Hosted Actions and remote protection | Unverified pending GitHub authentication |

Coverage measures the modules imported by the TypeScript tests. CLI entrypoints and workflow data handoff were also exercised as separate end-to-end commands. Screenshots and JSON results are in `evidence/`. Low-severity CloudTrail recommendations are disclosed in the audit and platform reports; no unaccepted high or critical IaC findings remain.

No paid AI request or cloud API verification was performed. The real AI integration and PR integration were tested using explicit mocked HTTP transports. Terraform schema validation loads the real pinned AWS provider, while infrastructure plans use its supported mock provider. No infrastructure was provisioned.
