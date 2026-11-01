# Local acceptance

1. Install exact npm dependencies with scripts disabled and bootstrap checksum-pinned tools.
2. Run `npm run verify` for static types, TypeScript coverage, Python tests and all seven full-pipeline AWS examples.
3. Run `node --experimental-strip-types scripts/adversarial.ts` after the demo to test malicious generator output, scanner integrity failures and independent plan policy mutations.
4. Run `python3 scripts/check_workflows.py` and `python3 scripts/scan_repository.py` for workflow boundaries, dependency vulnerabilities and secrets.
5. Inspect the HTML and JSON reports, exact tool logs, mock test events and policies. Every gate must pass on an approved request.

On hosts restricting local Unix sockets, Terraform's provider process needs permission to open a local communication socket. No cloud account permissions are required. A failed provider startup is a failed gate, not a skipped check.

Plan evidence comes from `terraform test -json -verbose` with a trusted `mock_provider "aws"` and `command = plan`. Provider schemas are loaded from the real pinned AWS binary. The plan's computed IDs may be unknown. Policy-critical values must be known; IAM permissions are constructed using known specification identifiers. No synthetic hand-authored plan is substituted for passing evidence.

Unit coverage is reported separately from end-to-end acceptance. GitHub API and OpenAI HTTP tests use mocked transports. A passing mock transport test is never described as a live integration result. Hosted workflow execution and actual repository protection require GitHub authentication and cannot be verified locally.
