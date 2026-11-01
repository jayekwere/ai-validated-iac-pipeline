# Policy rule catalog

`policy/v1/plan.rego` evaluates the Terraform plan JSON after the generator has finished. It has no knowledge of the specification or the AI response; it sees only the planned resources. Any finding sets `decision.allow` to `false` and blocks the candidate.

Security attributes covered by these rules must be known and compliant. The rule tests cover both compliant and violating inputs, with malformed IAM documents and unknown ingress rejected explicitly. This catalog is not a claim of live AWS deployability or exhaustive Terraform plan validation. Each rule has a violating and a compliant case in `policy/v1/rules_test.rego`, and bypass regressions live in `policy/v1/plan_test.rego`. Run them with `.tools/opa test policy/v1 -v`.

The independent Python scanner (`scripts/scan.py`) uses separate code for overlapping security checks. Its checks complement OPA; they are not a one-to-one implementation of this catalog. Both gates must pass.

## Plan integrity

| Rule ID | Denies | Why |
| --- | --- | --- |
| `PLAN_FORMAT` | Input without a `resource_changes` array | Anything else is not a Terraform plan and cannot be evaluated |
| `UNKNOWN_VALUES` | A resource change whose `change.after` is absent or not an object | Unknown values cannot be checked, so they cannot be approved |
| `PROVIDER` | Any provider other than `hashicorp/aws` | Keeps generated code inside the reviewed provider surface |
| `MODULE` | Any resource address under `module.` | Modules pull in code the policy has not reviewed |

## Storage

| Rule ID | Denies | Why |
| --- | --- | --- |
| `PUBLIC_STORAGE` | An S3 public access block with any of the four controls not `true` | All four are needed to stop ACL- and policy-based exposure |
| `MISSING_ENCRYPTION` | An `aws_s3_bucket` without a matching encryption configuration | Encryption must be declared, not assumed from account defaults |
| `ENCRYPTION` | A data bucket not using `aws:kms` | Data buckets use customer-managed KMS keys |
| `LOG_ENCRYPTION` | The `logs` sink not using `AES256` | ALB and S3 access logging cannot deliver to SSE-KMS buckets; see `policy/scanner-exceptions.json` |
| `ENCRYPTION_UNKNOWN` | An encryption configuration without a `rule` array | An absent algorithm is not evidence of encryption |

## Compute

| Rule ID | Denies | Why |
| --- | --- | --- |
| `PUBLIC_COMPUTE` | An instance whose `associate_public_ip_address` is not explicitly `false` | Unset can assign a public IP in a public subnet |
| `DISK_ENCRYPTION` | A root block device not explicitly encrypted | Protects data at rest on the instance volume |
| `IMDS` | Instance metadata without `http_tokens = "required"` | IMDSv2 reduces exposure to SSRF-based credential theft |

## Network

| Rule ID | Denies | Why |
| --- | --- | --- |
| `INGRESS_UNKNOWN` | A security group without a known ingress array, object entries or string CIDR arrays | An unknown rule set cannot be approved |
| `ADMIN_INGRESS` | Security group ingress from `0.0.0.0/0` or `::/0` | Open ingress on either address family exposes the port to the internet |
| `PUBLIC_LB` | A load balancer not explicitly `internal = true` | AWS creates internet-facing load balancers when the flag is unset |
| `TLS` | A listener not using `HTTPS` | Traffic must be encrypted in transit |

## Identity

| Rule ID | Denies | Why |
| --- | --- | --- |
| `IAM_DOCUMENT` | Malformed JSON, missing or invalid statement structure, effects, actions or resources | An invalid document must not pass through undefined rule evaluation |
| `UNKNOWN_IAM` | A role policy whose document is not known at plan time | An unknown document cannot be checked for privilege |
| `WILDCARD_IAM` | An Allow statement with `*` in any action | Wildcard actions grant more than the workload needs |
| `WILDCARD_RESOURCE` | An Allow statement with `Resource = "*"` | Grants must name the resources they apply to |
| `IAM_NEGATION` | An Allow statement using `NotAction` or `NotResource` | These grant everything except the listed values |

`Statement`, `Action` and `Resource` are normalized to arrays first, because IAM accepts a single string or object as well as an array. Without that, `{"Statement": {"Effect": "Allow", "Action": "*", "Resource": "*"}}` was not evaluated.

## Audit

| Rule ID | Denies | Why |
| --- | --- | --- |
| `AUDIT` | A CloudTrail trail without log file validation | Validation detects tampering with delivered logs |

## Adding a rule

1. Add the rule to `policy/v1/plan.rego`, reading attributes with `object.get` and a `null` default so a missing value is denied.
2. Add `test_<rule>_denied` and `test_<rule>_allowed` to `policy/v1/rules_test.rego`. Run `python3 scripts/check_policy_coverage.py` to detect omissions, then execute the tests using OPA.
3. Add the equivalent check to `scripts/scan.py` and a case to `test/test_scan.py`.
4. Confirm every compliant `evidence/*/plan.json` still produces no findings.
5. Add a row to this catalog.
