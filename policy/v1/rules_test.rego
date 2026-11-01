package iac.v1_rules_test

# One violating and one compliant case per rule ID. Each test asserts the
# specific finding ID, so a rule that stops firing (or fires on safe input)
# fails here even when another rule happens to deny the same plan.

import data.iac.v1 as policy
import rego.v1

aws := "registry.terraform.io/hashicorp/aws"

rc(type, name, after) := {
	"address": sprintf("%s.%s", [type, name]),
	"mode": "managed",
	"type": type,
	"name": name,
	"provider_name": aws,
	"change": {"after": after},
}

ids(changes) := {f.id | some f in policy.deny with input as {"resource_changes": changes}}

kms_sse := {"rule": [{"apply_server_side_encryption_by_default": [{"sse_algorithm": "aws:kms"}]}]}

aes_sse := {"rule": [{"apply_server_side_encryption_by_default": [{"sse_algorithm": "AES256"}]}]}

secure_instance := {
	"associate_public_ip_address": false,
	"root_block_device": [{"encrypted": true}],
	"metadata_options": [{"http_tokens": "required"}],
}

scoped_policy := json.marshal({"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Action": ["s3:GetObject"], "Resource": ["arn:aws:s3:::b/*"]}]})

# PLAN_FORMAT
test_plan_format_denied if {
	f := {f.id | some f in policy.deny with input as {"resource_changes": "nope"}}
	"PLAN_FORMAT" in f
}

test_plan_format_allowed if not "PLAN_FORMAT" in ids([])

# PROVIDER
test_provider_denied if "PROVIDER" in ids([object.union(rc("aws_lb", "x", {"internal": true}), {"provider_name": "registry.terraform.io/hashicorp/random"})])

test_provider_allowed if not "PROVIDER" in ids([rc("aws_lb", "x", {"internal": true})])

# PUBLIC_STORAGE
pab(v) := {k: v | some k in ["block_public_acls", "block_public_policy", "ignore_public_acls", "restrict_public_buckets"]}

test_public_storage_denied if "PUBLIC_STORAGE" in ids([rc("aws_s3_bucket_public_access_block", "x", object.union(pab(true), {"restrict_public_buckets": false}))])

test_public_storage_missing_key_denied if "PUBLIC_STORAGE" in ids([rc("aws_s3_bucket_public_access_block", "x", {"block_public_acls": true})])

test_public_storage_allowed if not "PUBLIC_STORAGE" in ids([rc("aws_s3_bucket_public_access_block", "x", pab(true))])

# MISSING_ENCRYPTION
test_missing_encryption_denied if "MISSING_ENCRYPTION" in ids([rc("aws_s3_bucket", "data", {})])

test_missing_encryption_allowed if not "MISSING_ENCRYPTION" in ids([
	rc("aws_s3_bucket", "data", {}),
	rc("aws_s3_bucket_server_side_encryption_configuration", "data", kms_sse),
])

# ENCRYPTION
test_encryption_denied if "ENCRYPTION" in ids([rc("aws_s3_bucket_server_side_encryption_configuration", "data", aes_sse)])

test_encryption_allowed if not "ENCRYPTION" in ids([rc("aws_s3_bucket_server_side_encryption_configuration", "data", kms_sse)])

# LOG_ENCRYPTION (the log sink is the one bucket that must use SSE-S3)
test_log_encryption_denied if "LOG_ENCRYPTION" in ids([rc("aws_s3_bucket_server_side_encryption_configuration", "logs", kms_sse)])

test_log_encryption_allowed if {
	found := ids([rc("aws_s3_bucket_server_side_encryption_configuration", "logs", aes_sse)])
	not "LOG_ENCRYPTION" in found
	not "ENCRYPTION" in found
}

# ENCRYPTION_UNKNOWN
test_encryption_unknown_denied if "ENCRYPTION_UNKNOWN" in ids([rc("aws_s3_bucket_server_side_encryption_configuration", "data", {})])

test_encryption_unknown_allowed if not "ENCRYPTION_UNKNOWN" in ids([rc("aws_s3_bucket_server_side_encryption_configuration", "data", kms_sse)])

# PUBLIC_COMPUTE
test_public_compute_denied if "PUBLIC_COMPUTE" in ids([rc("aws_instance", "x", object.union(secure_instance, {"associate_public_ip_address": true}))])

test_public_compute_allowed if not "PUBLIC_COMPUTE" in ids([rc("aws_instance", "x", secure_instance)])

# DISK_ENCRYPTION
test_disk_encryption_denied if "DISK_ENCRYPTION" in ids([rc("aws_instance", "x", object.union(secure_instance, {"root_block_device": [{"encrypted": false}]}))])

test_disk_encryption_allowed if not "DISK_ENCRYPTION" in ids([rc("aws_instance", "x", secure_instance)])

# IMDS
test_imds_denied if "IMDS" in ids([rc("aws_instance", "x", object.union(secure_instance, {"metadata_options": [{"http_tokens": "optional"}]}))])

test_imds_allowed if not "IMDS" in ids([rc("aws_instance", "x", secure_instance)])

# ADMIN_INGRESS
test_admin_ingress_denied if "ADMIN_INGRESS" in ids([rc("aws_security_group", "x", {"ingress": [{"from_port": 22, "cidr_blocks": ["0.0.0.0/0"]}]})])

test_admin_ingress_ipv6_denied if "ADMIN_INGRESS" in ids([rc("aws_security_group", "x", {"ingress": [{"from_port": 22, "ipv6_cidr_blocks": ["::/0"]}]})])

test_admin_ingress_dual_stack_denied if "ADMIN_INGRESS" in ids([rc("aws_security_group", "x", {"ingress": [{"from_port": 22, "cidr_blocks": ["10.42.0.0/16"], "ipv6_cidr_blocks": ["::/0"]}]})])

test_admin_ingress_private_ipv6_allowed if not "ADMIN_INGRESS" in ids([rc("aws_security_group", "x", {"ingress": [{"from_port": 443, "ipv6_cidr_blocks": ["fd00::/8"]}]})])

test_admin_ingress_allowed if not "ADMIN_INGRESS" in ids([rc("aws_security_group", "x", {"ingress": [{"from_port": 443, "cidr_blocks": ["10.42.0.0/16"]}]})])

# WILDCARD_IAM
test_wildcard_iam_denied if "WILDCARD_IAM" in ids([rc("aws_iam_role_policy", "x", {"policy": json.marshal({"Statement": [{"Effect": "Allow", "Action": ["ec2:*"], "Resource": ["arn:aws:ec2:::i"]}]})})])

test_wildcard_iam_allowed if not "WILDCARD_IAM" in ids([rc("aws_iam_role_policy", "x", {"policy": scoped_policy})])

# WILDCARD_RESOURCE
test_wildcard_resource_denied if "WILDCARD_RESOURCE" in ids([rc("aws_iam_role_policy", "x", {"policy": json.marshal({"Statement": [{"Effect": "Allow", "Action": ["s3:GetObject"], "Resource": ["*"]}]})})])

test_wildcard_resource_allowed if not "WILDCARD_RESOURCE" in ids([rc("aws_iam_role_policy", "x", {"policy": scoped_policy})])

# UNKNOWN_IAM
test_unknown_iam_denied if "UNKNOWN_IAM" in ids([rc("aws_iam_role_policy", "x", {})])

test_unknown_iam_allowed if not "UNKNOWN_IAM" in ids([rc("aws_iam_role_policy", "x", {"policy": scoped_policy})])

# IAM_NEGATION
test_iam_negation_denied if "IAM_NEGATION" in ids([rc("aws_iam_role_policy", "x", {"policy": json.marshal({"Statement": [{"Effect": "Allow", "NotAction": ["iam:*"], "Resource": ["arn:aws:s3:::b"]}]})})])

test_iam_negation_allowed if not "IAM_NEGATION" in ids([rc("aws_iam_role_policy", "x", {"policy": scoped_policy})])

# PUBLIC_LB
test_public_lb_denied if "PUBLIC_LB" in ids([rc("aws_lb", "x", {"internal": false})])

test_public_lb_allowed if not "PUBLIC_LB" in ids([rc("aws_lb", "x", {"internal": true})])

# TLS
test_tls_denied if "TLS" in ids([rc("aws_lb_listener", "x", {"protocol": "HTTP", "port": 80})])

test_tls_allowed if not "TLS" in ids([rc("aws_lb_listener", "x", {"protocol": "HTTPS", "port": 443})])

# AUDIT
test_audit_denied if "AUDIT" in ids([rc("aws_cloudtrail", "x", {"enable_log_file_validation": false})])

test_audit_allowed if not "AUDIT" in ids([rc("aws_cloudtrail", "x", {"enable_log_file_validation": true})])

# MODULE
test_module_denied if "MODULE" in ids([object.union(rc("aws_lb", "x", {"internal": true}), {"address": "module.net.aws_lb.x"})])

test_module_allowed if not "MODULE" in ids([rc("aws_lb", "x", {"internal": true})])

# A complete compliant plan produces no findings at all.
test_compliant_plan_allowed if {
	policy.decision.allow with input as {"resource_changes": [
		rc("aws_s3_bucket", "data", {}),
		rc("aws_s3_bucket_server_side_encryption_configuration", "data", kms_sse),
		rc("aws_s3_bucket_public_access_block", "data", pab(true)),
		rc("aws_instance", "app", secure_instance),
		rc("aws_security_group", "app", {"ingress": [{"from_port": 443, "cidr_blocks": ["10.42.0.0/16"]}]}),
		rc("aws_iam_role_policy", "app", {"policy": scoped_policy}),
		rc("aws_lb", "app", {"internal": true}),
		rc("aws_lb_listener", "app", {"protocol": "HTTPS", "port": 443}),
		rc("aws_cloudtrail", "audit", {"enable_log_file_validation": true}),
	]}
}

test_unknown_values_denied if "UNKNOWN_VALUES" in ids([rc("aws_lb","x",null)])
test_unknown_values_allowed if not "UNKNOWN_VALUES" in ids([rc("aws_lb","x",{"internal":true})])
test_iam_document_denied if "IAM_DOCUMENT" in ids([rc("aws_iam_role_policy","x",{"policy":"{bad"})])
test_iam_document_allowed if not "IAM_DOCUMENT" in ids([rc("aws_iam_role_policy","x",{"policy":scoped_policy})])
test_ingress_unknown_denied if "INGRESS_UNKNOWN" in ids([rc("aws_security_group","x",{})])
test_ingress_unknown_allowed if not "INGRESS_UNKNOWN" in ids([rc("aws_security_group","x",{"ingress":[]})])

test_open_ipv4_cannot_hide_behind_null_ipv6 if "ADMIN_INGRESS" in ids([rc("aws_security_group","x",{"ingress":[{"cidr_blocks":["0.0.0.0/0"],"ipv6_cidr_blocks":null}]})])
test_open_ipv6_cannot_hide_behind_null_ipv4 if "ADMIN_INGRESS" in ids([rc("aws_security_group","x",{"ingress":[{"cidr_blocks":null,"ipv6_cidr_blocks":["::/0"]}]})])
test_malformed_address_family_denied if "INGRESS_UNKNOWN" in ids([rc("aws_security_group","x",{"ingress":[{"cidr_blocks":null}]})])

test_null_ingress_entry_denied if "INGRESS_UNKNOWN" in ids([rc("aws_security_group","x",{"ingress":[null]})])
test_unknown_cidr_denied if "INGRESS_UNKNOWN" in ids([rc("aws_security_group","x",{"ingress":[{"cidr_blocks":[null]}]})])
