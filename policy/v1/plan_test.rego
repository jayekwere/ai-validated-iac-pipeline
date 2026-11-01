package iac.v1_test
import rego.v1
import data.iac.v1 as policy
test_bad_format if {not policy.decision.allow with input as {}}
test_empty if {policy.decision.allow with input as {"resource_changes":[]}}
test_public_bucket if {not policy.decision.allow with input as {"resource_changes":[{"address":"aws_s3_bucket_public_access_block.x","type":"aws_s3_bucket_public_access_block","provider_name":"registry.terraform.io/hashicorp/aws","change":{"after":{"block_public_acls":false}}}]}}

iam_plan(statement) := {"resource_changes":[{"address":"aws_iam_role_policy.p","mode":"managed","type":"aws_iam_role_policy","provider_name":"registry.terraform.io/hashicorp/aws","change":{"after":{"policy":json.marshal({"Version":"2012-10-17","Statement":statement})}}}]}
finding_ids(plan) := {f.id | some f in policy.deny with input as plan}

test_wildcard_action_string_denied if {"WILDCARD_IAM" in finding_ids(iam_plan({"Effect":"Allow","Action":"*","Resource":"arn:aws:s3:::b/*"}))}
test_wildcard_action_array_denied if {"WILDCARD_IAM" in finding_ids(iam_plan([{"Effect":"Allow","Action":["s3:*"],"Resource":["arn:aws:s3:::b"]}]))}
test_wildcard_resource_string_denied if {"WILDCARD_RESOURCE" in finding_ids(iam_plan([{"Effect":"Allow","Action":"s3:GetObject","Resource":"*"}]))}
test_single_statement_object_admin_denied if {
	ids := finding_ids(iam_plan({"Effect":"Allow","Action":"*","Resource":"*"}))
	"WILDCARD_IAM" in ids
	"WILDCARD_RESOURCE" in ids
}
test_not_action_denied if {"IAM_NEGATION" in finding_ids(iam_plan([{"Effect":"Allow","NotAction":"iam:*","Resource":"arn:aws:s3:::b"}]))}
test_not_resource_denied if {"IAM_NEGATION" in finding_ids(iam_plan([{"Effect":"Allow","Action":"s3:GetObject","NotResource":"arn:aws:s3:::b"}]))}
test_deny_statement_wildcards_allowed if {count(finding_ids(iam_plan([{"Effect":"Deny","Action":"*","Resource":"*"}]))) == 0}
test_scoped_string_statement_allowed if {count(finding_ids(iam_plan({"Effect":"Allow","Action":"s3:GetObject","Resource":"arn:aws:s3:::b/k"}))) == 0}

test_null_negation_denied if {"IAM_NEGATION" in finding_ids(iam_plan({"Effect":"Allow","Action":"s3:GetObject","Resource":"arn:aws:s3:::b/k","NotAction":null}))}
test_invalid_iam_shapes_denied if {
    every stmt in [null, [], {}, "bad", {"Effect":"Allow","Action":null,"Resource":"*"}, {"Effect":"Allow","Action":[],"Resource":"arn:aws:s3:::b/k"}, {"Effect":"Allow","Action":{"wildcard":"*"},"Resource":"*"}] {
        "IAM_DOCUMENT" in finding_ids(iam_plan(stmt))
    }
}
test_invalid_iam_json_denied if {
    p := {"resource_changes":[{"type":"aws_iam_role_policy","address":"aws_iam_role_policy.x","change":{"after":{"policy":"{bad"}}}]}
    "IAM_DOCUMENT" in finding_ids(p)
}
# Missing security attributes must fail closed, matching the independent Python scanner.
plan_of(type, after) := {"resource_changes":[{"address":sprintf("%s.x",[type]),"mode":"managed","type":type,"name":"x","provider_name":"registry.terraform.io/hashicorp/aws","change":{"after":after}}]}

test_missing_public_ip_setting_denied if {"PUBLIC_COMPUTE" in finding_ids(plan_of("aws_instance", {"root_block_device":[{"encrypted":true}],"metadata_options":[{"http_tokens":"required"}]}))}
test_missing_root_device_denied if {"DISK_ENCRYPTION" in finding_ids(plan_of("aws_instance", {"associate_public_ip_address":false,"metadata_options":[{"http_tokens":"required"}]}))}
test_missing_metadata_options_denied if {"IMDS" in finding_ids(plan_of("aws_instance", {"associate_public_ip_address":false,"root_block_device":[{"encrypted":true}]}))}
test_missing_internal_flag_denied if {"PUBLIC_LB" in finding_ids(plan_of("aws_lb", {}))}
test_missing_listener_protocol_denied if {"TLS" in finding_ids(plan_of("aws_lb_listener", {"port":443}))}
test_missing_log_validation_denied if {"AUDIT" in finding_ids(plan_of("aws_cloudtrail", {}))}
test_missing_sse_algorithm_denied if {"ENCRYPTION" in finding_ids(plan_of("aws_s3_bucket_server_side_encryption_configuration", {"rule":[{"apply_server_side_encryption_by_default":[{}]}]}))}
test_unknown_after_denied if {"UNKNOWN_VALUES" in finding_ids(plan_of("aws_lb", null))}
