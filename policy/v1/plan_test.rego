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
