package iac.v1_test
import rego.v1
import data.iac.v1 as policy
test_bad_format if {not policy.decision.allow with input as {}}
test_empty if {policy.decision.allow with input as {"resource_changes":[]}}
test_public_bucket if {not policy.decision.allow with input as {"resource_changes":[{"address":"aws_s3_bucket_public_access_block.x","type":"aws_s3_bucket_public_access_block","provider_name":"registry.terraform.io/hashicorp/aws","change":{"after":{"block_public_acls":false}}}]}}
