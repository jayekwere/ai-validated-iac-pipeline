mock_provider "aws" {}
run "secure_plan" {
  command = plan
  assert {
    condition = aws_s3_bucket_public_access_block.logs.block_public_acls && aws_s3_bucket_public_access_block.logs.block_public_policy
    error_message = "Public access controls required"
  }
  assert {
    condition = aws_kms_key.main.enable_key_rotation
    error_message = "Key rotation required"
  }
  # KIND_ASSERTIONS
}
