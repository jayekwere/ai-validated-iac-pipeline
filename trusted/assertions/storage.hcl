  assert {
    condition = aws_s3_bucket_public_access_block.storage.restrict_public_buckets
    error_message = "Storage must be private"
  }
  assert {
    condition = one(aws_s3_bucket_server_side_encryption_configuration.storage.rule).apply_server_side_encryption_by_default[0].sse_algorithm == "aws:kms"
    error_message = "Storage must use KMS"
  }
