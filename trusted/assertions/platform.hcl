  assert {
    condition = aws_s3_bucket_public_access_block.storage.restrict_public_buckets
    error_message = "Storage must be private"
  }
  assert {
    condition = one(aws_s3_bucket_server_side_encryption_configuration.storage.rule).apply_server_side_encryption_by_default[0].sse_algorithm == "aws:kms"
    error_message = "Storage must use KMS"
  }
  assert {
    condition = !aws_instance.app.associate_public_ip_address
    error_message = "No public compute"
  }
  assert {
    condition = aws_instance.app.metadata_options[0].http_tokens == "required"
    error_message = "IMDSv2 required"
  }
  assert {
    condition = aws_instance.app.root_block_device[0].encrypted
    error_message = "Disk encryption required"
  }
  assert {
    condition = jsondecode(aws_iam_role_policy.reader.policy).Statement[0].Action[0] == "s3:GetObject"
    error_message = "Read-only IAM grant required"
  }
  assert {
    condition = !aws_subnet.app_a.map_public_ip_on_launch && !aws_subnet.data_a.map_public_ip_on_launch
    error_message = "Private subnets required"
  }
  assert {
    condition = length(aws_default_security_group.default.ingress) == 0
    error_message = "Default group must deny ingress"
  }
  assert {
    condition = aws_lb.app.internal
    error_message = "Internal load balancer required"
  }
  assert {
    condition = aws_lb_listener.https.protocol == "HTTPS"
    error_message = "TLS required"
  }
  assert {
    condition = aws_cloudtrail.audit.is_multi_region_trail && aws_cloudtrail.audit.enable_log_file_validation
    error_message = "Validated multi-region trail required"
  }
  assert {
    condition = aws_cloudwatch_log_group.audit.retention_in_days >= 365
    error_message = "Audit retention required"
  }
