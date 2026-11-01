  assert {
    condition = aws_cloudtrail.audit.is_multi_region_trail && aws_cloudtrail.audit.enable_log_file_validation
    error_message = "Validated multi-region trail required"
  }
  assert {
    condition = aws_cloudwatch_log_group.audit.retention_in_days >= 365
    error_message = "Audit retention required"
  }
