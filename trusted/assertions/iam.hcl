  assert {
    condition = jsondecode(aws_iam_role_policy.reader.policy).Statement[0].Action[0] == "s3:GetObject"
    error_message = "Read-only IAM grant required"
  }
