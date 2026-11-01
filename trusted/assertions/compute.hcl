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
