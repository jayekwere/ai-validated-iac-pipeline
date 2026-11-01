  assert {
    condition = !aws_subnet.app_a.map_public_ip_on_launch && !aws_subnet.data_a.map_public_ip_on_launch
    error_message = "Private subnets required"
  }
  assert {
    condition = length(aws_default_security_group.default.ingress) == 0
    error_message = "Default group must deny ingress"
  }
