  assert {
    condition = aws_lb.app.internal
    error_message = "Internal load balancer required"
  }
  assert {
    condition = aws_lb_listener.https.protocol == "HTTPS"
    error_message = "TLS required"
  }
