package iac.v1
import rego.v1
resources := {r.address: r | some r in input.resource_changes; r.mode == "managed"}
deny contains {"id":"PLAN_FORMAT","address":"plan","message":"Expected Terraform plan JSON with resource changes"} if { not is_array(object.get(input,"resource_changes",null)) }
deny contains {"id":"PROVIDER","address":r.address,"message":"Unapproved provider"} if {some r in input.resource_changes; r.provider_name != "registry.terraform.io/hashicorp/aws"}
deny contains {"id":"PUBLIC_STORAGE","address":r.address,"message":"All S3 public access controls must be enabled"} if {some r in input.resource_changes; r.type == "aws_s3_bucket_public_access_block"; some k in ["block_public_acls","block_public_policy","ignore_public_acls","restrict_public_buckets"]; object.get(r.change.after,k,false) != true}
deny contains {"id":"MISSING_ENCRYPTION","address":r.address,"message":"Bucket needs an encryption companion"} if {some r in input.resource_changes;r.type == "aws_s3_bucket"; not resources[replace(r.address,"aws_s3_bucket.","aws_s3_bucket_server_side_encryption_configuration.")]}
deny contains {"id":"ENCRYPTION","address":r.address,"message":"S3 requires KMS encryption"} if {some r in input.resource_changes;r.type == "aws_s3_bucket_server_side_encryption_configuration";r.name != "logs";r.change.after.rule[0].apply_server_side_encryption_by_default[0].sse_algorithm != "aws:kms"}
deny contains {"id":"PUBLIC_COMPUTE","address":r.address,"message":"Compute cannot have a public IP"} if {some r in input.resource_changes;r.type == "aws_instance";r.change.after.associate_public_ip_address != false}
deny contains {"id":"DISK_ENCRYPTION","address":r.address,"message":"Compute disk must be encrypted"} if {some r in input.resource_changes;r.type == "aws_instance";r.change.after.root_block_device[0].encrypted != true}
deny contains {"id":"IMDS","address":r.address,"message":"IMDSv2 required"} if {some r in input.resource_changes;r.type == "aws_instance";r.change.after.metadata_options[0].http_tokens != "required"}
deny contains {"id":"ADMIN_INGRESS","address":r.address,"message":"Public ingress forbidden"} if {some r in input.resource_changes;r.type == "aws_security_group";some ingress in r.change.after.ingress;some cidr in ingress.cidr_blocks;cidr == "0.0.0.0/0"}
deny contains {"id":"WILDCARD_IAM","address":r.address,"message":"Wildcard IAM grants forbidden"} if {some r in input.resource_changes;r.type == "aws_iam_role_policy";some stmt in allow_statements(r);some action in as_array(object.get(stmt,"Action",[]));contains(action,"*")}
deny contains {"id":"PUBLIC_LB","address":r.address,"message":"Load balancer must be internal"} if {some r in input.resource_changes;r.type == "aws_lb";r.change.after.internal != true}
deny contains {"id":"TLS","address":r.address,"message":"Only HTTPS listeners approved"} if {some r in input.resource_changes;r.type == "aws_lb_listener";r.change.after.protocol != "HTTPS"}
deny contains {"id":"AUDIT","address":r.address,"message":"CloudTrail validation must be enabled"} if {some r in input.resource_changes;r.type == "aws_cloudtrail";r.change.after.enable_log_file_validation != true}
decision := {"version":"1.0.0","allow":count(deny)==0,"findings":deny}

deny contains {"id":"LOG_ENCRYPTION","address":r.address,"message":"Service log sink must use SSE-S3"} if {some r in input.resource_changes;r.type == "aws_s3_bucket_server_side_encryption_configuration";r.name == "logs";r.change.after.rule[0].apply_server_side_encryption_by_default[0].sse_algorithm != "AES256"}

deny contains {"id":"UNKNOWN_IAM","address":r.address,"message":"IAM policy must be known during planning"} if {some r in input.resource_changes;r.type == "aws_iam_role_policy";not is_string(object.get(r.change.after,"policy",null))}
deny contains {"id":"WILDCARD_RESOURCE","address":r.address,"message":"IAM global resources forbidden"} if {some r in input.resource_changes;r.type == "aws_iam_role_policy";some stmt in allow_statements(r);some arn in as_array(object.get(stmt,"Resource",[]));arn == "*"}
deny contains {"id":"MODULE","address":r.address,"message":"Module addresses are not approved"} if {some r in input.resource_changes;startswith(r.address,"module.")}
deny contains {"id":"ENCRYPTION_UNKNOWN","address":r.address,"message":"Encryption algorithm must be known"} if {some r in input.resource_changes;r.type == "aws_s3_bucket_server_side_encryption_configuration";not is_array(object.get(r.change.after,"rule",null))}
deny contains {"id":"IAM_NEGATION","address":r.address,"message":"Allow statements cannot use NotAction or NotResource"} if {some r in input.resource_changes;r.type == "aws_iam_role_policy";some stmt in allow_statements(r);some k in ["NotAction","NotResource"];object.get(stmt,k,null) != null}

# IAM accepts Statement, Action and Resource as a single value or an array. Normalize before iterating so the string form cannot bypass the checks.
as_array(x) := x if is_array(x)
as_array(x) := [x] if not is_array(x)
allow_statements(r) := [stmt | some stmt in as_array(json.unmarshal(r.change.after.policy).Statement); stmt.Effect == "Allow"] if is_string(object.get(r.change.after,"policy",null))
