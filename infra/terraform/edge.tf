resource "aws_security_group" "public_alb" {
  name   = "${local.name}-public-alb"
  vpc_id = aws_vpc.main.id

  ingress {
    protocol    = "tcp"
    from_port   = 443
    to_port     = 443
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    protocol    = "tcp"
    from_port   = 80
    to_port     = 80
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    protocol        = "tcp"
    from_port       = 3000
    to_port         = 3000
    security_groups = [aws_security_group.service.id]
  }
}

# This is the HTTPS application edge and must be internet-facing.
#trivy:ignore:AVD-AWS-0053
resource "aws_lb" "web" {
  name                       = "${local.name}-web"
  internal                   = false
  load_balancer_type         = "application"
  security_groups            = [aws_security_group.public_alb.id]
  subnets                    = values(aws_subnet.public)[*].id
  idle_timeout               = 60
  drop_invalid_header_fields = true

  access_logs {
    bucket  = aws_s3_bucket.load_balancer_logs.id
    enabled = true
  }

  depends_on = [aws_s3_bucket_policy.load_balancer_logs]
}

resource "aws_lb_target_group" "web" {
  name        = "${local.name}-web"
  port        = 3000
  protocol    = "HTTP"
  target_type = "ip"
  vpc_id      = aws_vpc.main.id

  health_check {
    path    = "/"
    matcher = "200-399"
  }
}

resource "aws_lb_listener" "web_https" {
  load_balancer_arn = aws_lb.web.arn
  port              = 443
  protocol          = "HTTPS"
  certificate_arn   = var.web_certificate_arn

  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.web.arn
  }
}

resource "aws_lb_listener" "web_http" {
  load_balancer_arn = aws_lb.web.arn
  port              = 80
  protocol          = "HTTP"

  default_action {
    type = "redirect"
    redirect {
      protocol    = "HTTPS"
      port        = "443"
      status_code = "HTTP_301"
    }
  }
}

resource "aws_wafv2_web_acl" "web" {
  name  = "${local.name}-web"
  scope = "REGIONAL"

  default_action {
    allow {}
  }

  rule {
    name     = "managed-common"
    priority = 1
    override_action {
      none {}
    }
    statement {
      managed_rule_group_statement {
        name        = "AWSManagedRulesCommonRuleSet"
        vendor_name = "AWS"
      }
    }
    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "managed-common"
      sampled_requests_enabled   = true
    }
  }

  rule {
    name     = "rate-limit"
    priority = 2
    action {
      block {}
    }
    statement {
      rate_based_statement {
        limit              = 2000
        aggregate_key_type = "IP"
      }
    }
    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "rate-limit"
      sampled_requests_enabled   = true
    }
  }

  visibility_config {
    cloudwatch_metrics_enabled = true
    metric_name                = "${local.name}-web"
    sampled_requests_enabled   = true
  }
}

resource "aws_wafv2_web_acl_association" "web" {
  resource_arn = aws_lb.web.arn
  web_acl_arn  = aws_wafv2_web_acl.web.arn
}

resource "aws_ecs_task_definition" "web" {
  family                   = "${local.name}-web"
  network_mode             = "awsvpc"
  requires_compatibilities = ["FARGATE"]
  cpu                      = "512"
  memory                   = "1024"
  execution_role_arn       = aws_iam_role.task_execution.arn
  task_role_arn            = aws_iam_role.runtime.arn
  depends_on               = [aws_iam_role_policy.task_execution_secrets]

  container_definitions = jsonencode([{
    name         = "web"
    image        = var.web_image
    essential    = true
    portMappings = [{ containerPort = 3000, protocol = "tcp" }]
    secrets = [{
      name      = "PRISM_PRIVY_APP_ID"
      valueFrom = var.privy_app_id_secret_arn
      }, {
      name      = "PRISM_PRIVY_VERIFICATION_KEY"
      valueFrom = var.privy_verification_key_secret_arn
      }, {
      name      = "PRISM_CONTROL_PLANE_AUTH_KEY"
      valueFrom = var.control_plane_auth_key_secret_arn
      }, {
      name      = "PRISM_ALCHEMY_API_KEY"
      valueFrom = var.alchemy_api_key_secret_arn
      }, {
      name      = "PRISM_ALCHEMY_POLICY_ID"
      valueFrom = var.alchemy_policy_id_secret_arn
      }, {
      name      = "PRISM_WALLET_AUTH_KEY"
      valueFrom = var.wallet_auth_key_secret_arn
    }]
    environment = [
      {
        name  = "PRISM_API_BASE_URL"
        value = "http://control-plane.prism.internal:8080"
      },
      {
        name  = "PRISM_ESCROW_ADDRESS"
        value = var.lease_escrow_address
      },
      {
        name  = "PRISM_PROOF_INDEX_URL"
        value = var.proof_index_url
      }
    ]
    logConfiguration = {
      logDriver = "awslogs"
      options = {
        awslogs-group         = aws_cloudwatch_log_group.services.name
        awslogs-region        = var.aws_region
        awslogs-stream-prefix = "web"
      }
    }
  }])
}

resource "aws_ecs_service" "web" {
  name                              = "web"
  cluster                           = aws_ecs_cluster.main.id
  task_definition                   = aws_ecs_task_definition.web.arn
  desired_count                     = 2
  launch_type                       = "FARGATE"
  health_check_grace_period_seconds = 60

  deployment_circuit_breaker {
    enable   = true
    rollback = true
  }

  network_configuration {
    assign_public_ip = false
    subnets          = values(aws_subnet.private)[*].id
    security_groups  = [aws_security_group.service.id]
  }

  load_balancer {
    target_group_arn = aws_lb_target_group.web.arn
    container_name   = "web"
    container_port   = 3000
  }

  depends_on = [aws_lb_listener.web_https]
}

resource "aws_security_group" "gateway" {
  name   = "${local.name}-gateway"
  vpc_id = aws_vpc.main.id

  ingress {
    protocol    = "tcp"
    from_port   = 8081
    to_port     = 8081
    cidr_blocks = [aws_vpc.main.cidr_block]
  }

  ingress {
    protocol    = "tcp"
    from_port   = 7443
    to_port     = 7444
    cidr_blocks = [aws_vpc.main.cidr_block]
  }

  # EC2 bootstrap and Secrets Manager use rotating AWS HTTPS endpoints. The
  # rule is port-limited; node and relay traffic enters through the NLB.
  #trivy:ignore:AVD-AWS-0104
  egress {
    protocol    = "tcp"
    from_port   = 443
    to_port     = 443
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    protocol    = "tcp"
    from_port   = 6379
    to_port     = 6379
    cidr_blocks = [aws_vpc.main.cidr_block]
  }

  egress {
    protocol    = "tcp"
    from_port   = 8080
    to_port     = 8080
    cidr_blocks = [aws_vpc.main.cidr_block]
  }

  egress {
    protocol    = "udp"
    from_port   = 53
    to_port     = 53
    cidr_blocks = ["10.48.0.2/32"]
  }

  egress {
    protocol    = "tcp"
    from_port   = 53
    to_port     = 53
    cidr_blocks = ["10.48.0.2/32"]
  }
}

resource "aws_iam_role" "gateway" {
  name = "${local.name}-gateway"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect = "Allow"
      Principal = {
        Service = "ec2.amazonaws.com"
      }
      Action = "sts:AssumeRole"
    }]
  })
}

resource "aws_iam_role_policy" "gateway" {
  name = "${local.name}-gateway"
  role = aws_iam_role.gateway.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect = "Allow"
      Action = ["secretsmanager:GetSecretValue"]
      Resource = [
        var.gateway_control_token_secret_arn,
        var.gateway_observer_token_secret_arn,
        var.gateway_hmac_secret_arn,
        var.gateway_redis_url_secret_arn,
        var.gateway_tls_certificate_secret_arn,
        var.gateway_tls_key_secret_arn,
        var.node_ca_certificate_secret_arn,
      ]
    }]
  })
}

resource "aws_iam_instance_profile" "gateway" {
  name = "${local.name}-gateway"
  role = aws_iam_role.gateway.name
}

resource "aws_launch_template" "gateway" {
  name_prefix   = "${local.name}-gateway-"
  image_id      = var.gateway_ami_id
  instance_type = var.gateway_instance_type

  iam_instance_profile { arn = aws_iam_instance_profile.gateway.arn }
  vpc_security_group_ids = [aws_security_group.gateway.id]

  metadata_options {
    http_endpoint = "enabled"
    http_tokens   = "required"
  }

  user_data = base64encode(<<-EOT
    #!/bin/bash
    set -euo pipefail

    install -d -m 0700 /etc/prism-gateway
    aws secretsmanager get-secret-value --region ${var.aws_region} --secret-id ${var.gateway_tls_certificate_secret_arn} --query SecretString --output text >/etc/prism-gateway/server.crt
    aws secretsmanager get-secret-value --region ${var.aws_region} --secret-id ${var.gateway_tls_key_secret_arn} --query SecretString --output text >/etc/prism-gateway/server.key
    aws secretsmanager get-secret-value --region ${var.aws_region} --secret-id ${var.node_ca_certificate_secret_arn} --query SecretString --output text >/etc/prism-gateway/node-ca.crt
    chmod 0400 /etc/prism-gateway/server.key
    chmod 0444 /etc/prism-gateway/server.crt /etc/prism-gateway/node-ca.crt
    cat >/etc/prism-gateway.env <<EOF
    PRISM_GATEWAY_CONTROL_TOKEN=$(aws secretsmanager get-secret-value --region ${var.aws_region} --secret-id ${var.gateway_control_token_secret_arn} --query SecretString --output text)
    PRISM_GATEWAY_OBSERVER_TOKEN=$(aws secretsmanager get-secret-value --region ${var.aws_region} --secret-id ${var.gateway_observer_token_secret_arn} --query SecretString --output text)
    PRISM_GATEWAY_HMAC_KEY=$(aws secretsmanager get-secret-value --region ${var.aws_region} --secret-id ${var.gateway_hmac_secret_arn} --query SecretString --output text)
    PRISM_REDIS_URL=$(aws secretsmanager get-secret-value --region ${var.aws_region} --secret-id ${var.gateway_redis_url_secret_arn} --query SecretString --output text)
    PRISM_GATEWAY_ADDR=0.0.0.0:8081
    PRISM_ENABLE_TUNNEL=1
    PRISM_TUNNEL_ADDR=0.0.0.0:7443
    PRISM_RELAY_ADDR=0.0.0.0:7444
    PRISM_TUNNEL_SERVER_CERTIFICATE=/etc/prism-gateway/server.crt
    PRISM_TUNNEL_SERVER_KEY=/etc/prism-gateway/server.key
    PRISM_TUNNEL_CLIENT_CA=/etc/prism-gateway/node-ca.crt
    PRISM_CONTROL_PLANE_URL=http://control-plane.prism.internal:8080
    PRISM_ALLOW_PRIVATE_CONTROL_PLANE_HTTP=1
    EOF
    chmod 0600 /etc/prism-gateway.env
    install -d -m 0755 /etc/systemd/system/prism-gateway.service.d
    cat >/etc/systemd/system/prism-gateway.service.d/environment.conf <<'EOF'
    [Service]
    EnvironmentFile=/etc/prism-gateway.env
    EOF
    systemctl daemon-reload
    systemctl enable prism-gateway
    systemctl start prism-gateway
  EOT
  )
}

# The node and renter TLS protocols require TCP pass-through for end-to-end
# certificate validation, so this network load balancer is public by design.
#trivy:ignore:AVD-AWS-0053
resource "aws_lb" "gateway" {
  name               = "${local.name}-gateway"
  internal           = false
  load_balancer_type = "network"
  subnets            = values(aws_subnet.public)[*].id

  access_logs {
    bucket  = aws_s3_bucket.load_balancer_logs.id
    enabled = true
  }

  depends_on = [aws_s3_bucket_policy.load_balancer_logs]
}

resource "aws_lb_target_group" "gateway_node" {
  name        = "${local.name}-gateway-node"
  port        = 7443
  protocol    = "TCP"
  target_type = "instance"
  vpc_id      = aws_vpc.main.id

  health_check {
    protocol = "HTTP"
    port     = "8081"
    path     = "/healthz"
    matcher  = "200-399"
  }
}

resource "aws_lb_target_group" "gateway_relay" {
  name        = "${local.name}-gateway-relay"
  port        = 7444
  protocol    = "TCP"
  target_type = "instance"
  vpc_id      = aws_vpc.main.id

  health_check {
    protocol = "HTTP"
    port     = "8081"
    path     = "/healthz"
    matcher  = "200-399"
  }
}

resource "aws_lb_listener" "gateway_node" {
  load_balancer_arn = aws_lb.gateway.arn
  port              = 7443
  protocol          = "TCP"

  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.gateway_node.arn
  }
}

resource "aws_lb_listener" "gateway_relay" {
  load_balancer_arn = aws_lb.gateway.arn
  port              = 7444
  protocol          = "TCP"

  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.gateway_relay.arn
  }
}

resource "aws_autoscaling_group" "gateway" {
  name                = "${local.name}-gateway"
  min_size            = 2
  max_size            = 8
  desired_capacity    = 2
  health_check_type   = "ELB"
  vpc_zone_identifier = values(aws_subnet.private)[*].id
  target_group_arns = [
    aws_lb_target_group.gateway_node.arn,
    aws_lb_target_group.gateway_relay.arn,
  ]
  health_check_grace_period = 180

  launch_template {
    id      = aws_launch_template.gateway.id
    version = "$Latest"
  }

  instance_refresh {
    strategy = "Rolling"

    preferences {
      min_healthy_percentage = 50
    }
  }
}

resource "aws_cloudfront_origin_access_control" "proofs" {
  name                              = "${local.name}-proofs"
  description                       = "Private S3 access for public proof artifacts"
  origin_access_control_origin_type = "s3"
  signing_behavior                  = "always"
  signing_protocol                  = "sigv4"
}

resource "aws_wafv2_web_acl" "proofs" {
  provider = aws.us_east_1
  name     = "${local.name}-proofs"
  scope    = "CLOUDFRONT"

  default_action {
    allow {}
  }

  rule {
    name     = "managed-common"
    priority = 1

    override_action {
      none {}
    }

    statement {
      managed_rule_group_statement {
        name        = "AWSManagedRulesCommonRuleSet"
        vendor_name = "AWS"
      }
    }

    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "${local.name}-proofs-common"
      sampled_requests_enabled   = true
    }
  }

  rule {
    name     = "rate-limit"
    priority = 2

    action {
      block {}
    }

    statement {
      rate_based_statement {
        limit              = 2000
        aggregate_key_type = "IP"
      }
    }

    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "${local.name}-proofs-rate"
      sampled_requests_enabled   = true
    }
  }

  visibility_config {
    cloudwatch_metrics_enabled = true
    metric_name                = "${local.name}-proofs"
    sampled_requests_enabled   = true
  }
}

resource "aws_cloudfront_distribution" "proofs" {
  enabled         = true
  is_ipv6_enabled = true
  aliases         = [var.proof_domain_name]
  web_acl_id      = aws_wafv2_web_acl.proofs.arn

  origin {
    domain_name              = aws_s3_bucket.public_proofs.bucket_regional_domain_name
    origin_id                = "proof-artifacts"
    origin_access_control_id = aws_cloudfront_origin_access_control.proofs.id
  }

  default_cache_behavior {
    allowed_methods        = ["GET", "HEAD"]
    cached_methods         = ["GET", "HEAD"]
    target_origin_id       = "proof-artifacts"
    viewer_protocol_policy = "redirect-to-https"

    forwarded_values {
      query_string = false
      cookies { forward = "none" }
    }
  }

  restrictions {
    geo_restriction {
      restriction_type = "none"
    }
  }
  viewer_certificate {
    acm_certificate_arn      = var.proof_certificate_arn
    minimum_protocol_version = "TLSv1.2_2021"
    ssl_support_method       = "sni-only"
  }
}

resource "aws_s3_bucket_policy" "public_proofs" {
  bucket = aws_s3_bucket.public_proofs.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "cloudfront.amazonaws.com" }
      Action    = "s3:GetObject"
      Resource  = "${aws_s3_bucket.public_proofs.arn}/*"
      Condition = { StringEquals = { "AWS:SourceArn" = aws_cloudfront_distribution.proofs.arn } }
    }]
  })
}
