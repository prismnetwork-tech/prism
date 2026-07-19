locals {
  name = "prism-${var.environment}"
  az_a = var.availability_zones[0]
  az_b = var.availability_zones[1]
}

data "aws_caller_identity" "current" {}

resource "aws_vpc" "main" {
  cidr_block           = "10.48.0.0/16"
  enable_dns_hostnames = true
  enable_dns_support   = true
}

resource "aws_internet_gateway" "main" {
  vpc_id = aws_vpc.main.id
}

resource "aws_subnet" "public" {
  for_each = {
    a = { cidr = "10.48.0.0/20", az = local.az_a }
    b = { cidr = "10.48.16.0/20", az = local.az_b }
  }

  vpc_id                  = aws_vpc.main.id
  cidr_block              = each.value.cidr
  availability_zone       = each.value.az
  map_public_ip_on_launch = false
}

resource "aws_subnet" "private" {
  for_each = {
    a = { cidr = "10.48.128.0/20", az = local.az_a }
    b = { cidr = "10.48.144.0/20", az = local.az_b }
  }

  vpc_id            = aws_vpc.main.id
  cidr_block        = each.value.cidr
  availability_zone = each.value.az
}

resource "aws_route_table" "public" {
  vpc_id = aws_vpc.main.id

  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.main.id
  }
}

resource "aws_route_table_association" "public" {
  for_each       = aws_subnet.public
  route_table_id = aws_route_table.public.id
  subnet_id      = each.value.id
}

resource "aws_eip" "nat" {
  domain = "vpc"
}

resource "aws_nat_gateway" "main" {
  allocation_id = aws_eip.nat.id
  subnet_id     = aws_subnet.public["a"].id
  depends_on    = [aws_internet_gateway.main]
}

resource "aws_route_table" "private" {
  vpc_id = aws_vpc.main.id

  route {
    cidr_block     = "0.0.0.0/0"
    nat_gateway_id = aws_nat_gateway.main.id
  }
}

resource "aws_route_table_association" "private" {
  for_each       = aws_subnet.private
  route_table_id = aws_route_table.private.id
  subnet_id      = each.value.id
}

resource "aws_security_group" "service" {
  name   = "${local.name}-service"
  vpc_id = aws_vpc.main.id

  ingress {
    protocol    = "tcp"
    from_port   = 8080
    to_port     = 8081
    cidr_blocks = [aws_vpc.main.cidr_block]
  }

  # RPC, Privy, X and AWS public API endpoints use rotating HTTPS addresses;
  # the rule is port-limited and outbound traffic still traverses the NAT.
  #trivy:ignore:AVD-AWS-0104
  egress {
    protocol    = "tcp"
    from_port   = 443
    to_port     = 443
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    protocol    = "tcp"
    from_port   = 5432
    to_port     = 5432
    cidr_blocks = [aws_vpc.main.cidr_block]
  }

  egress {
    protocol    = "tcp"
    from_port   = 6379
    to_port     = 6379
    cidr_blocks = [aws_vpc.main.cidr_block]
  }

  egress {
    protocol  = "tcp"
    from_port = 8080
    to_port   = 8081
    self      = true
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

resource "aws_security_group" "database" {
  name   = "${local.name}-database"
  vpc_id = aws_vpc.main.id

  ingress {
    protocol        = "tcp"
    from_port       = 5432
    to_port         = 5432
    security_groups = [aws_security_group.service.id]
  }
}

resource "aws_security_group" "cache" {
  name   = "${local.name}-cache"
  vpc_id = aws_vpc.main.id

  ingress {
    protocol        = "tcp"
    from_port       = 6379
    to_port         = 6379
    security_groups = [aws_security_group.service.id, aws_security_group.gateway.id]
  }
}

resource "aws_db_subnet_group" "main" {
  name       = "${local.name}-database"
  subnet_ids = values(aws_subnet.private)[*].id
}

resource "aws_db_instance" "main" {
  identifier                   = "${local.name}-postgres"
  allocated_storage            = 50
  max_allocated_storage        = 250
  engine                       = "postgres"
  engine_version               = "17"
  instance_class               = "db.r7g.large"
  db_name                      = "prism"
  username                     = "prism"
  manage_master_user_password  = true
  db_subnet_group_name         = aws_db_subnet_group.main.name
  vpc_security_group_ids       = [aws_security_group.database.id]
  multi_az                     = true
  storage_encrypted            = true
  backup_retention_period      = 35
  deletion_protection          = true
  skip_final_snapshot          = false
  final_snapshot_identifier    = "${local.name}-final"
  publicly_accessible          = false
  auto_minor_version_upgrade   = true
  performance_insights_enabled = true
  enabled_cloudwatch_logs_exports = [
    "postgresql",
    "upgrade",
  ]
}

resource "aws_elasticache_subnet_group" "main" {
  name       = "${local.name}-cache"
  subnet_ids = values(aws_subnet.private)[*].id
}

resource "aws_elasticache_replication_group" "main" {
  replication_group_id       = "${local.name}-cache"
  description                = "Prism transient state"
  engine                     = "valkey"
  node_type                  = "cache.r7g.large"
  num_cache_clusters         = 2
  automatic_failover_enabled = true
  multi_az_enabled           = true
  transit_encryption_enabled = true
  at_rest_encryption_enabled = true
  subnet_group_name          = aws_elasticache_subnet_group.main.name
  security_group_ids         = [aws_security_group.cache.id]
}

resource "aws_s3_bucket" "private_receipts" {
  bucket_prefix = "${local.name}-private-receipts-"
}

resource "aws_s3_bucket" "public_proofs" {
  bucket_prefix = "${local.name}-public-proofs-"
}

resource "aws_s3_bucket" "load_balancer_logs" {
  bucket_prefix = "${local.name}-load-balancer-logs-"
}

resource "aws_kms_key" "storage" {
  description         = "Prism Network private receipt encryption"
  enable_key_rotation = true
}

resource "aws_kms_alias" "storage" {
  name          = "alias/${local.name}-private-receipts"
  target_key_id = aws_kms_key.storage.key_id
}

resource "aws_s3_bucket_public_access_block" "private_receipts" {
  bucket                  = aws_s3_bucket.private_receipts.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_public_access_block" "public_proofs" {
  bucket                  = aws_s3_bucket.public_proofs.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_public_access_block" "load_balancer_logs" {
  bucket                  = aws_s3_bucket.load_balancer_logs.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_server_side_encryption_configuration" "private_receipts" {
  bucket = aws_s3_bucket.private_receipts.id

  rule {
    apply_server_side_encryption_by_default {
      kms_master_key_id = aws_kms_key.storage.arn
      sse_algorithm     = "aws:kms"
    }

    bucket_key_enabled = true
  }
}

# Public proofs are hash-verifiable public data; SSE-S3 avoids a KMS dependency
# on the CloudFront origin without weakening confidentiality.
#trivy:ignore:AVD-AWS-0132
resource "aws_s3_bucket_server_side_encryption_configuration" "public_proofs" {
  bucket = aws_s3_bucket.public_proofs.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

resource "aws_s3_bucket_versioning" "private_receipts" {
  bucket = aws_s3_bucket.private_receipts.id

  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_versioning" "public_proofs" {
  bucket = aws_s3_bucket.public_proofs.id

  versioning_configuration {
    status = "Enabled"
  }
}

# Elastic Load Balancing log delivery supports SSE-S3, not customer-managed KMS.
#trivy:ignore:AVD-AWS-0132
resource "aws_s3_bucket_server_side_encryption_configuration" "load_balancer_logs" {
  bucket = aws_s3_bucket.load_balancer_logs.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

resource "aws_s3_bucket_lifecycle_configuration" "load_balancer_logs" {
  bucket = aws_s3_bucket.load_balancer_logs.id

  rule {
    id     = "expire"
    status = "Enabled"

    filter {}

    expiration {
      days = 90
    }
  }
}

resource "aws_s3_bucket_policy" "load_balancer_logs" {
  bucket = aws_s3_bucket.load_balancer_logs.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid       = "LoadBalancerLogDelivery"
      Effect    = "Allow"
      Principal = { Service = "logdelivery.elasticloadbalancing.amazonaws.com" }
      Action    = "s3:PutObject"
      Resource  = "${aws_s3_bucket.load_balancer_logs.arn}/AWSLogs/${data.aws_caller_identity.current.account_id}/*"
      Condition = {
        ArnLike = {
          "aws:SourceArn" = "arn:aws:elasticloadbalancing:${var.aws_region}:${data.aws_caller_identity.current.account_id}:loadbalancer/*"
        }
      }
    }]
  })
}

resource "aws_sqs_queue" "dead_letter" {
  name                      = "${local.name}-dead-letter"
  message_retention_seconds = 1209600
  sqs_managed_sse_enabled   = true
}

resource "aws_sqs_queue" "node_commands" {
  name                       = "${local.name}-node-commands"
  visibility_timeout_seconds = 120
  sqs_managed_sse_enabled    = true
  redrive_policy = jsonencode({
    deadLetterTargetArn = aws_sqs_queue.dead_letter.arn
    maxReceiveCount     = 5
  })
}

resource "aws_sqs_queue" "settlements" {
  name                       = "${local.name}-settlements"
  visibility_timeout_seconds = 300
  sqs_managed_sse_enabled    = true
  redrive_policy = jsonencode({
    deadLetterTargetArn = aws_sqs_queue.dead_letter.arn
    maxReceiveCount     = 5
  })
}

resource "aws_sqs_queue" "proof_outbox" {
  name                       = "${local.name}-proof-outbox"
  visibility_timeout_seconds = 300
  sqs_managed_sse_enabled    = true
  redrive_policy = jsonencode({
    deadLetterTargetArn = aws_sqs_queue.dead_letter.arn
    maxReceiveCount     = 5
  })
}

# AWS KMS only supports manual replacement for asymmetric signing keys.
resource "aws_kms_key" "attestor" { # nosemgrep: terraform.aws.security.aws-kms-no-rotation.aws-kms-no-rotation
  description              = "Prism Network metering attestor"
  customer_master_key_spec = "ECC_SECG_P256K1"
  key_usage                = "SIGN_VERIFY"
  multi_region             = false
}

resource "aws_kms_alias" "attestor" {
  name          = "alias/${local.name}-metering-attestor"
  target_key_id = aws_kms_key.attestor.key_id
}

data "aws_iam_policy_document" "service_logs_key" {
  statement {
    sid       = "AccountAdministration"
    actions   = ["kms:*"]
    resources = ["*"]

    principals {
      type        = "AWS"
      identifiers = ["arn:aws:iam::${data.aws_caller_identity.current.account_id}:root"]
    }
  }

  statement {
    sid = "CloudWatchLogs"
    actions = [
      "kms:Decrypt",
      "kms:Encrypt",
      "kms:GenerateDataKey*",
      "kms:ReEncrypt*",
      "kms:DescribeKey",
    ]
    resources = ["*"]

    principals {
      type        = "Service"
      identifiers = ["logs.${var.aws_region}.amazonaws.com"]
    }

    condition {
      test     = "ArnLike"
      variable = "kms:EncryptionContext:aws:logs:arn"
      values   = ["arn:aws:logs:${var.aws_region}:${data.aws_caller_identity.current.account_id}:*"]
    }
  }
}

resource "aws_kms_key" "service_logs" {
  description         = "Prism Network service log encryption"
  enable_key_rotation = true
  policy              = data.aws_iam_policy_document.service_logs_key.json
}

resource "aws_kms_alias" "service_logs" {
  name          = "alias/${local.name}-service-logs"
  target_key_id = aws_kms_key.service_logs.key_id
}

resource "aws_cloudwatch_log_group" "services" {
  name              = "/prism/${var.environment}/services"
  retention_in_days = 90
  kms_key_id        = aws_kms_key.service_logs.arn
}

resource "aws_iam_role" "task_execution" {
  name = "${local.name}-task-execution"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "ecs-tasks.amazonaws.com" }
      Action    = "sts:AssumeRole"
    }]
  })
}

resource "aws_iam_role_policy_attachment" "task_execution" {
  role       = aws_iam_role.task_execution.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AmazonECSTaskExecutionRolePolicy"
}

resource "aws_iam_role_policy" "task_execution_secrets" {
  name = "${local.name}-task-execution-secrets"
  role = aws_iam_role.task_execution.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect = "Allow"
      Action = ["secretsmanager:GetSecretValue"]
      Resource = [
        var.database_url_secret_arn,
        var.control_plane_rpc_url_secret_arn,
        var.control_plane_auth_key_secret_arn,
        var.access_credential_key_secret_arn,
        var.gateway_observer_token_secret_arn,
        var.node_ca_certificate_secret_arn,
        var.node_ca_key_secret_arn,
        var.privy_app_id_secret_arn,
        var.privy_verification_key_secret_arn,
        var.alchemy_api_key_secret_arn,
        var.alchemy_policy_id_secret_arn,
        var.wallet_auth_key_secret_arn,
        var.gateway_control_token_secret_arn,
        var.gateway_hmac_secret_arn,
      ]
    }]
  })
}

resource "aws_iam_role" "runtime" {
  name               = "${local.name}-runtime"
  assume_role_policy = aws_iam_role.task_execution.assume_role_policy
}

resource "aws_ecs_cluster" "main" {
  name = local.name
}

resource "aws_service_discovery_private_dns_namespace" "services" {
  name = "prism.internal"
  vpc  = aws_vpc.main.id
}

resource "aws_service_discovery_service" "control_plane" {
  name = "control-plane"

  dns_config {
    namespace_id = aws_service_discovery_private_dns_namespace.services.id

    dns_records {
      ttl  = 10
      type = "A"
    }

    routing_policy = "MULTIVALUE"
  }

  health_check_custom_config {}
}

resource "aws_ecs_task_definition" "control_plane" {
  family                   = "${local.name}-control-plane"
  network_mode             = "awsvpc"
  requires_compatibilities = ["FARGATE"]
  cpu                      = "1024"
  memory                   = "2048"
  execution_role_arn       = aws_iam_role.task_execution.arn
  task_role_arn            = aws_iam_role.runtime.arn
  depends_on               = [aws_iam_role_policy.task_execution_secrets]

  container_definitions = jsonencode([{
    name         = "control-plane"
    image        = var.control_plane_image
    essential    = true
    portMappings = [{ containerPort = 8080, protocol = "tcp" }]
    secrets = [{
      name      = "DATABASE_URL"
      valueFrom = var.database_url_secret_arn
      }, {
      name      = "PRISM_RPC_URL"
      valueFrom = var.control_plane_rpc_url_secret_arn
      }, {
      name      = "PRISM_CONTROL_PLANE_AUTH_KEY"
      valueFrom = var.control_plane_auth_key_secret_arn
      }, {
      name      = "PRISM_ACCESS_CREDENTIAL_KEY"
      valueFrom = var.access_credential_key_secret_arn
      }, {
      name      = "PRISM_GATEWAY_OBSERVER_TOKEN"
      valueFrom = var.gateway_observer_token_secret_arn
      }, {
      name      = "PRISM_NODE_CA_CERTIFICATE_PEM"
      valueFrom = var.node_ca_certificate_secret_arn
      }, {
      name      = "PRISM_NODE_CA_KEY_PEM"
      valueFrom = var.node_ca_key_secret_arn
    }]
    environment = [
      {
        name  = "PRISM_NODE_REGISTRY_ADDRESS"
        value = var.node_registry_address
      },
      {
        name  = "PRISM_LEASE_ESCROW_ADDRESS"
        value = var.lease_escrow_address
      },
      {
        name  = "PRISM_PUBLIC_GATEWAY_HOST"
        value = var.gateway_domain_name
      },
      {
        name  = "PRISM_PUBLIC_RELAY_PORT"
        value = "7444"
      },
      {
        name  = "PRISM_OPERATOR_SUBJECTS"
        value = join(",", var.operator_subjects)
      }
    ]
    logConfiguration = {
      logDriver = "awslogs"
      options = {
        awslogs-group         = aws_cloudwatch_log_group.services.name
        awslogs-region        = var.aws_region
        awslogs-stream-prefix = "control-plane"
      }
    }
  }])
}

resource "aws_ecs_service" "control_plane" {
  name            = "control-plane"
  cluster         = aws_ecs_cluster.main.id
  task_definition = aws_ecs_task_definition.control_plane.arn
  desired_count   = 2
  launch_type     = "FARGATE"

  deployment_circuit_breaker {
    enable   = true
    rollback = true
  }

  network_configuration {
    assign_public_ip = false
    subnets          = values(aws_subnet.private)[*].id
    security_groups  = [aws_security_group.service.id]
  }

  service_registries {
    registry_arn = aws_service_discovery_service.control_plane.arn
  }
}
