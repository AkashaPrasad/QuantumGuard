# QuantumGuard API on AWS: one small instance with no inbound port open to the internet, reached only through
# an API Gateway HTTP API (TLS) over a private VPC link. The web console is served separately (see ../cloudflare).

terraform {
  required_version = ">= 1.9"
  required_providers {
    aws    = { source = "hashicorp/aws", version = ">= 6.0" }
    random = { source = "hashicorp/random", version = ">= 3.6" }
  }
}

provider "aws" {
  region  = var.region
  profile = var.profile
  default_tags {
    tags = { Project = var.name }
  }
}

data "aws_caller_identity" "me" {}

data "aws_vpc" "default" {
  default = true
}

data "aws_subnets" "default" {
  filter {
    name   = "vpc-id"
    values = [data.aws_vpc.default.id]
  }
  filter {
    name   = "default-for-az"
    values = ["true"]
  }
}

data "aws_ssm_parameter" "al2023_arm64" {
  name = "/aws/service/ami-amazon-linux-latest/al2023-ami-kernel-default-arm64"
}

locals {
  registry  = "${data.aws_caller_identity.me.account_id}.dkr.ecr.${var.region}.amazonaws.com"
  image_ref = "${aws_ecr_repository.app.repository_url}:${var.image_tag}"
  subnet_id = sort(data.aws_subnets.default.ids)[0]
  key_param = "/${var.name}/edge-key"
}

# ---- image registry ----------------------------------------------------------------------------

resource "aws_ecr_repository" "app" {
  name                 = var.name
  image_tag_mutability = "IMMUTABLE"
  force_delete         = true
  image_scanning_configuration {
    scan_on_push = true
  }
  encryption_configuration {
    encryption_type = "AES256"
  }
}

# ---- the shared key that proves a request came through the web edge -------------------------------

resource "random_password" "edge_key" {
  length  = 48
  special = false
}

resource "aws_ssm_parameter" "edge_key" {
  name  = local.key_param
  type  = "SecureString"
  value = random_password.edge_key.result
}

# ---- instance identity: pull its own image, read its own key, be managed without SSH -------------

data "aws_iam_policy_document" "assume" {
  statement {
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["ec2.amazonaws.com"]
    }
  }
}

data "aws_iam_policy_document" "instance" {
  statement {
    actions   = ["ecr:GetAuthorizationToken"]
    resources = ["*"]
  }
  statement {
    actions   = ["ecr:BatchGetImage", "ecr:GetDownloadUrlForLayer", "ecr:BatchCheckLayerAvailability"]
    resources = [aws_ecr_repository.app.arn]
  }
  statement {
    actions   = ["ssm:GetParameter"]
    resources = [aws_ssm_parameter.edge_key.arn]
  }
}

resource "aws_iam_role" "instance" {
  name               = "${var.name}-backend"
  assume_role_policy = data.aws_iam_policy_document.assume.json
}

resource "aws_iam_role_policy" "instance" {
  name   = "own-image-and-key"
  role   = aws_iam_role.instance.id
  policy = data.aws_iam_policy_document.instance.json
}

resource "aws_iam_role_policy_attachment" "ssm" {
  role       = aws_iam_role.instance.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore"
}

resource "aws_iam_instance_profile" "instance" {
  name = "${var.name}-backend"
  role = aws_iam_role.instance.name
}

# ---- network: nothing in from the internet, only the API gateway's private link on the proxy port ---

resource "aws_security_group" "link" {
  name        = "${var.name}-link"
  description = "QuantumGuard API gateway link"
  vpc_id      = data.aws_vpc.default.id
}

resource "aws_vpc_security_group_egress_rule" "link_to_backend" {
  security_group_id            = aws_security_group.link.id
  description                  = "To the API proxy"
  referenced_security_group_id = aws_security_group.backend.id
  ip_protocol                  = "tcp"
  from_port                    = 8080
  to_port                      = 8080
}

resource "aws_security_group" "backend" {
  name        = "${var.name}-api"
  description = "QuantumGuard API: gateway link only"
  vpc_id      = data.aws_vpc.default.id
  lifecycle {
    create_before_destroy = true
  }
}

resource "aws_vpc_security_group_ingress_rule" "from_link" {
  security_group_id            = aws_security_group.backend.id
  description                  = "API gateway link"
  referenced_security_group_id = aws_security_group.link.id
  ip_protocol                  = "tcp"
  from_port                    = 8080
  to_port                      = 8080
}

resource "aws_vpc_security_group_egress_rule" "https" {
  security_group_id = aws_security_group.backend.id
  description       = "Image pulls, package updates, Systems Manager"
  cidr_ipv4         = "0.0.0.0/0"
  ip_protocol       = "tcp"
  from_port         = 443
  to_port           = 443
}

# ---- the instance -------------------------------------------------------------------------------

resource "aws_instance" "backend" {
  ami                         = data.aws_ssm_parameter.al2023_arm64.value
  instance_type               = var.instance_type
  subnet_id                   = local.subnet_id
  vpc_security_group_ids      = [aws_security_group.backend.id]
  iam_instance_profile        = aws_iam_instance_profile.instance.name
  associate_public_ip_address = true # outbound only; the security group admits nothing from the internet

  metadata_options {
    http_tokens                 = "required"
    http_put_response_hop_limit = 1 # containers cannot reach the instance credentials
  }

  root_block_device {
    volume_type = "gp3"
    volume_size = 16
    encrypted   = true
  }

  user_data = templatefile("${path.module}/user-data.sh.tftpl", {
    region      = var.region
    registry    = local.registry
    image_ref   = local.image_ref
    caddy_image = var.caddy_image
    key_param   = local.key_param
    demo        = var.demo ? "1" : "0"
  })

  tags = { Name = "${var.name}-backend" }

  lifecycle {
    ignore_changes = [ami, user_data] # later image updates go through `qg-up`, not a rebuild
  }

  depends_on = [aws_iam_role_policy.instance, aws_iam_role_policy_attachment.ssm, aws_ssm_parameter.edge_key]
}

# ---- API gateway: the only public address of the API ---------------------------------------------

# The gateway finds the instance through a service registry entry and reaches it over the private link.
resource "aws_service_discovery_http_namespace" "this" {
  name = var.name
}

resource "aws_service_discovery_service" "backend" {
  name         = "backend"
  namespace_id = aws_service_discovery_http_namespace.this.id
}

resource "aws_service_discovery_instance" "backend" {
  instance_id = aws_instance.backend.id
  service_id  = aws_service_discovery_service.backend.id
  attributes = {
    AWS_INSTANCE_IPV4 = aws_instance.backend.private_ip
    AWS_INSTANCE_PORT = "8080"
  }
}

resource "aws_apigatewayv2_vpc_link" "this" {
  name               = var.name
  subnet_ids         = data.aws_subnets.default.ids
  security_group_ids = [aws_security_group.link.id]
}

resource "aws_apigatewayv2_api" "api" {
  name          = "${var.name}-api"
  protocol_type = "HTTP"
}

resource "aws_apigatewayv2_integration" "backend" {
  api_id                 = aws_apigatewayv2_api.api.id
  integration_type       = "HTTP_PROXY"
  integration_method     = "ANY"
  integration_uri        = aws_service_discovery_service.backend.arn
  connection_type        = "VPC_LINK"
  connection_id          = aws_apigatewayv2_vpc_link.this.id
  payload_format_version = "1.0"
  depends_on             = [aws_service_discovery_instance.backend]
}

resource "aws_apigatewayv2_route" "all" {
  api_id    = aws_apigatewayv2_api.api.id
  route_key = "$default"
  target    = "integrations/${aws_apigatewayv2_integration.backend.id}"
}

resource "aws_apigatewayv2_stage" "default" {
  api_id      = aws_apigatewayv2_api.api.id
  name        = "$default"
  auto_deploy = true
  default_route_settings {
    throttling_burst_limit = 200
    throttling_rate_limit  = 100
  }
}
