terraform {
  required_version = ">= 1.6.0"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

provider "aws" {
  region = var.aws_region
  default_tags {
    tags = var.tags
  }
}

data "aws_caller_identity" "current" {}
data "aws_region" "current" {}

locals {
  account_id = data.aws_caller_identity.current.account_id
  region     = data.aws_region.current.name
}

# 1. EventBridge Schedule Group
resource "aws_scheduler_schedule_group" "secops" {
  name = "${var.project_prefix}-schedule-group-${var.environment}"
}

# 2. Shared Data Lake & State Checkpoint Bucket
resource "aws_s3_bucket" "data_lake" {
  bucket = "${var.project_prefix}-data-lake-${local.account_id}-${var.environment}"
}

resource "aws_s3_bucket_server_side_encryption_configuration" "data_lake" {
  bucket = aws_s3_bucket.data_lake.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

# 3. Collector Infrastructure (Secrets, IAM, Lambdas, Schedules)
resource "aws_secretsmanager_secret" "collector" {
  for_each    = var.collectors
  name        = "${var.project_prefix}-scrt-${each.key}-credentials"
  description = "API credentials for SecOps log collector plugin: ${each.key}"
}

resource "aws_cloudwatch_log_group" "lambda" {
  for_each          = var.collectors
  name              = "/aws/lambda/${var.project_prefix}-lmb-${each.key}-${var.environment}"
  retention_in_days = 30
}

# Lambda Execution IAM Role
resource "aws_iam_role" "lambda_exec" {
  for_each = var.collectors
  name     = "${var.project_prefix}-iam-r-${each.key}-${var.environment}-lambda"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          Service = "lambda.amazonaws.com"
        }
      }
    ]
  })
}

resource "aws_iam_role_policy" "lambda_policy" {
  for_each = var.collectors
  name     = "${var.project_prefix}-p-${each.key}-policy"
  role     = aws_iam_role.lambda_exec[each.key].id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "CloudWatchLogs"
        Effect = "Allow"
        Action = [
          "logs:CreateLogStream",
          "logs:PutLogEvents"
        ]
        Resource = [
          aws_cloudwatch_log_group.lambda[each.key].arn,
          "${aws_cloudwatch_log_group.lambda[each.key].arn}:*"
        ]
      },
      {
        Sid    = "SecretsManagerRead"
        Effect = "Allow"
        Action = [
          "secretsmanager:GetSecretValue",
          "secretsmanager:DescribeSecret"
        ]
        Resource = [
          aws_secretsmanager_secret.collector[each.key].arn,
          "arn:aws:secretsmanager:${local.region}:${local.account_id}:secret:${var.project_prefix}-sink-*-credentials*"
        ]
      },
      {
        Sid    = "S3DataLakeIngest"
        Effect = "Allow"
        Action = [
          "s3:PutObject",
          "s3:GetObject"
        ]
        Resource = "${aws_s3_bucket.data_lake.arn}/*"
      },
      {
        Sid    = "S3DataLakeBucket"
        Effect = "Allow"
        Action = [
          "s3:ListBucket"
        ]
        Resource = aws_s3_bucket.data_lake.arn
      }
    ]
  })
}

# Lambda Function
resource "aws_lambda_function" "collector" {
  for_each      = var.collectors
  function_name = "${var.project_prefix}-lmb-${each.key}-${var.environment}"
  role          = aws_iam_role.lambda_exec[each.key].arn
  handler       = "secops_collector.lambda_handler.lambda_handler"
  runtime       = "python3.11"
  timeout       = each.value.timeout_seconds
  memory_size   = each.value.memory_size
  architectures = ["x86_64"]

  # Dummy zip placeholder; deployment pipelines supply built artifact
  filename         = "${path.module}/dummy_payload.zip"
  source_code_hash = fileexists("${path.module}/dummy_payload.zip") ? filebase64sha256("${path.module}/dummy_payload.zip") : null

  environment {
    variables = {
      SOURCE_TYPE          = each.key
      SINK_TYPES           = join(",", each.value.sinks)
      SECRETS_BACKEND      = "secretsmanager"
      STATE_BACKEND        = "s3"
      STATE_BUCKET         = aws_s3_bucket.data_lake.id
      SECRET_NAME_OVERRIDE = aws_secretsmanager_secret.collector[each.key].name
    }
  }

  depends_on = [aws_cloudwatch_log_group.lambda]
}

# EventBridge Scheduler Execution Role
resource "aws_iam_role" "scheduler" {
  for_each = var.collectors
  name     = "${var.project_prefix}-iam-r-${each.key}-${var.environment}-scheduler"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          Service = "scheduler.amazonaws.com"
        }
      }
    ]
  })
}

resource "aws_iam_role_policy" "scheduler_invoke" {
  for_each = var.collectors
  name     = "${var.project_prefix}-p-sch-invoke-${each.key}"
  role     = aws_iam_role.scheduler[each.key].id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "InvokeLambda"
        Effect = "Allow"
        Action = ["lambda:InvokeFunction"]
        Resource = [
          aws_lambda_function.collector[each.key].arn,
          "${aws_lambda_function.collector[each.key].arn}:*"
        ]
      }
    ]
  })
}

# EventBridge Schedule
resource "aws_scheduler_schedule" "schedule" {
  for_each   = var.collectors
  name       = "${var.project_prefix}-sch-${each.key}-${var.environment}"
  group_name = aws_scheduler_schedule_group.secops.name

  flexible_time_window {
    mode = "OFF"
  }

  schedule_expression = "rate(${each.value.rate_minutes} minutes)"
  state               = "ENABLED"

  target {
    arn      = aws_lambda_function.collector[each.key].arn
    role_arn = aws_iam_role.scheduler[each.key].arn
    input = jsonencode({
      source_type         = each.key
      sink_types          = each.value.sinks
      time_window_minutes = each.value.rate_minutes
    })

    retry_policy {
      maximum_event_age_in_seconds = 3600
      maximum_retry_attempts       = 2
    }
  }
}
