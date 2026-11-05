variable "environment" {
  type        = string
  description = "Target deployment environment (e.g., prod, staging, dev)."
  default     = "prod"
}

variable "aws_region" {
  type        = string
  description = "AWS deployment region."
  default     = "us-west-2"
}

variable "project_prefix" {
  type        = string
  description = "Prefix applied to all provisioned cloud resources."
  default     = "secops"
}

variable "tags" {
  type        = map(string)
  description = "Resource tags applied to all infrastructure components."
  default = {
    Project   = "SecOps-Log-Collector"
    ManagedBy = "OpenTofu"
    Owner     = "Koality-Assured-SecEng"
  }
}

variable "collectors" {
  type = map(object({
    rate_minutes    = number
    timeout_seconds = number
    memory_size     = number
    sinks           = list(string)
  }))
  description = "Map of collector product configurations."
  default = {
    okta = {
      rate_minutes    = 5
      timeout_seconds = 300
      memory_size     = 256
      sinks           = ["logscale", "s3"]
    }
    crowdstrike = {
      rate_minutes    = 5
      timeout_seconds = 600
      memory_size     = 512
      sinks           = ["logscale", "s3"]
    }
    datadog = {
      rate_minutes    = 5
      timeout_seconds = 300
      memory_size     = 256
      sinks           = ["logscale", "s3"]
    }
    github = {
      rate_minutes    = 15
      timeout_seconds = 300
      memory_size     = 256
      sinks           = ["logscale", "s3"]
    }
    sentinelone = {
      rate_minutes    = 5
      timeout_seconds = 300
      memory_size     = 256
      sinks           = ["logscale", "s3"]
    }
  }
}
