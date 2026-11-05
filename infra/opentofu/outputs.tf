output "schedule_group_name" {
  description = "EventBridge Schedule Group name."
  value       = aws_scheduler_schedule_group.secops.name
}

output "data_lake_bucket_id" {
  description = "S3 Data Lake bucket ID for security logs and checkpoints."
  value       = aws_s3_bucket.data_lake.id
}

output "lambda_arns" {
  description = "ARNs of provisioned collector Lambda functions."
  value       = { for k, v in aws_lambda_function.collector : k => v.arn }
}

output "secret_arns" {
  description = "ARNs of Secrets Manager secrets for collector credentials."
  value       = { for k, v in aws_secretsmanager_secret.collector : k => v.arn }
}

output "schedule_arns" {
  description = "ARNs of EventBridge Schedules."
  value       = { for k, v in aws_scheduler_schedule.schedule : k => v.arn }
}
