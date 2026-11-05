"""Declarative Pulumi module generating EventBridge Scheduler, IAM roles, and Lambdas."""

import json

import pulumi
import pulumi_aws as aws
from config import (
    collector_products,
    common_tags,
    environment,
    project_prefix,
)

current_caller = aws.get_caller_identity()
current_region = aws.get_region()

account_id = current_caller.account_id
region_name = current_region.name

# 1. EventBridge Schedule Group
schedule_group_name = f"{project_prefix}-schedule-group-{environment}"
schedule_group = aws.scheduler.ScheduleGroup(
    schedule_group_name,
    name=schedule_group_name,
    tags=common_tags | {"Name": schedule_group_name},
)

# 2. Shared S3 Security Data Lake Bucket for Raw Logs & Checkpoints
data_lake_bucket_name = f"{project_prefix}-data-lake-{account_id}-{environment}"
data_lake_bucket = aws.s3.Bucket(
    data_lake_bucket_name,
    bucket=data_lake_bucket_name,
    tags=common_tags | {"Name": data_lake_bucket_name},
)

# Output collections
lambda_arns = {}
secret_arns = {}
schedule_arns = {}

# 3. Create repetitive collector resources per product
for product, settings in collector_products.items():
    rate_mins = settings["rate_minutes"]
    timeout_secs = settings["timeout_seconds"]
    memory_mb = settings["memory_size"]
    sink_list = settings["sinks"]

    res_suffix = f"{product}-{environment}"
    lambda_name = f"{project_prefix}-lmb-{res_suffix}"
    secret_name = f"{project_prefix}-scrt-{product}-credentials"
    log_group_name = f"/aws/lambda/{lambda_name}"
    schedule_name = f"{project_prefix}-sch-{res_suffix}"

    # A. Secrets Manager Secret
    secret = aws.secretsmanager.Secret(
        secret_name,
        name=secret_name,
        description=f"API credentials for SecOps log collection plugin: {product}",
        tags=common_tags | {"Name": secret_name, "Source": product},
    )
    secret_arns[product] = secret.arn

    # B. IAM Policies & Roles
    # Assume role policy for Lambda
    lambda_assume_role = aws.iam.get_policy_document(
        statements=[
            aws.iam.GetPolicyDocumentStatementArgs(
                effect="Allow",
                principals=[
                    aws.iam.GetPolicyDocumentStatementPrincipalArgs(
                        type="Service",
                        identifiers=["lambda.amazonaws.com"],
                    )
                ],
                actions=["sts:AssumeRole"],
            )
        ]
    )

    # Assume role policy for EventBridge Scheduler
    scheduler_assume_role = aws.iam.get_policy_document(
        statements=[
            aws.iam.GetPolicyDocumentStatementArgs(
                effect="Allow",
                principals=[
                    aws.iam.GetPolicyDocumentStatementPrincipalArgs(
                        type="Service",
                        identifiers=["scheduler.amazonaws.com"],
                    )
                ],
                actions=["sts:AssumeRole"],
            )
        ]
    )

    # CloudWatch Logs Policy
    cw_log_policy_doc = aws.iam.get_policy_document(
        statements=[
            aws.iam.GetPolicyDocumentStatementArgs(
                sid="CloudWatchLogging",
                effect="Allow",
                actions=["logs:CreateLogStream", "logs:PutLogEvents"],
                resources=["arn:aws:logs:*:*:*"],
            )
        ]
    )

    # Secrets Access Policy (least privilege: only this product's secret)
    secrets_policy_doc = aws.iam.get_policy_document(
        statements=[
            aws.iam.GetPolicyDocumentStatementArgs(
                sid="SecretsManagerRead",
                effect="Allow",
                actions=["secretsmanager:GetSecretValue", "secretsmanager:DescribeSecret"],
                resources=[secret.arn],
            )
        ]
    )

    # S3 Data Lake & Checkpoint Access Policy
    s3_policy_doc = aws.iam.get_policy_document(
        statements=[
            aws.iam.GetPolicyDocumentStatementArgs(
                sid="S3DataLakeIngest",
                effect="Allow",
                actions=["s3:PutObject", "s3:GetObject"],
                resources=[data_lake_bucket.arn.apply(lambda arn: f"{arn}/*")],
            )
        ]
    )

    lambda_exec_role = aws.iam.Role(
        f"{project_prefix}-iam-r-{res_suffix}-lambda",
        name=f"{project_prefix}-iam-r-{res_suffix}-lambda",
        assume_role_policy=lambda_assume_role.json,
        tags=common_tags | {"Name": f"{project_prefix}-iam-r-{res_suffix}-lambda"},
    )

    scheduler_role = aws.iam.Role(
        f"{project_prefix}-iam-r-{res_suffix}-scheduler",
        name=f"{project_prefix}-iam-r-{res_suffix}-scheduler",
        assume_role_policy=scheduler_assume_role.json,
        tags=common_tags | {"Name": f"{project_prefix}-iam-r-{res_suffix}-scheduler"},
    )

    # Attach policies to Lambda Role
    aws.iam.RolePolicy(
        f"{project_prefix}-p-cw-{res_suffix}",
        role=lambda_exec_role.name,
        policy=cw_log_policy_doc.json,
    )
    aws.iam.RolePolicy(
        f"{project_prefix}-p-sm-{res_suffix}",
        role=lambda_exec_role.name,
        policy=secrets_policy_doc.json,
    )
    aws.iam.RolePolicy(
        f"{project_prefix}-p-s3-{res_suffix}",
        role=lambda_exec_role.name,
        policy=s3_policy_doc.json,
    )

    # Attach Lambda Invoke to Scheduler Role
    scheduler_invoke_policy_doc = aws.iam.get_policy_document(
        statements=[
            aws.iam.GetPolicyDocumentStatementArgs(
                sid="SchedulerInvokeLambda",
                effect="Allow",
                actions=["lambda:InvokeFunction"],
                resources=[
                    pulumi.Output.concat("arn:aws:lambda:", region_name, ":", account_id, f":function:{lambda_name}"),
                    pulumi.Output.concat("arn:aws:lambda:", region_name, ":", account_id, f":function:{lambda_name}:*"),
                ],
            )
        ]
    )
    aws.iam.RolePolicy(
        f"{project_prefix}-p-invoke-{res_suffix}",
        role=scheduler_role.name,
        policy=scheduler_invoke_policy_doc.json,
    )

    # C. CloudWatch Log Group
    cw_log_group = aws.cloudwatch.LogGroup(
        f"{project_prefix}-cw-{res_suffix}",
        name=log_group_name,
        retention_in_days=30,
        tags=common_tags | {"Name": log_group_name},
    )

    # D. Lambda Function
    collector_lambda = aws.lambda_.Function(
        lambda_name,
        name=lambda_name,
        role=lambda_exec_role.arn,
        handler="secops_collector.lambda_handler.lambda_handler",
        runtime="python3.11",
        timeout=timeout_secs,
        memory_size=memory_mb,
        architectures=["x86_64"],
        environment=aws.lambda_.FunctionEnvironmentArgs(
            variables={
                "SOURCE_TYPE": product,
                "SINK_TYPES": ",".join(sink_list),
                "SECRETS_BACKEND": "secretsmanager",
                "STATE_BACKEND": "s3",
                "STATE_BUCKET": data_lake_bucket.id,
                "SECRET_NAME_OVERRIDE": secret.name,
            }
        ),
        tags=common_tags | {"Name": lambda_name, "Source": product},
        opts=pulumi.ResourceOptions(depends_on=[cw_log_group]),
    )
    lambda_arns[product] = collector_lambda.arn

    # E. EventBridge Scheduler Schedule
    schedule_input = json.dumps(
        {
            "source_type": product,
            "sink_types": sink_list,
            "time_window_minutes": rate_mins,
        }
    )

    schedule = aws.scheduler.Schedule(
        schedule_name,
        name=schedule_name,
        group_name=schedule_group.name,
        flexible_time_window=aws.scheduler.ScheduleFlexibleTimeWindowArgs(mode="OFF"),
        schedule_expression=f"rate({rate_mins} minutes)",
        state="ENABLED",
        target=aws.scheduler.ScheduleTargetArgs(
            arn=collector_lambda.arn,
            role_arn=scheduler_role.arn,
            input=schedule_input,
            retry_policy=aws.scheduler.ScheduleTargetRetryPolicyArgs(
                maximum_event_age_in_seconds=3600,
                maximum_retry_attempts=2,
            ),
        ),
        opts=pulumi.ResourceOptions(depends_on=[collector_lambda]),
    )
    schedule_arns[product] = schedule.arn

# Export outputs
pulumi.export("schedule_group_name", schedule_group.name)
pulumi.export("data_lake_bucket", data_lake_bucket.id)
pulumi.export("lambda_arns", lambda_arns)
pulumi.export("secret_arns", secret_arns)
pulumi.export("schedule_arns", schedule_arns)
