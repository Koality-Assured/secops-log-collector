# Security Policy

## Supported Versions

The following versions of `secops-log-collector` currently receive security updates and patches:

| Version | Supported          |
| ------- | ------------------ |
| 1.0.x   | :white_check_mark: |
| < 1.0   | :x:                |

## Reporting a Vulnerability

Koality Assured takes the security of its infrastructure and logging pipelines seriously. If you discover a vulnerability, misconfiguration, or credential exposure in this repository, please do **NOT** open a public issue.

Instead, please submit a responsible disclosure report to:

- **Security Team Email:** `security@koalityassured.com`
- **PGP Key ID:** `0x4A1E2B3C` (Available upon request)

### What to Include in Your Report

To help us triage and resolve the issue quickly, please provide:
1. A description of the vulnerability and its potential impact.
2. Steps to reproduce the issue (proof of concept script or curl command without actual secrets).
3. The affected component (`core/`, `sources/`, `sinks/`, `infra/`).
4. Any potential remediations or mitigating controls.

### Response Timelines

- **Initial Response:** Within 24 hours of receipt.
- **Triage & Status Assessment:** Within 72 hours.
- **Resolution & Patch Deployment:** Critical vulnerabilities are patched within 7 business days.

## Architectural Security Standards

This project adheres to rigorous enterprise security controls:
- **Zero-Secret Storage:** No API tokens, keys, passwords, or cloud credentials may ever be committed to git or stored in configuration files.
- **Credential Segregation:** All source and sink credentials must be provisioned via AWS Secrets Manager or secure environment variables.
- **Least Privilege Access:** IAM execution roles are scoped strictly to the specific Secrets Manager secret, CloudWatch log group, and S3 path required for that specific collector function.
- **Sanitized Logging:** Telemetry and exception handlers strip query parameters, headers, and payload attributes that could potentially reflect sensitive credentials or authorization headers.
