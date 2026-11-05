# AGENTS.md — SecOps Log Collector Guidelines

Canonical operational rules for autonomous and pair-programming AI coding agents operating on `secops-log-collector`.

---

## 1. Zero-Leak & Sanitization Invariant (CRITICAL)

- **Strict Proprietary Sanitization:** Agents MUST NOT insert, commit, or reference proprietary company names, legacy studio labels, internal AWS account numbers, real production endpoint URLs, or live API credentials.
- **Sanitized Test Fixtures:** All test fixtures and examples MUST use RFC 2606 reserved domains (`example.com`, `example.org`, `localhost`) and dummy UUIDs or tokens (`tok_123`, `mock_bearer_token`).
- **Adversarial Gate:** Prior to submitting changes, agents MUST execute `python adversarial_review.py` and ensure a 0-violation outcome.

---

## 2. Architecture & Code Style Standards

- **Python Runtime:** Python 3.11+ using modern typing conventions (`from __future__ import annotations`, `List`, `Dict`, `Optional`).
- **Schema Validation:** Core data transfer models MUST inherit from `pydantic.BaseModel` with field descriptions and UTC timezone validation.
- **Error Handling:** All external HTTP calls MUST route through `RobustRateLimiter` to honor `Retry-After` headers and 429 backoff.
- **Modularity:**
  - Source plugins reside in `secops_collector/sources/` and inherit from `BaseSource`.
  - Sink plugins reside in `secops_collector/sinks/` and inherit from `BaseSink`.
  - Infrastructure modules in `infra/pulumi/` and `infra/opentofu/` must remain in sync.

---

## 3. Testing & Verification Gate

- **Unit Test Coverage:** Every new source or sink MUST have corresponding unit tests in `tests/`.
- **Zero-Sleep Mocking:** Tests MUST inject `mock_sleep_recorder` or custom sleep callables into `RobustRateLimiter` to avoid sleeping during test runs.
- **100% Test Pass Rate:** `python -m pytest` must run with 0 failures and 0 errors.

---

## 4. Change Protocol

1. Create or modify code in clean feature branch.
2. Run `ruff check .` and `ruff format .`.
3. Run `python adversarial_review.py` to confirm zero leaks, syntax validity, and 100% test pass.
4. Commit using Conventional Commits (`feat:`, `fix:`, `docs:`, `test:`, `refactor:`).
