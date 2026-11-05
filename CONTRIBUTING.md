# Contributing to SecOps Log Collector

We welcome contributions to the Koality Assured SecOps Log Collector engine! Follow these guidelines to ensure consistency, high code quality, and strict security compliance.

---

## Development Workflow

### Prerequisites
- Python 3.11+
- [uv](https://github.com/astral-sh/uv) or `pip`
- Git

### Local Setup

1. Clone the repository:
   ```bash
   git clone https://github.com/koality-assured/secops-log-collector.git
   cd secops-log-collector
   ```

2. Create virtual environment and install dependencies:
   ```bash
   uv venv
   # On Windows:
   .venv\Scripts\activate
   # On Linux/macOS:
   source .venv/bin/activate

   uv pip install -e ".[dev]"
   ```

3. Run the test suite:
   ```bash
   python -m pytest -v
   ```

4. Run code formatting and linting:
   ```bash
   ruff check .
   ruff format .
   ```

---

## Adding a New Source Collector

1. Create a new collector module in `secops_collector/sources/<product_name>.py`.
2. Inherit from `BaseSource` and implement `collect(time_window, checkpoint)`.
3. Register the new plugin in `secops_collector/sources/__init__.py`.
4. Add comprehensive unit tests in `tests/test_sources.py` validating:
   - Pagination flow (Link headers, cursors, or page numbers).
   - Rate limit handling (HTTP 429 response backoff).
   - Mapping into standardized `LogEvent` schemas.
5. Update infrastructure definitions in `infra/pulumi/` and `infra/opentofu/`.

---

## Adding a New Output Sink

1. Create a new sink module in `secops_collector/sinks/<sink_name>.py`.
2. Inherit from `BaseSink` and implement `write(batch) -> int`.
3. Register the new sink in `secops_collector/sinks/__init__.py`.
4. Add unit tests in `tests/test_sinks.py` validating delivery and error handling.

---

## Commit & PR Guidelines

- Follow Conventional Commits:
  - `feat:` for new capabilities or collector plugins.
  - `fix:` for bug fixes.
  - `docs:` for documentation updates.
  - `test:` for test suite additions.
  - `refactor:` for code cleanups without behavior changes.
- Ensure 100% test pass rate:
  ```bash
  python adversarial_review.py
  ```
- No proprietary names, customer names, internal account numbers, or real tokens may appear anywhere in pull requests.
