# Contributing

CloudAudit is developed by **xtawb**. Contributions are welcome via pull
request.

## Development Setup

```bash
git clone https://github.com/xtawb/cloudaudit
cd cloudaudit
pip install -e ".[all]"
pip install pytest pytest-asyncio
```

Verify your setup with the built-in self-test before making changes:

```bash
cloudaudit selftest
```

The project does not yet ship a `tests/` directory. If you're contributing a
fix or feature, adding a `tests/` package with `pytest` coverage for it is
strongly encouraged — run it with:

```bash
python -m pytest tests/ -v
```

All tests must pass before submitting a pull request.

## Code Standards

- Python 3.11+ type annotations required on all public functions
- All new modules must include a module-level docstring explaining purpose
  and design
- `from __future__ import annotations` in all files
- No external telemetry, analytics, or "call home" code

## Adding Detection Patterns

New secret patterns can be added either directly to
`scanners/secret_scanner.py` or, for a lower-friction contribution, as a
[custom pattern plugin](configuration.md#custom-secret-patterns) — either
way, include:

1. **Regex** — a compiled pattern targeting the specific credential format
2. **Entropy minimum** — a justified Shannon entropy threshold
3. **Validator** — a Python callable for provider-specific validation where
   applicable
4. **Context keywords** — a list of surrounding keywords that increase
   confidence
5. **Compliance references** — applicable CIS/NIST/SOC2/PCI-DSS/ISO27001
   controls
6. **Test case** — a test with a real-format (non-functional) sample

Pattern severity guidelines:

- **Critical** — direct account compromise possible (cloud credentials,
  private keys)
- **High** — significant risk requiring 24-72h remediation (passwords, PATs)
- **Medium** — moderate risk requiring investigation (JWT tokens, generic
  API keys)
- **Low** — informational, low direct impact (emails, internal IPs)

## Adding Scanner Plugins

Third-party scanners can also be distributed as installable plugins rather
than patched directly into the core scanner — see
[Detection Algorithms → Extensibility: Scanner Plugins](detection-algorithms.md#extensibility-scanner-plugins)
for the entry-point interface (`cloudaudit/scanners/plugin_loader.py`).

## AI Prompt Changes

Changes to AI prompts (in `ai/providers.py`, `ai/analyzer.py`) require
explicit review to ensure:

1. No exploitation guidance is introduced
2. The defensive framing is maintained
3. The response format remains parseable

The review criterion is: *"Could this prompt output be used to attack a
system?"* If yes, the prompt must be revised.

## Security Considerations

Any contribution that adds:

- HTTP write methods (PUT, DELETE, PATCH)
- External data transmission beyond the configured AI provider or an
  explicitly user-supplied `--webhook-url`
- Code that logs or stores raw secret values

will be rejected. CloudAudit's core value proposition is defensive,
read-only operation.

## Versioning

Follow semantic versioning ([semver.org](https://semver.org)):

- **MAJOR** (X.0.0) — breaking changes to CLI interface or output format
- **MINOR** (0.X.0) — new detection patterns, providers, or report sections
- **PATCH** (0.0.X) — bug fixes, false-positive reductions, performance
  improvements

## Contact

**xtawb** — [https://linktr.ee/xtawb](https://linktr.ee/xtawb)

Repository: [https://github.com/xtawb/cloudaudit](https://github.com/xtawb/cloudaudit)

## Continuous integration (v1.4.0)

`.github/workflows/tests.yml` runs on every push and pull request, on Linux
and Windows:

```bash
python -m unittest discover -s tests -t . -v
cloudaudit selftest
cloudaudit benchmark --min-precision 0.97 --min-recall 0.95
```

The benchmark is a regression gate. When you add or change a detection rule:

1. Add the case that motivated it to `intelligence/benchmark.py` — a positive
   (planted secret) **and**, where it applies, a negative that looks similar.
2. If you found a false positive in the wild, add it as a negative first, see
   it fail, then fix the rule.
3. Never put a credential literal in the repository; assemble synthetic
   values at runtime as the corpus and the tests do.

## Publishing to PyPI

`.github/workflows/publish.yml` is manual (`workflow_dispatch`) and uses PyPI
Trusted Publishing — no API token is stored anywhere. One-time setup:

1. Create an account on pypi.org and, under *Publishing*, add a pending
   publisher: owner `xtawb`, repository `cloudaudit`, workflow `publish.yml`,
   environment `pypi`.
2. In the GitHub repository settings, create an environment named `pypi`.
3. Run the workflow from the *Actions* tab after tagging a release.
