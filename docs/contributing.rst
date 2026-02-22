Contributing
============

CloudAudit is developed by **xtawb**. Contributions are welcome via pull request.

Development Setup
-----------------

.. code-block:: bash

   git clone https://github.com/xtawb/cloudaudit
   cd cloudaudit
   pip install -e ".[dev]"
   pip install pytest pytest-asyncio

Run tests:

.. code-block:: bash

   python3 -m pytest tests/ -v

All tests must pass before submitting a pull request.

Code Standards
--------------

* Python 3.11+ type annotations required on all public functions
* All new modules must include a module-level docstring explaining purpose and design
* ``from __future__ import annotations`` in all files
* No external telemetry, analytics, or "call home" code

Adding Detection Patterns
--------------------------

New secret patterns must include:

1. **Regex**: A compiled pattern targeting the specific credential format
2. **Entropy minimum**: A justified Shannon entropy threshold
3. **Validator**: A Python callable for provider-specific validation where applicable
4. **Context keywords**: A list of surrounding keywords that increase confidence
5. **Compliance references**: Applicable CIS/NIST/SOC2/PCI-DSS/ISO27001 controls
6. **Test case**: A test in ``tests/test_secret_scanner.py`` with a real-format (non-functional) sample

Pattern severity guidelines:

* **Critical**: Direct account compromise possible (cloud credentials, private keys)
* **High**: Significant risk requiring 24-72h remediation (passwords, PATs)
* **Medium**: Moderate risk requiring investigation (JWT tokens, generic API keys)
* **Low**: Informational, low direct impact (emails, internal IPs)

AI Prompt Changes
-----------------

Changes to AI prompts (in ``ai/providers.py``) require explicit review to ensure:

1. No exploitation guidance is introduced
2. The defensive framing is maintained
3. The response format remains parseable

The review criterion is: *"Could this prompt output be used to attack a system?"*
If yes, the prompt must be revised.

Security Considerations
-----------------------

Any contribution that adds:

* HTTP write methods (PUT, DELETE, PATCH)
* External data transmission (beyond the configured AI provider)
* Code that logs or stores raw secret values

will be rejected. CloudAudit's core value proposition is defensive, read-only operation.

Versioning
----------

Follow semantic versioning (semver.org):

* **MAJOR** (X.0.0): Breaking changes to CLI interface or output format
* **MINOR** (0.X.0): New detection patterns, providers, or report sections
* **PATCH** (0.0.X): Bug fixes, false-positive reductions, performance improvements

Branch Strategy
---------------

* ``main``: Stable releases only
* ``develop``: Integration branch
* ``feature/name``: Feature branches (merge into develop)
* ``fix/name``: Hotfix branches (merge into main and develop)

Contact
-------

**xtawb** — [https://linktr.ee/xtawb](https://linktr.ee/xtawb)

Repository: https://github.com/xtawb/cloudaudit
