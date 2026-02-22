Configuration
=============

API Key Management
------------------

CloudAudit provides a dedicated ``config`` subcommand for managing AI provider API keys securely.

Store a key (interactive, validates before saving):

.. code-block:: bash

   cloudaudit config --set-api gemini
   cloudaudit config --set-api openai
   cloudaudit config --set-api claude
   cloudaudit config --set-api deepseek

List all configured providers:

.. code-block:: bash

   cloudaudit config --list-providers

Remove a stored key:

.. code-block:: bash

   cloudaudit config --remove-api openai

Storage Security
~~~~~~~~~~~~~~~~

Keys are stored at ``~/.cloudaudit/config.enc`` using Fernet symmetric encryption:

* **Algorithm**: AES-128-CBC + HMAC-SHA256 (Fernet)
* **Key derivation**: PBKDF2-SHA256 (100,000 iterations, random 32-byte salt)
* **Salt location**: ``~/.cloudaudit/.salt`` (mode 600)
* **Config location**: ``~/.cloudaudit/config.enc`` (mode 600)
* **Keys are never logged** to any output stream

Live Validation
~~~~~~~~~~~~~~~

When a key is entered via ``config --set-api``, CloudAudit validates it by making a
minimal API call (e.g. listing available models) before saving. If validation fails,
provider-specific troubleshooting steps are displayed.

Environment Variables
---------------------

Instead of using the key manager, you can set environment variables:

.. list-table::
   :header-rows: 1
   :widths: 25 30 45

   * - Provider
     - Variable
     - Notes
   * - Google Gemini
     - ``GEMINI_API_KEY``
     - Starts with ``AIza``
   * - OpenAI
     - ``OPENAI_API_KEY``
     - Starts with ``sk-``
   * - Anthropic Claude
     - ``ANTHROPIC_API_KEY``
     - Starts with ``sk-ant-``
   * - DeepSeek
     - ``DEEPSEEK_API_KEY``
     - Starts with ``sk-``
   * - Custom endpoint
     - ``CUSTOM_LLM_API_KEY``
     - Any format

Alternatively, create a ``.cloudaudit.env`` file in your working directory (mode 600):

.. code-block:: bash

   GEMINI_API_KEY=AIzaSy...
   OPENAI_API_KEY=sk-...

Key Resolution Order
--------------------

CloudAudit resolves API keys in this order:

1. ``--api-key`` CLI flag
2. Provider-specific environment variable (e.g. ``GEMINI_API_KEY``)
3. Generic ``CLOUDAUDIT_API_KEY`` environment variable
4. ``.cloudaudit.env`` file in working directory
5. Encrypted key store (``~/.cloudaudit/config.enc``)

Performance Tuning
------------------

.. list-table::
   :header-rows: 1
   :widths: 30 15 55

   * - Flag
     - Default
     - Description
   * - ``-t`` / ``--threads``
     - 8
     - Concurrent HTTP request workers
   * - ``--timeout``
     - 30.0
     - Per-request timeout in seconds
   * - ``--rate-limit``
     - 0.15
     - Delay in seconds between requests (politeness)
   * - ``--max-size``
     - 20971520
     - Maximum per-file download size in bytes (20 MB)
   * - ``--max-depth``
     - 15
     - Maximum recursive crawl depth

Scan Scope Control
------------------

Restrict what files are analysed:

.. code-block:: bash

   # Only scan specific file extensions
   cloudaudit -u https://... --extensions env,json,yml,py,sql

   # Skip certain path prefixes
   cloudaudit -u https://... --ignore-paths logs,tmp,cache

   # Only report findings at HIGH severity and above
   cloudaudit -u https://... --min-severity HIGH
