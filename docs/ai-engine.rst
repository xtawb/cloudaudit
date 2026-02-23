AI Engine
=========

CloudAudit integrates AI across three distinct functions:

1. **Semantic file analysis** — Understanding file intent, not just pattern matching
2. **Anomaly scoring** — Entropy and pattern correlation to rate file risk
3. **Executive summary** — Human-readable CISO-level summary of the full audit

AI Safety Principles
--------------------

All AI integration in CloudAudit is governed by strict safety rules:

* **No raw secrets transmitted**: Content is sanitised before sending (base64 truncation, PEM replacement)
* **No exploitation guidance**: All AI prompts explicitly forbid attack path generation or weaponisation advice
* **Defensive framing only**: Prompts are written from the perspective of a defensive security auditor
* **Heuristic fallback**: The ``HeuristicProvider`` always runs if no AI provider is configured — no API required

Provider Abstraction Layer
--------------------------

Source: ``ai/providers.py``

All providers implement the ``AIProvider`` abstract base class with three methods:

.. code-block:: python

   class AIProvider(ABC):
       def complete(self, prompt: str, max_tokens: int) -> AIResponse: ...
       def generate_executive_summary(self, audit_json: str) -> AIResponse: ...
       def analyse_file_content(self, filename, filetype, content) -> AIResponse: ...
       def score_anomaly(self, filename, entropy_strings, patterns) -> AIResponse: ...

All responses are normalised to ``AIResponse(text, provider, model, latency_ms, tokens_used)``.

Provider Chain
--------------

The ``ProviderChain`` class wraps one primary provider and always appends
``HeuristicProvider`` as the final fallback:

.. code-block:: text

   [Configured Provider]  →  fails?  →  [HeuristicProvider]  →  always succeeds

Auth errors (HTTP 401, invalid key) are re-raised immediately rather than falling back —
they require user action and should not be silently swallowed.

Supported Providers
-------------------

Google Gemini
~~~~~~~~~~~~~

* **Dynamic model discovery**: Calls ``list_models()`` to find supported models before generation
* **Automatic fallback**: Automatically discovers compatible Gemini text models dynamically via ``client.models.list()`` and selects the most capable available model.
* **Requirement**: ``pip install cloudaudit[gemini]``

OpenAI
~~~~~~

* **Models**: ``gpt-4o-mini``, ``gpt-3.5-turbo`` (automatic fallback)
* **Auth detection**: 401 responses raise ``ProviderAuthError`` immediately (no retry)
* **Requirement**: ``pip install openai``

DeepSeek
~~~~~~~~

* Uses the OpenAI-compatible API endpoint at ``https://api.deepseek.com/v1``
* Same ``openai`` Python package, different base URL
* **Models**: ``deepseek-chat``, ``deepseek-coder``

Anthropic Claude
~~~~~~~~~~~~~~~~

* **Models**: ``claude-3-5-haiku-latest``, ``claude-3-haiku-20240307``
* **Requirement**: ``pip install anthropic``

Ollama (Local)
~~~~~~~~~~~~~~

* Calls ``http://localhost:11434/api/generate`` (configurable URL)
* No API key required
* ``validate_key()`` pings ``/api/tags`` to confirm the server is running
* Supports any model installed locally (``ollama pull llama3``)

Custom OpenAI-Compatible
~~~~~~~~~~~~~~~~~~~~~~~~

* Specify ``--provider custom --provider-url https://your-endpoint/v1``
* Works with self-hosted vLLM, LM Studio, Jan, and any OpenAI-compatible API

Heuristic (Built-in)
~~~~~~~~~~~~~~~~~~~~

* No API required, zero latency, always available
* Generates structured summaries from finding data using deterministic logic
* Produces the same executive summary structure as AI providers for consistent report format

Semantic File Analysis
----------------------

Source: ``ai/analyzer.py`` — ``AIFileAnalyzer``

The AI receives the following structured prompt for file analysis:

.. code-block:: text

   You are a cloud security analyst reviewing a file found in a publicly exposed
   cloud storage container.

   File: {filename}
   File Type: {filetype}
   Content (truncated, secrets partially redacted):
   {content}

   Identify any of the following:
   1. Credentials, API keys, tokens, or secrets
   2. Internal infrastructure details
   3. PII or sensitive personal data patterns
   4. Security misconfigurations
   5. Hardcoded environment-specific values
   6. Compliance violations

   For each finding, output JSON:
   {"findings": [{"type": "...", "description": "...", "severity": "critical|high|medium|low",
                  "line_hint": "...", "confidence": 0.0-1.0, "recommendation": "..."}]}

   Output ONLY valid JSON. No markdown fences.

The response is parsed and each item becomes an ``AIFinding`` (labelled ``[AI]`` in reports).

Anomaly Scoring
---------------

Source: ``ai/analyzer.py`` — ``AnomalyScorer``

For files where heuristic anomaly score exceeds 3.0, the AI is asked to score the
anomaly and provide a 2-sentence explanation:

.. code-block:: text

   {"score": 0-10, "explanation": "..."}

The final score blends heuristic (60%) and AI (40%) contributions.

The heuristic anomaly score is computed from:

* High-entropy string density ratio (lines with entropy >= threshold / total lines)
* Existing finding severity amplification (Critical: +1.5 per finding, High: +0.8)
* Sensitive keyword density (password, secret, token, key, etc.)
* File size relative to extension (small .env files score higher)

Executive Summary
-----------------

The AI is asked to produce a 4-6 paragraph executive summary:

1. Overall risk posture and exposure severity
2. Most critical finding categories and their business impact
3. Top 3 remediation priorities with estimated effort
4. Compliance framework gaps
5. Strategic recommendations

The prompt explicitly states: *"Do NOT suggest exploitation steps or attack paths."*

The summary is included in all report formats and printed to terminal with ``--verbose``.
