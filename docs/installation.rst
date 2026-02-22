Installation
============

Requirements
------------

* Python 3.11 or later
* pip (any modern version)
* Network access to target cloud storage endpoints

Quick Install
-------------

.. code-block:: bash

   git clone https://github.com/xtawb/cloudaudit
   cd cloudaudit
   pip install -r requirements.txt
   pip install -e .

Verify installation:

.. code-block:: bash

   cloudaudit --version

Optional Dependencies
---------------------

The following packages unlock optional features:

.. list-table::
   :header-rows: 1
   :widths: 30 30 40

   * - Package
     - Feature
     - Install
   * - ``google-generativeai``
     - Google Gemini AI summaries and analysis
     - ``pip install google-generativeai``
   * - ``openai``
     - OpenAI GPT and DeepSeek AI (OpenAI-compatible)
     - ``pip install openai``
   * - ``anthropic``
     - Anthropic Claude AI
     - ``pip install anthropic``
   * - ``Pillow``
     - EXIF metadata extraction from images
     - ``pip install Pillow``
   * - ``cryptography``
     - Encrypted local API key storage
     - ``pip install cryptography``
   * - ``py7zr``
     - 7-Zip archive extraction
     - ``pip install py7zr``

All-in-one with all optional features:

.. code-block:: bash

   pip install cloudaudit[all]

Environment
-----------

No special environment configuration is required for basic operation.
See :doc:`configuration` for AI provider and API key setup.
