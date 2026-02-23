# docs/conf.py — Sphinx configuration for CloudAudit
# Primary documentation uses MkDocs (mkdocs.yml); this file provides
# Sphinx compatibility for environments that require it.

import sys
import os

# Allow importing the package without installation
sys.path.insert(0, os.path.abspath(".."))

# Pull version dynamically from the package
try:
    from cloudaudit.core.constants import __version__
except ImportError:
    __version__ = "1.0.2"

# ── Project metadata ───────────────────────────────────────────────────────────

project = "CloudAudit"
author = "xtawb"
copyright = f"2025, {author}"
version = __version__
release = __version__

# ── Extensions ─────────────────────────────────────────────────────────────────

extensions = [
    "sphinx.ext.autodoc",
    "sphinx.ext.napoleon",
    "sphinx.ext.viewcode",
    "sphinx.ext.intersphinx",
    "sphinx.ext.todo",
    "sphinx_autodoc_typehints",
]

# ── Autodoc configuration ──────────────────────────────────────────────────────

autodoc_default_options = {
    "members": True,
    "member-order": "bysource",
    "special-members": "__init__",
    "undoc-members": True,
    "exclude-members": "__weakref__",
}

napoleon_google_docstring = True
napoleon_numpy_docstring = False
napoleon_include_init_with_doc = False
napoleon_include_private_with_doc = False

# ── HTML output ────────────────────────────────────────────────────────────────

html_theme = "furo"
html_title = f"CloudAudit {version}"

html_theme_options = {
    "light_css_variables": {
        "color-brand-primary": "#e65100",
        "color-brand-content": "#e65100",
    },
}

# ── Intersphinx mapping ────────────────────────────────────────────────────────

intersphinx_mapping = {
    "python": ("https://docs.python.org/3", None),
}

# ── General ────────────────────────────────────────────────────────────────────

exclude_patterns = ["_build", "Thumbs.db", ".DS_Store"]
todo_include_todos = True
