"""Sphinx configuration; build against the installed native extension."""
project = "pyjosers"
author = "Kushal Das"
copyright = "2026, Kushal Das"
release = "0.1.0"
extensions = ["sphinx.ext.autodoc", "sphinx.ext.napoleon", "sphinx.ext.doctest"]
html_theme = "furo"
exclude_patterns = ["_build"]
autodoc_member_order = "bysource"
autodoc_typehints = "description"
