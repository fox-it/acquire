extensions = [
    "autoapi.extension",
    "sphinx.ext.autodoc",
    "sphinx.ext.autosectionlabel",
    "sphinx.ext.doctest",
    "sphinx.ext.napoleon",
    "sphinx_argparse_cli",
]

exclude_patterns = []

html_theme = "furo"

autoapi_type = "python"
autoapi_dirs = ["../../acquire/"]
autoapi_ignore = ["*tests*", "*.tox*", "*venv*", "*examples*"]
autoapi_python_use_implicit_namespaces = True
autoapi_add_toctree_entry = False
autoapi_root = "api"
autoapi_options = [
    "members",
    "undoc-members",
    "show-inheritance",
    "show-module-summary",
    "special-members",
    "imported-members",
]
autoapi_keep_files = True
autoapi_template_dir = "_templates/autoapi"

autodoc_typehints = "signature"
autodoc_member_order = "groupwise"

autosectionlabel_prefix_document = True
