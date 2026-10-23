"""MITRE technique automation scripts.

Each module in this package defines exactly one ``TechniqueScript`` and
registers it with ``@technique``. Importing the package is not enough — the
registry loads every module lazily via ``load_all_techniques()``.
"""
