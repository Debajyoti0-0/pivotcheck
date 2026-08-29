"""Top-level entry point for the pivotcheck package.

Allows running the tool with `python __main__.py` from the project root.
This mirrors the behavior of `python -m pivotcheck` and the console script.
"""

from pivotcheck.cli import entry_point

if __name__ == "__main__":
    entry_point()
