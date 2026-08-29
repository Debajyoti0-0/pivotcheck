"""Enable `python -m pivotcheck` execution.

Delegates entirely to the CLI entry point so both invocation styles behave
identically:

    python -m pivotcheck discover
    pivotcheck discover        (console script)
"""

from pivotcheck.cli import entry_point

if __name__ == "__main__":
    entry_point()
