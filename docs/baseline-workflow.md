# Baseline workflow

Create, inspect, compare, and remove saved network perspectives:

```text
pivotcheck --data-dir /engagement/data baseline create --name workstation
pivotcheck baseline list
pivotcheck baseline show workstation
pivotcheck compare workstation --format json
pivotcheck baseline delete workstation --yes
```

Baseline names are case-insensitive identifiers: lowercase letters, digits,
and hyphens only, with a 63-character limit. The data directory precedence is
the explicit `--data-dir`, then `PIVOTCHECK_DATA_DIR/pivotcheck`, then the
platform data directory (`XDG_DATA_HOME/pivotcheck` on Linux).

Files are JSON schema version 1 and are written to a temporary file before
`os.replace()`. Replacement is atomic when the underlying filesystem supports
same-directory atomic replacement; a failed replacement leaves the existing
file intact. Baselines contain sensitive reconnaissance evidence and are not
encrypted.
