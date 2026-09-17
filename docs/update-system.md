# Update System

Source: `config_mgr/updater.py`

CloudAudit checks for new releases at startup and offers to update
automatically.

## Behaviour

1. At startup, CloudAudit silently checks the GitHub releases API:

   ```text
   GET https://api.github.com/repos/xtawb/cloudaudit/releases/latest
   ```

2. If a newer version is found (semantic version comparison), the user is
   prompted:

   ```text
   A new version is available (v1.3.0).
   Do you want to update now? [Y/n]:
   ```

3. **If declined** — displays the current version, marks the tool as
   outdated, and continues execution normally.
4. **If accepted** — runs `pip install --upgrade` from the GitHub
   repository, displays the changelog URL, and confirms success.
5. **On update failure** — reports the error message and continues running
   the current version. No rollback is needed — the existing installation
   is unchanged.
6. **On network failure** — the update check is always silent and
   non-fatal. If the GitHub API is unreachable, CloudAudit continues
   normally.

## Disable the Update Check

```bash
cloudaudit --no-update -u https://mybucket.s3.amazonaws.com/ \
           --confirm-ownership --org-name "Acme Corp"
```

## Version Comparison

Versions are compared using semantic versioning:

```python
def _compare_versions(v1: str, v2: str) -> int:
    """Return -1 if v1 < v2, 0 if equal, 1 if v1 > v2."""
```

Pre-release versions (e.g. `1.3.0-beta.1`) are not offered as updates.

## Timeout

The update check has a short timeout (a few seconds). If the GitHub API does
not respond within this window, the check is abandoned silently and the scan
proceeds unaffected.

## Local Scan History

Related but separate from the update system: CloudAudit also keeps a local
record of past scans (unless `--no-history` is passed) in a SQLite database
at `~/.cloudaudit/history.db`. This powers `cloudaudit history` and the
exposure trend delta described in [Risk Engine](risk-engine.md). It never
leaves your machine and no scan data is ever sent as part of the update
check.

```bash
cloudaudit history --limit 10
```

## Continuous / Interval Scanning

For drift detection, `--interval SECONDS` re-runs the same scan on a timer
until interrupted (Ctrl+C), recording every run to local history so you can
track how a target's exposure changes over time:

```bash
cloudaudit -u https://mybucket.s3.amazonaws.com/ \
           --confirm-ownership --org-name "Acme Corp" \
           --interval 3600
```
