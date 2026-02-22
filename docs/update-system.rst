Update System
=============

Source: ``config_mgr/updater.py``

CloudAudit checks for new releases at startup and offers to update automatically.

Behaviour
---------

1. At startup, CloudAudit silently checks the GitHub releases API:

   .. code-block:: text

      GET https://api.github.com/repos/xtawb/cloudaudit/releases/latest

2. If a newer version is found (semantic version comparison), the user is prompted:

   .. code-block:: text

      A new version is available (v2.1.0).
      Do you want to update now? [Y/n]:

3. **If declined**: Displays the current version, marks the tool as outdated, and
   continues execution normally.

4. **If accepted**: Runs ``pip install --upgrade`` from the GitHub repository,
   displays the changelog URL, and confirms success.

5. **On update failure**: Reports the error message and continues running the current
   version. No rollback is needed — the existing installation is unchanged.

6. **On network failure**: The update check is always silent and non-fatal. If the
   GitHub API is unreachable, CloudAudit continues normally.

Disable Update Check
--------------------

.. code-block:: bash

   cloudaudit --no-update-check -u https://...

Or set the environment variable:

.. code-block:: bash

   CLOUDAUDIT_NO_UPDATE=1 cloudaudit -u https://...

Version Comparison
------------------

Versions are compared using semantic versioning:

.. code-block:: python

   def _compare_versions(v1: str, v2: str) -> int:
       """Return -1 if v1 < v2, 0 if equal, 1 if v1 > v2."""

Pre-release versions (e.g. ``2.1.0-beta.1``) are not offered as updates.

Timeout
-------

The update check has a 6-second timeout. If the GitHub API does not respond within this
window, the check is abandoned silently.
