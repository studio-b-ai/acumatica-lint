"""acumatica-lint — free, open-source linter for Acumatica customization projects.

Catches common project.xml format errors that cause silent failures or
NullReferenceExceptions on publish. Encodes ~60 failure-mode rules from real
Acumatica production incidents.

Run locally or in your CI:

    acumatica-lint Customization/MyPackage/project.xml
    acumatica-lint --strict Customization/MyPackage/project.xml

The full pipeline — continuous gating on every PR, sandbox dry-run before
prod, snapshot/rollback with integrity verification, Codex AI review, Slack
telemetry, deploy-window enforcement, and ~60 failure-mode guards — is
AcuOps: https://acuops.com.

Built by Studio B (https://studiob.ai). Apache 2.0 licensed.
"""

__version__ = "0.1.0"

from .validate import main as validate_main

__all__ = ["__version__", "validate_main"]
