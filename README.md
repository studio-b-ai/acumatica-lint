# acumatica-lint

[![PyPI](https://img.shields.io/pypi/v/acumatica-lint.svg)](https://pypi.org/project/acumatica-lint/)
[![License: Apache 2.0](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)
[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/downloads/)

> Free, open-source linter for Acumatica customization projects. Catches publish-time failure modes — silent `NullReferenceException`s, dropped DAC extensions, orphan SiteMap rows, GI catalog exclusions, schema mutations without `IF NOT EXISTS` guards — before they restart your production app pool.
>
> Want this run automatically on every PR, plus sandbox dry-run before prod, snapshot/rollback with integrity verification, Codex AI review, Slack telemetry, and deploy-window enforcement? → **[AcuOps](https://acuops.com)**

## Install

```bash
pip install acumatica-lint
```

Python 3.10+. One dependency (`pyyaml` for the ISV co-publish allowlist parser). Works on macOS, Linux, and Windows.

## Use

Point it at a `project.xml`:

```bash
acumatica-lint Customization/MyPackage/project.xml
```

With strict mode (additional warnings for best-practice violations):

```bash
acumatica-lint --strict Customization/MyPackage/project.xml
```

ISV authors — enforce a class-name prefix on all `<Graph>` declarations:

```bash
acumatica-lint --isv-prefix AO Customization/MyISV/project.xml
```

Debug-only DLL-source plugin scan (skips XML/Graph/semantic checks):

```bash
acumatica-lint --dll-source-only Customization/MyPackage/project.xml
```

### Exit codes

- `0` — passed (with or without warnings)
- `1` — failed (one or more hard-fail errors)
- `2` — usage error (bad CLI args)

## What it catches

`acumatica-lint` encodes ~60 failure-mode rules from real Acumatica production incidents Studio B has resolved. A non-exhaustive list:

- **DAC fields without matching `<Sql>` ALTER TABLE** — auto-column creation has been broken on cloud Acumatica since early 2026. `[PXDBx]` fields without a corresponding `<Sql>` ALTER will silently fail at publish.
- **Phantom DAC references in `<GITable Name>`** — silently aborts GI processing without an error in the publish log.
- **GI Creation Contract** — every new OData-exposed GI requires `<RolesInGraph Rolename="*" Accessrights="4" ApplicationName="/" />` AND a matching entry in the package's `CustomizationPlugin` allowlist. Miss either and the GI silently catalog-excludes, returning HTTP 404 from `/OData/{tenant}/$metadata`.
- **SiteMap orphans** (`ParentID="00000000-..."`) — invisible in `SM205010 (Access Rights by Role)`, ungrantable, OData 404.
- **Modern GI format requirements** (24.208+) — `GITable.Name` must be fully-qualified DAC name; `<GIWhere Condition>` must use Acumatica's vocabulary (`"E "`, `"NE"`, `"GE"`, etc., NOT `"EQ"`); `<GIWhere>` attribute name is `Operation=` NOT `Operator=`; `MUIScreen.SubcategoryID` must point at tenant-real subcategory, not auto-created system-default.
- **`<Sql>` re-execution warnings** — `<Sql>` scripts are tracked by Name; bumping to `_v2` is silently skipped. For logic that must survive every publish, use `CustomizationPlugin.PXDatabase.Execute()`.
- **DAC extension fields without `<EntityEndpoint>` mapping** — `PUT` returns HTTP 200 + echoes value + silent-drops at commit. Three places must match: SQL column, DAC attribute, inline `<EntityEndpoint>` block.
- **C# CustomizationPlugin static checks** — banned APIs (`WebConfigurationManager`, `HttpContext`); SQL against GI* tables in `UpdateDatabase()`; SQL against `INUnit`; INSERT/UPDATE/SELECT column refs on Acumatica system tables outside the allowlist.
- **DLL source reference auditing** — gap-closer for compiled-DLL plugins: every plugin check runs on every `.cs` under `src/<DllName>/` when `project.xml` references `<File AppRelativePath="Bin\<DllName>.dll" />`.
- **ISV prefix enforcement** — when invoked with `--isv-prefix`, validates that every `<Graph ClassName=>` follows your ISV convention.
- **Inline `<EntityEndpoint>` block requirements** — must be a top-level child of `<Customization>` in `project.xml`; standalone `EntityEndpoint_*.xml` at zip root is NOT processed.

Every hard-fail check ships an escape-hatch comment marker for audited exceptions:

```xml
<!-- REVIEWED: gi-sql-safe       — suppress validate_gi_sql -->
<!-- REVIEWED: inunit-sql-safe   — suppress validate_inunit_sql -->
<!-- REVIEWED: schema-safe       — suppress validate_plugin_sql_column_refs -->
```

## What this linter is NOT

This linter is the deterministic check engine. It runs once, against one project, returns errors and warnings, exits.

It does **not**:

- Run continuously on every PR
- Push your customization to a sandbox tenant and run an end-to-end test suite before allowing the prod publish
- Take a snapshot of your current customization state with integrity verification before each publish (catching `merge=true` partial-publish corruption)
- Roll back automatically when a publish fails midway
- Review the C# code in `CustomizationPlugin.UpdateDatabase()` with AI to flag non-obvious correctness issues a static rule can't catch
- Post `:rotating_light:` Slack notifications when a publish fails
- Enforce deploy windows (no schema changes during business hours)
- Coordinate co-publishes with ISV packages without inflating the `publishBegin` page count past Acumatica's `ThreadAbortException` limit
- Issue + revoke per-VAR license keys with grace periods

All of that is **[AcuOps](https://acuops.com)** — the managed pipeline. $800/mo per Acumatica instance.

## Founding partners

AcuOps is selecting 7–10 founding partners locked at **$500/mo for the life of subscription** in exchange for a published case study + reference availability. We're picking partners across VAR, ISV, in-house mid-market, and enterprise deployment patterns. → [Apply](https://acuops.com/founding-partners)

## Contributing

Pull requests welcome. New rules should:

1. Reference the originating production incident (AAR date, PR number, or both) in a comment
2. Ship with both a positive example (`project.xml` snippet that triggers the rule) and a negative example
3. Include an escape-hatch comment marker if the rule may have legitimate exceptions

Coding style is enforced by `ruff`. Run `pip install -e ".[dev]"` then `ruff check src/`.

## License

Apache 2.0 — see [LICENSE](./LICENSE).

The Apache 2.0 patent grant protects all contributors from patent litigation over contributed code. This matters when the codebase encodes hard-won failure-mode knowledge from real production incidents.

## Built by Studio B

Studio B ([studiob.ai](https://studiob.ai)) runs Acumatica deployments at scale across its portfolio. `acumatica-lint` is the static-check engine extracted from the AcuOps pipeline — the same code paths Studio B uses against its own production deployments.

The full pipeline → [acuops.com](https://acuops.com)
