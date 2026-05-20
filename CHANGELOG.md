# Changelog

All notable changes to `acumatica-lint` will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0] — 2026-05-20

### Added

- Initial release. Linter for Acumatica customization `project.xml` with
  ~25 validators covering common publish-time failure modes:
  - Project structure + XML well-formedness
  - DAC fields without matching `<Sql>` ALTER TABLE
  - Phantom DAC references in `<GITable>` elements
  - GI modern attribute set (24.208+)
  - `<EntityEndpoint>` inline-block mapping
  - GI Creation Contract (RolesInGraph at registration time + plugin allowlist)
  - SiteMap orphan detection (`ParentID="00000000-..."`)
  - Modern GI format requirements (FQN GITable.Name, GIWhere vocabulary, etc.)
  - Phantom field references in `<GIResult>`
  - `<MUIScreen>` parent reference validation
  - `<Sql>` re-execution warnings (silent-skip pattern)
  - SAFE_DELETE_EXEMPT comment markers for audited exceptions
  - C# CustomizationPlugin static checks (banned APIs, SQL-against-GI tables,
    SQL-against-INUnit, plugin SQL column refs, schema-mutation guards)
  - DLL source reference auditing
- CLI: `acumatica-lint <project.xml>` with `--strict`, `--no-semantic`,
  `--isv-prefix`, `--dll-source-only` flags
- Python 3.9+ supported, stdlib-only (no external dependencies)
- Apache 2.0 licensed

### Encoded production lessons

This release encodes failure-mode rules from real Acumatica production
incidents. Each rule references the originating incident (AAR date or PR
number) in inline comments — invaluable context for understanding *why* a
given check exists.

### From the AcuOps team

This linter is Tier 1 of a three-tier funnel — the deterministic check
engine. For continuous PR gating, sandbox dry-runs before prod,
snapshot/rollback with integrity verification, Codex AI review, Slack
telemetry, deploy-window enforcement, and ~60 failure-mode guards working
together as a managed pipeline → see [AcuOps](https://acuops.com).

[0.1.0]: https://github.com/studio-b-ai/acumatica-lint/releases/tag/v0.1.0
