#!/usr/bin/env python3
"""
Acumatica Customization Project XML Validator

Validates project.xml format before packaging into a .zip for deployment.
Catches common format errors that cause silent failures or NullReferenceExceptions.

Usage:
    acumatica-lint Customization/_project/project.xml
    acumatica-lint --strict Customization/_project/project.xml

Hard-fail C# code checks (AAR-encoded; each maps to a real prod incident):
  * validate_customization_plugin_ban — WebConfigurationManager, HttpContext,
    DELETE/UPDATE/DROP/TRUNCATE in UpdateDatabase() (AAR 2026-03-28).
  * validate_gi_sql                   — INSERT/DELETE/UPDATE/DROP/TRUNCATE on
    GI* tables (AAR 2026-03-29).
  * validate_inunit_sql               — DELETE FROM INUnit / INSERT INTO INUnit
    (AAR 2026-03-28).
  * validate_plugin_sql_column_refs   — INSERT/UPDATE/SELECT column refs on
    Acumatica system tables (GIDesign, GITable, GIResult, GIWhere, GISort,
    GIFilter, GIRelation, GIOn, GIGroupBy, CustProject, UserRecords,
    FavoriteRecord) that aren't in the per-table allowlist (AAR 2026-04-17).
  * validate_dll_source_references    — gap-closer for DLL-sourced plugins:
    runs every plugin check (validate_plugin_sql_column_refs,
    validate_customization_plugin_ban, validate_gi_sql, validate_inunit_sql,
    validate_pxdb_has_sql, scan_security, validate_csharp,
    validate_extension_safety, validate_crm_dac_safety) on every .cs under
    src/<DllName>/ when project.xml references
    <File AppRelativePath="Bin\\<DllName>.dll" />. The CDATA-only checks
    were zero-coverage against the canonical compiled-DLL pattern until
    PR #27 (rule-18) and this PR (the rest).

Every hard-fail check ships an escape-hatch comment marker for audited exceptions:
    -- REVIEWED: gi-sql-safe       → suppress validate_gi_sql
    -- REVIEWED: inunit-sql-safe   → suppress validate_inunit_sql
    -- REVIEWED: schema-safe       → suppress validate_plugin_sql_column_refs
"""

import os
import re
import sys
import xml.etree.ElementTree as ET
from pathlib import Path

RED = "\033[91m"
YELLOW = "\033[93m"
GREEN = "\033[92m"
RESET = "\033[0m"

errors = []
warnings = []


def error(msg: str):
    errors.append(msg)
    print(f"{RED}[ERROR]{RESET} {msg}")


def warn(msg: str):
    warnings.append(msg)
    print(f"{YELLOW}[WARN]{RESET}  {msg}")


def ok(msg: str):
    print(f"{GREEN}[OK]{RESET}    {msg}")


def validate(path: str, strict: bool = False, no_semantic: bool = False, isv_prefix: str = ""):
    """Validate an Acumatica customization project.xml file.

    Args:
        path: Path to the project.xml file to validate.
        strict: Enable stricter checks (e.g. fail on warnings that are
            normally advisory).
        no_semantic: Skip the DAC/SQL cross-reference semantic checks.
        isv_prefix: If non-empty, enforce that every Graph ClassName starts
            with this prefix. Used for ISV certification builds (e.g. "AO").
    """

    file_path = Path(path)
    if not file_path.exists():
        error(f"File not found: {path}")
        return False

    # Parse XML
    try:
        tree = ET.parse(str(file_path))
        root = tree.getroot()
    except ET.ParseError as e:
        error(f"XML parse error: {e}")
        return False

    ok("XML is well-formed")

    # Check 0: REJECT XML COMMENTS — Acumatica import crashes with
    # InvalidCastException: XmlComment to XmlElement. This caused
    # database corruption on 2026-03-22. Comments must be stripped
    # BEFORE the package reaches the import API.
    raw_xml = file_path.read_text(encoding="utf-8")
    comment_pattern = re.compile(r"<!--.*?-->", re.DOTALL)
    comments_found = comment_pattern.findall(raw_xml)
    if comments_found:
        error(f"project.xml contains {len(comments_found)} XML comment(s)")
        error("Acumatica import CRASHES on XML comments (InvalidCastException).")
        error("Strip comments with: python scripts/inline-project.py <file>")
        for i, c in enumerate(comments_found[:3]):
            error(f"  Comment {i+1}: {c[:80]}...")
        if not strict:
            error("This is a HARD FAILURE even in non-strict mode.")
        return False
    ok("No XML comments (import-safe)")

    # Check 1: Root element must be <Customization>
    if root.tag != "Customization":
        error(f"Root element is <{root.tag}>, must be <Customization>")
        error("This may be a developer-format project.xml (not import format)")
        return False
    ok("Root element is <Customization>")

    # Check 2: level attribute
    level = root.get("level")
    if level is None:
        warn("Missing 'level' attribute on <Customization> (should be \"0\")")
    else:
        ok(f"level=\"{level}\"")

    # Check 3: product-version attribute
    pv = root.get("product-version")
    if pv is None:
        warn("Missing 'product-version' attribute (e.g., \"24.208\")")
    else:
        ok(f"product-version=\"{pv}\"")

    # Check 4: Validate <Sql> elements (ALTER TABLE column creation)
    sql_elements = root.findall(".//Sql")
    for elem in sql_elements:
        name = elem.get("Name", "(unnamed)")
        source = elem.get("Script", "")
        cdata = elem.find("CDATA")
        if cdata is None or not (cdata.text or "").strip():
            error(f"<Sql Name=\"{name}\"> missing or empty CDATA")
        else:
            sql_text = cdata.text or ""
            if "ALTER TABLE" in sql_text and "IF NOT EXISTS" not in sql_text:
                warn(f"<Sql Name=\"{name}\"> has ALTER TABLE without IF NOT EXISTS guard")
            ok(f"<Sql Name=\"{name}\"> validated")

    # Check 5: <Table> elements with IsNewColumn="True"
    # Required for first-time column creation, but causes NullReferenceException
    # on re-import if columns already exist. Warn (not error) so CI passes on
    # initial deploy; remove <Table> elements after first successful publish.
    table_elements = root.findall(".//Table")
    for table in table_elements:
        table_name = table.get("TableName", "(unnamed)")
        columns = table.findall("Column")
        new_columns = [c for c in columns if c.get("IsNewColumn") == "True"]
        if new_columns:
            col_names = ", ".join(c.get("ColumnName", "?") for c in new_columns)
            warn(
                f"<Table TableName=\"{table_name}\"> has IsNewColumn=\"True\" columns: {col_names}\n"
                f"         Required for first-time column creation. REMOVE after first publish\n"
                f"         to avoid NullReferenceException on re-import."
            )
        elif strict:
            warn(
                f"<Table TableName=\"{table_name}\"> present (no IsNewColumn). "
                f"Consider removing — DAC attributes handle column creation."
            )

    if not table_elements:
        ok("No <Table> elements (columns auto-created by DAC attributes)")

    # Check 5b: <File> elements — validate format and physical file existence
    #
    # Two formats exist:
    #   CORRECT: <File AppRelativePath="Pages\SB\SB501000.aspx" /> (self-closing)
    #     Physical file must exist in project directory. Packaged into zip by deploy.
    #     Standard Acumatica format — used by all ISV packages.
    #
    #   WRONG: <File Path="..." Content="#CDATA"> or <File Path="..." Content="path">
    #     Causes ArgumentNullException: entryName at ZipArchive.GetEntry during import.
    #     Confirmed: PR #71 + #79, runs 23694192480, 23699240216 (2026-03-28).
    file_elements = root.findall(".//File")
    aspx_count = 0
    for file_elem in file_elements:
        app_rel = file_elem.get("AppRelativePath", "")
        old_path = file_elem.get("Path", "")
        old_content = file_elem.get("Content", "")

        # HARD FAIL: Old Path/Content format — crashes on import
        if old_path and old_content:
            error(
                f"<File Path=\"{old_path}\" Content=\"{old_content}\"> uses WRONG format.\n"
                f"         This causes ArgumentNullException on Customization API import.\n"
                f"         Use: <File AppRelativePath=\"{old_path}\" /> with physical file in project dir.\n"
                f"         See: PR #71, PR #79 (2026-03-28)"
            )
            continue

        # AppRelativePath format — correct. Two sub-formats:
        #   1. Inline CDATA: Source="#CDATA" with <CDATA> child (e.g., CSS themes)
        #      No physical file needed — content is embedded in project.xml.
        #   2. Physical file: Self-closing <File AppRelativePath="..." />
        #      Physical file must exist in project directory for zip packaging.
        if app_rel:
            source_attr = file_elem.get("Source", "")
            has_cdata = file_elem.find("CDATA") is not None

            if source_attr == "#CDATA" and has_cdata:
                # Inline content — no physical file needed
                ok(f"<File AppRelativePath=\"{app_rel}\"> — inline CDATA content")
            else:
                # Physical file reference — verify it exists
                rel_normalized = app_rel.replace("\\", "/")
                physical_path = file_path.parent / rel_normalized
                if not physical_path.exists():
                    error(
                        f"<File AppRelativePath=\"{app_rel}\"> — physical file not found.\n"
                        f"         Expected at: {physical_path}\n"
                        f"         The file must exist in the project directory to be packaged into the zip."
                    )
                else:
                    ok(f"<File AppRelativePath=\"{app_rel}\"> — physical file exists")

            if app_rel.lower().endswith(".aspx") or app_rel.lower().endswith(".aspx.cs"):
                aspx_count += 1

    if file_elements:
        parts = []
        if aspx_count:
            parts.append(f"{aspx_count} ASPX")
        non_aspx = len(file_elements) - aspx_count
        if non_aspx:
            parts.append(f"{non_aspx} other")
        ok(f"Found {len(file_elements)} <File> element(s) ({', '.join(parts)})")
    elif not file_elements:
        pass  # No <File> elements — nothing to check

    # Collect ALL SQL text from <Sql> and <SqlScript> elements for cross-reference
    all_sql_text = ""
    for elem in root.findall(".//Sql"):
        cdata = elem.find("CDATA")
        if cdata is not None and cdata.text:
            all_sql_text += cdata.text + "\n"
    for elem in root.findall(".//SqlScript"):
        cdata = elem.find("CDATA")
        if cdata is not None and cdata.text:
            all_sql_text += cdata.text + "\n"

    # Check 6: Validate <Graph> elements
    # Supports two formats:
    #   1. Inline CDATA: Source="#CDATA" with <CDATA> child containing C# code
    #   2. External file: Source="Code\DAC\MyFile.cs" referencing a .cs file in the package
    graphs = root.findall(".//Graph")
    if not graphs:
        warn("No <Graph> elements found (no C# code in this project)")
    else:
        inline_count = 0
        external_count = 0
        for graph in graphs:
            class_name = graph.get("ClassName", "(missing)")
            source = graph.get("Source")
            file_type = graph.get("FileType")

            if not graph.get("ClassName"):
                error("<Graph> missing 'ClassName' attribute")

            # ISV prefix enforcement (opt-in via --isv-prefix / isv_prefix kwarg).
            # Used for ISV certification builds to ensure every ClassName starts
            # with the registered vendor prefix (e.g. "AO" → AO_CustomerExt).
            if isv_prefix and class_name != "(missing)":
                if not class_name.startswith(isv_prefix):
                    error(
                        f'<Graph ClassName="{class_name}"> does not start with '
                        f'ISV prefix "{isv_prefix}". '
                        f'Expected: "{isv_prefix}_{class_name}" or similar.'
                    )

            if source == "#CDATA":
                # Inline CDATA format — validate code content
                inline_count += 1
                if file_type != "NewFile":
                    warn(f"<Graph ClassName=\"{class_name}\"> FileType should be \"NewFile\", got \"{file_type}\"")

                cdata = graph.find("CDATA")
                if cdata is None:
                    error(f"<Graph ClassName=\"{class_name}\"> missing <CDATA> child element")
                    continue

                code = cdata.text or ""
                if not code.strip():
                    error(f"<Graph ClassName=\"{class_name}\"> has empty CDATA (no C# code)")
                    continue

                # CRITICAL: CustomizationPlugin ban (caused 3 production outages)
                validate_customization_plugin_ban(class_name, code)

                # CRITICAL: Destructive GI SQL detection (AAR 2026-03-29)
                validate_gi_sql(class_name, code)

                # CRITICAL: Destructive INUnit SQL detection (AAR 2026-03-28)
                validate_inunit_sql(class_name, code)

                # CRITICAL: Plugin SQL column refs on system tables (AAR 2026-04-17)
                validate_plugin_sql_column_refs(class_name, code)

                # CRITICAL: [PXDB*] fields must have matching SQL
                validate_pxdb_has_sql(class_name, code, all_sql_text)

                # Security scan — hardcoded credentials / secrets / keys
                scan_security(class_name, code)

                # Basic C# validation
                validate_csharp(class_name, code, strict)

                # Runtime safety checks (GetExtension patterns, inquiry guards)
                validate_extension_safety(class_name, code, strict)

                # CRM DAC compatibility checks
                validate_crm_dac_safety(class_name, code, strict)

            elif source and source.endswith(".cs"):
                # External file reference — validate the referenced .cs file exists
                external_count += 1
                # Resolve path relative to project.xml directory
                cs_path = file_path.parent / source.replace("\\", "/")
                if not cs_path.exists():
                    error(f"<Graph ClassName=\"{class_name}\"> references missing file: {source}")
                else:
                    # Read and validate the external .cs file
                    code = cs_path.read_text(encoding="utf-8")

                    # CRITICAL: CustomizationPlugin ban
                    validate_customization_plugin_ban(class_name, code)

                    # CRITICAL: Destructive GI SQL detection (AAR 2026-03-29)
                    validate_gi_sql(class_name, code)

                    # CRITICAL: Destructive INUnit SQL detection (AAR 2026-03-28)
                    validate_inunit_sql(class_name, code)

                    # CRITICAL: Plugin SQL column refs on system tables (AAR 2026-04-17)
                    validate_plugin_sql_column_refs(class_name, code)

                    # CRITICAL: [PXDB*] fields must have matching SQL
                    validate_pxdb_has_sql(class_name, code, all_sql_text)

                    # Security scan — hardcoded credentials / secrets / keys
                    scan_security(class_name, code)

                    validate_csharp(class_name, code, strict)
                    validate_extension_safety(class_name, code, strict)
                    validate_crm_dac_safety(class_name, code, strict)
            else:
                error(f"<Graph ClassName=\"{class_name}\"> invalid Source: \"{source}\" (expected \"#CDATA\" or a .cs file path)")

        parts = []
        if inline_count:
            parts.append(f"{inline_count} inline")
        if external_count:
            parts.append(f"{external_count} external")
        ok(f"Found {len(graphs)} <Graph> element(s) ({', '.join(parts)})")

    # Check 7: Validate <SqlScript> elements
    # NOTE: SM204505 IMPORT rejects <SqlScript> ("Unknown tag SqlScript").
    # DAC [PXDB*] attributes auto-create columns, so SQL is rarely needed.
    # If present, warn that it must be removed before .zip import.
    sql_scripts = root.findall(".//SqlScript")
    for script in sql_scripts:
        name = script.get("Name", "(missing)")
        warn(
            f"<SqlScript Name=\"{name}\"> will be REJECTED by SM204505 import "
            f"(\"Unknown tag SqlScript\"). Remove before packaging .zip — "
            f"DAC [PXDB*] attributes auto-create columns. "
            f"Add SQL via Customization Project Editor if truly needed."
        )
        source = script.get("Source")
        if source != "#CDATA":
            error(f"<SqlScript Name=\"{name}\"> Source should be \"#CDATA\", got \"{source}\"")

        cdata = script.find("CDATA")
        if cdata is None:
            error(f"<SqlScript Name=\"{name}\"> missing <CDATA> child element")
        elif not (cdata.text or "").strip():
            error(f"<SqlScript Name=\"{name}\"> has empty CDATA (no SQL)")
        else:
            sql_text = cdata.text
            # Check for IF NOT EXISTS guards
            if "ALTER TABLE" in sql_text and "IF NOT EXISTS" not in sql_text:
                warn(f"<SqlScript Name=\"{name}\"> has ALTER TABLE without IF NOT EXISTS guard")

    if sql_scripts:
        ok(f"Found {len(sql_scripts)} <SqlScript> element(s) (remove before import)")

    # Rule-18 column-ref guard against src/{DllName}/ for every
    # <File AppRelativePath="Bin\..."/> reference. Closes the gap left by
    # PR #24 which only scanned <Graph Source="#CDATA"/external .cs>.
    validate_dll_source_references(path, strict=strict)

    # Rule-17: GI OData contract — every ExposeViaOData="1" GI must have its
    # ScreenID listed in GI_SCREENS_REQUIRING_GRANT in a CustomizationPlugin.
    validate_gi_odata_contract(root, file_path)

    # Rule-22: ISV co-publish contamination — co_publish in acuops.yaml must
    # not include ISV package names (inflates PageIndexing, causes ThreadAbort).
    validate_isv_copublish(file_path)

    # Rule-31: Legacy 24.204 GI format — GenericInquiryScreen blocks must use
    # the modern 24.208 attribute set (PrimaryScreenIDNew, etc.).
    validate_gi_modern_format(root)

    # 2026-04-28: <EntityEndpoint><Mapping><To object="..."> form-caption
    # anti-pattern (client-asthetik PR #59). Spaces in object= = UI caption,
    # not graph data-view name → silent mapping drop, $adHocSchema empty.
    validate_mapping_object_no_space(root, strict=strict)

    # AAR-2026-03-09: <Sql> CREATE TABLE — silently ignored on cloud Acumatica.
    validate_sql_create_table(root)

    # Rule-24: <Sql> blocks don't re-execute on merge=true — warn reviewers to
    # use CustomizationPlugin.PXDatabase.Execute() for idempotent logic.
    validate_sql_reexec_warning(root)

    # Rule-45: <ScreenWithRights> blocks require plugin coverage of ALL three
    # RolesIn* tables (RolesInGraph, RolesInMember, RolesInCache).
    validate_screen_rights_trio(root, file_path, strict=strict)

    # 2026-05-10 W4 incident: role-grant copy from source screen silently
    # null-ops when source has zero rows. Emit error in strict mode when the
    # copy pattern is present but no empty-source fallback is found.
    validate_role_copy_has_fallback(root, file_path, strict=strict)

    # Rule-74: <EntityEndpoint><Mapping> rows are non-idempotent — re-publish
    # re-INSERTs into EntityMapping, causing duplicate-key ArgumentException.
    # Warn if no EntityMapping cleanup is found in any plugin .cs file.
    validate_entity_mapping_cleanup(root, file_path)

    # Rule-31 secondary: 5 additional <GenericInquiryScreen> failure modes that
    # validate_gi_modern_format doesn't cover (PR #25 successor):
    #   (1) dual-row GI blocks — RolesInGraph attaches to first row only, second GI 403
    #   (2) GI007xxx ScreenIDs — system-reserved range, custom GIs collide
    #   (3) phantom DAC refs — <GITable Name="..."> referencing non-existent DAC
    #   (4) GIFilter params — can block GI registration depending on type/scope
    #   (5) self-closing MUIScreen — GI unreachable from UI despite metadata entry
    validate_gi_secondary_modes(root)

    # W4 guard A: every ExposeViaOData="1" GI MUST declare <RolesInGraph> inline
    # in project.xml. Plugin-only grant is insufficient (plugin can null-op when
    # source template has zero rows). 2026-05-10 W4 incident: 10 of 17 Bolt GIs
    # relied solely on plugin path → zero grants → OData 404 for all 17.
    validate_gi_grant_required_in_xml(root, file_path)

    # W4 guard B: GI <SiteMap>/<row> ParentID must not be orphan (all-zeros GUID)
    # or a placeholder/sequential-byte GUID. Orphan SiteMap rows are invisible in
    # SM205010 → no role can grant access → OData returns 404 (not 403).
    # 2026-05-10 W4: 15 of 17 Bolt GIs had ParentID=zero, 1 had placeholder GUID.
    validate_sitemap_no_orphans(root)

    # W4 guard D: zip filename must match project.name in acuops.yaml.
    # 2026-05-10 W4: yaml said primary=AcuOps but build packaged Bolt_*.zip;
    # publishBegin ran [Bolt, Bolt, AsthetikTheme] (duplicate, AcuOps absent).
    validate_zip_name_matches_acuops_yaml_primary(file_path)

    # W4 guard E: extend role-copy fallback check — any direct-write fallback
    # for RolesInMember/RolesInCache MUST include Cachetype in the column whitelist.
    # 2026-05-11: acuops-pipeline#95 fallback used NULL default for unknown columns;
    # Cachetype (NOT NULL on RolesInMember/RolesInCache) → INSERT fails → zero role grants.
    validate_role_grant_column_whitelist(root, file_path, strict=strict)

    # W4 Recovery Guard (Check A): GIWhere Condition= must use the valid Acumatica
    # vocabulary. "EQ" is the canonical wrong value — parser throws, SM208000 fails
    # to render, OData returns 404. 2026-05-11 Heritage: 2 Bolt GIs used "EQ".
    # Reference: CLAUDE.md rule #128 #10; client-asthetik PRs #93 + #94.
    validate_giwhere_condition_vocabulary(root, raw_xml=raw_xml)

    # W4 Recovery Guard (Check B): GIWhere must use Operation= not Operator= (no R).
    # Publish silently ignores unrecognized attributes; SM208000 then receives blank
    # Operation and ValFromStr.GetCondition exception → OData 404.
    # Reference: CLAUDE.md rule #128 #11; client-asthetik PRs #93 + #94.
    validate_giwhere_operator_attribute_typo(root)

    if not no_semantic:
        from .semantic_checks import run_semantic_checks
        also_publish = os.environ.get("ALSO_PUBLISH_PROJECTS", "").split(",")
        manifest_candidates = [
            file_path.parent.parent.parent / "publish-manifest.json",
            file_path.parent.parent / "publish-manifest.json",
            Path("publish-manifest.json"),
        ]
        manifest_path = None
        for mp in manifest_candidates:
            if mp.exists():
                manifest_path = str(mp)
                break
        sem_errors, sem_warnings = run_semantic_checks(
            project_path=path,
            strict=strict,
            also_publish=also_publish,
            manifest_path=manifest_path,
        )
        errors.extend(sem_errors)
        warnings.extend(sem_warnings)

    return len(errors) == 0


# ── Rule-17: GI OData contract ───────────────────────────────────────────────
# CLAUDE.md rule #17: every <GenericInquiryScreen ExposeViaOData="1"> must have
# its ScreenID listed in a GI_SCREENS_REQUIRING_GRANT array inside a
# CustomizationPlugin .cs file. Missing = 403 on OData access at runtime.

def validate_gi_odata_contract(root, file_path: Path):
    """Check that every OData-exposed GI has its ScreenID in GI_SCREENS_REQUIRING_GRANT.

    Handles two project.xml structures:
    1. Simplified fixture format: <GenericInquiryScreen><GIDesign attrs .../></...>
    2. Real Acumatica export format: <GenericInquiryScreen><data-set><GIDesign><row attrs .../>

    Category: gi_contract
    """
    # Collect all ScreenIDs from OData-exposed GI blocks
    exposed_screen_ids = set()
    for gi_block in root.findall(".//GenericInquiryScreen"):
        # Candidate elements that carry ExposeViaOData + ScreenID:
        # - direct GIDesign element (simplified fixture format)
        # - GIDesign/row elements (real Acumatica export format)
        candidates = []
        gi_design_direct = gi_block.find("GIDesign")
        if gi_design_direct is not None:
            # Simplified format: attrs on the GIDesign element itself
            if gi_design_direct.get("ExposeViaOData") is not None:
                candidates.append(gi_design_direct)
            # Real format: attrs on row children
            for row in gi_design_direct.findall("row"):
                candidates.append(row)

        for elem in candidates:
            if elem.get("ExposeViaOData", "0") == "1":
                screen_id = (
                    elem.get("PrimaryScreenIDNew")
                    or elem.get("ScreenID")
                )
                if screen_id:
                    exposed_screen_ids.add(screen_id)

        # Also check SiteMap rows with ExposeViaOData="1" (legacy format)
        for row in gi_block.findall(".//SiteMap/row"):
            if row.get("ExposeViaOData") == "1":
                sid = row.get("ScreenID")
                if sid:
                    exposed_screen_ids.add(sid)

    if not exposed_screen_ids:
        return  # No OData GIs — nothing to check

    # Collect ScreenIDs present in any GI_SCREENS_REQUIRING_GRANT array
    # across all .cs files referenced in the package (inline CDATA + external).
    granted_screen_ids = set()
    grant_pattern = re.compile(
        r'GI_SCREENS_REQUIRING_GRANT\s*=\s*new\s*\[?\]?\s*\{([^}]+)\}',
        re.DOTALL,
    )
    string_literal = re.compile(r'"([A-Z0-9]+)"')

    def _collect_grants_from_code(code: str):
        for m in grant_pattern.finditer(code):
            for s in string_literal.finditer(m.group(1)):
                granted_screen_ids.add(s.group(1))

    for graph in root.findall(".//Graph"):
        source = graph.get("Source", "")
        if source == "#CDATA":
            cdata = graph.find("CDATA")
            if cdata is not None and cdata.text:
                _collect_grants_from_code(cdata.text)
        elif source.endswith(".cs"):
            cs_path = file_path.parent / source.replace("\\", "/")
            if cs_path.exists():
                _collect_grants_from_code(cs_path.read_text(encoding="utf-8"))

    # Also scan any .cs files in Bin src dirs (DLL-compiled pattern)
    src_dir = file_path.parent.parent.parent / "src"
    if src_dir.exists():
        for cs_file in src_dir.rglob("*.cs"):
            try:
                _collect_grants_from_code(cs_file.read_text(encoding="utf-8"))
            except Exception:
                pass

    missing = exposed_screen_ids - granted_screen_ids
    if missing:
        for sid in sorted(missing):
            error(
                f"GI ScreenID '{sid}' is ExposeViaOData=\"1\" but is NOT listed in "
                f"GI_SCREENS_REQUIRING_GRANT in any CustomizationPlugin .cs file.\n"
                f"         Missing grant = 403 OData access at runtime. "
                f"Add '{sid}' to GI_SCREENS_REQUIRING_GRANT[].\n"
                f"         See CLAUDE.md rule #17 and EnsureGIRoleAccess() pattern."
            )
    else:
        ok(f"GI OData contract: all {len(exposed_screen_ids)} exposed GI(s) have plugin grants")


# ── Rule-22: ISV co-publish contamination ────────────────────────────────────
# CLAUDE.md rule #22: co_publish in acuops.yaml must not include ISV package
# names. ISV inclusion inflates PageIndexing cost → ThreadAbortException.

_ISV_PREFIXES = {
    "Ramp", "FusionWMS", "Pacejet", "KNCentralizedLicense", "KNC", "WMSynergy",
}


def validate_isv_copublish(file_path: Path):
    """Check acuops.yaml co_publish list for ISV package names.

    Looks for acuops.yaml adjacent to or above the project.xml directory.
    Category: isv_copublish
    """
    import yaml  # stdlib pyyaml — available in requirements.txt

    # Locate acuops.yaml by walking up from the project.xml directory.
    # Search is bounded by the git repo root so we never pick up an unrelated
    # acuops.yaml from a sibling or parent project in a multi-repo dev tree.
    # When the project.xml is not inside any git repo, only its immediate
    # directory is checked (no upward walk) — this prevents the false-positive
    # scenario where /tmp/emptyproj/project.xml would otherwise match
    # /tmp/acuops.yaml from a completely different project.
    def _find_git_root(start: Path) -> Path | None:
        """Return the nearest ancestor dir that contains .git, or None."""
        current = start
        for _ in range(20):  # guard against infinite loop on pathological FS
            if (current / ".git").exists():
                return current
            parent = current.parent
            if parent == current:
                return None  # reached filesystem root
            current = parent
        return None

    git_root = _find_git_root(file_path.parent)

    # If inside a git repo: walk up to the repo root (max 3 levels).
    # If not in a git repo: only check the immediate directory.
    if git_root is not None:
        search_dirs: list[Path] = []
        current = file_path.parent
        for _ in range(3):
            search_dirs.append(current)
            if current == git_root:
                break
            parent = current.parent
            if parent == current:
                break
            current = parent
    else:
        search_dirs = [file_path.parent]

    acuops_yaml = None
    for d in search_dirs:
        candidate = d / "acuops.yaml"
        if candidate.exists():
            acuops_yaml = candidate
            break

    if acuops_yaml is None:
        ok("rule #22 ISV co-publish check skipped — no acuops.yaml found via parent walk")
        return

    try:
        with acuops_yaml.open() as f:
            config = yaml.safe_load(f) or {}
    except Exception as e:
        warn(f"Could not parse {acuops_yaml}: {e}")
        return

    co_publish = config.get("publish", {}).get("co_publish", []) or []
    # Also check env var ALSO_PUBLISH_PROJECTS
    env_val = os.environ.get("ALSO_PUBLISH_PROJECTS", "")
    env_entries = [e.strip() for e in env_val.split(",") if e.strip()]
    all_entries = list(co_publish) + env_entries

    contaminated = []
    for entry in all_entries:
        for prefix in _ISV_PREFIXES:
            if entry.startswith(prefix):
                contaminated.append(entry)
                break

    if contaminated:
        for pkg in contaminated:
            error(
                f"co_publish contains ISV package '{pkg}'.\n"
                f"         ISV packages in co_publish inflate Acumatica's PageIndexing scan,\n"
                f"         causing ThreadAbortException in PXPageIndexingService on prod.\n"
                f"         Root cause of 2026-04-15 PCC outage (11-project co-publish list).\n"
                f"         Remove ISV packages from co_publish — with merge=true, already-published\n"
                f"         ISV packages stay published without being in the list.\n"
                f"         See CLAUDE.md rule #22."
            )
    else:
        if all_entries:
            ok(f"co_publish: {len(all_entries)} entr(ies) — no ISV contamination")


# ── Rule-31: Legacy 24.204 GI format ─────────────────────────────────────────
# CLAUDE.md rule #31: GenericInquiryScreen blocks must use modern 24.208 attrs.
# Missing PrimaryScreenIDNew / ShowDeletedRecords / NotesAndFilesTable = silently
# rejected by publish engine → GI never lands in OData catalog (404).

_GI_REQUIRED_MODERN_ATTRS = {"PrimaryScreenIDNew", "ShowDeletedRecords", "NotesAndFilesTable"}


def validate_gi_modern_format(root):
    """Check <GenericInquiryScreen> blocks for required modern 24.208 attributes.

    Category: gi_legacy_format
    """
    gi_blocks = root.findall(".//GenericInquiryScreen")
    if not gi_blocks:
        return

    legacy_count = 0
    for gi_block in gi_blocks:
        gi_design = gi_block.find("GIDesign")
        if gi_design is None:
            # No GIDesign row — can't check
            continue
        name = gi_design.get("Name", "(unnamed)")
        missing_attrs = _GI_REQUIRED_MODERN_ATTRS - set(gi_design.attrib.keys())
        if missing_attrs:
            legacy_count += 1
            error(
                f"<GenericInquiryScreen Name=\"{name}\"> is missing modern 24.208 attributes: "
                f"{sorted(missing_attrs)}.\n"
                f"         Legacy attribute set is silently rejected by the publish engine —\n"
                f"         GI never lands in the OData catalog (404 on probe).\n"
                f"         Required modern attrs: PrimaryScreenIDNew, ShowDeletedRecords,\n"
                f"         ShowArchivedRecords, NotesAndFilesTable, MLDetectionEnabled, SkipEmptyGroups.\n"
                f"         See CLAUDE.md rule #31."
            )

    if legacy_count == 0 and gi_blocks:
        ok(f"GI format: all {len(gi_blocks)} GenericInquiryScreen block(s) use modern 24.208 attrs")


# ── 2026-04-28: <Mapping><To object="..."> form-caption anti-pattern ─────────
# Discovered during client-asthetik PR #59. An <EntityEndpoint> <TopLevelEntity>
# <Mapping> element whose <To object="..."> value contains a SPACE character is
# almost certainly the SO/PO form's UI caption (e.g. "Order Summary") instead
# of the graph data-view name (typically "Document"). Acumatica's metadata
# resolver silently drops mappings that can't bind to a real graph view —
# the entity registers but Fields/Mappings vanish, and $adHocSchema returns
# 200 with empty `custom: {}`. CLAUDE.md Rules #38 + #43 corollary.

def validate_mapping_object_no_space(root, strict: bool = True):
    """Flag <EntityEndpoint>/<TopLevelEntity>/<Mapping>/<To object="..."> values
    containing whitespace — graph data-view names never contain spaces.

    Strict mode FAILs (accumulates an error). Non-strict WARNs.

    Category: endpoint_mapping_form_caption
    """
    bad_count = 0
    total_count = 0

    for endpoint in root.findall(".//EntityEndpoint"):
        endpoint_name = endpoint.get("Name", "(unnamed)")
        for tle in endpoint.findall(".//TopLevelEntity"):
            entity_name = tle.get("name", "(unnamed)")
            for mapping in tle.findall(".//Mapping"):
                field_name = mapping.get("field", "(unnamed)")
                to_elem = mapping.find("To")
                if to_elem is None:
                    continue
                obj_value = to_elem.get("object")
                if obj_value is None:
                    continue
                total_count += 1
                if " " in obj_value or "\t" in obj_value:
                    bad_count += 1
                    msg = (
                        f"<EntityEndpoint Name=\"{endpoint_name}\"> "
                        f"<TopLevelEntity name=\"{entity_name}\">\n"
                        f"       <Mapping field=\"{field_name}\"> "
                        f"<To object=\"{obj_value}\"> contains a space.\n"
                        f"       This is almost certainly the SO/PO form's UI caption, not the graph\n"
                        f"       data-view name. Acumatica's metadata resolver silently drops mappings\n"
                        f"       that can't bind to a real view — entity registers but Fields/Mappings\n"
                        f"       vanish. See client-asthetik PR #59 (2026-04-28) for the canonical bug.\n"
                        f"       Use the SOOrderEntry/POOrderEntry view name (typically \"Document\"),\n"
                        f"       not the form caption like \"Order Summary\"."
                    )
                    if strict:
                        error(msg)
                    else:
                        warn(msg)

    if total_count > 0 and bad_count == 0:
        ok(f"Endpoint mappings: {total_count} <Mapping><To object=...> value(s) free of whitespace")


# ── Rule-24: <Sql> blocks don't re-execute on merge=true ─────────────────────
# CLAUDE.md rule #24: Acumatica tracks executed <Sql> scripts by Name.
# Bumping the Name suffix (e.g. _v2) does NOT force re-execution — Acumatica's
# "already applied" tracker permanently skips the script after the first publish.
# The 2026-04-16 PR #427 attempt failed across 3 deploy iterations on this.
# Idempotent install logic that must survive every merge=true publish MUST use
# CustomizationPlugin.PXDatabase.Execute() instead of <Sql> blocks.

def validate_sql_reexec_warning(root):
    """Warn when <Sql> blocks are present — they don't re-execute on merge=true.

    <Sql> is legal for first-publish data seeding but is a silent no-op on
    subsequent publishes because Acumatica tracks executed scripts by Name.
    For logic that must survive every publish, use CustomizationPlugin instead.

    This is a WARNING (not error) — <Sql> is not illegal, just fragile.
    Category: sql_reexec
    """
    sql_elements = root.findall(".//Sql")
    if not sql_elements:
        return

    for elem in sql_elements:
        name = elem.get("Name", "(unnamed)")
        warn(
            f"<Sql Name=\"{name}\"> will NOT re-execute on subsequent merge=true publishes.\n"
            f"         Acumatica tracks executed scripts by Name; bumping the Name suffix\n"
            f"         does NOT force re-execution — the block is silently skipped.\n"
            f"         Safe for one-time first-publish seeding, but use\n"
            f"         CustomizationPlugin.PXDatabase.Execute() for logic that must survive\n"
            f"         every publish (e.g. GI role grants, screen rights, cleanup queries).\n"
            f"         Root cause of 2026-04-16 PR #427 failure (3 deploy attempts, zero effect).\n"
            f"         See CLAUDE.md rule #24."
        )


# ── Rule-45: Custom screen access requires three RolesIn* tables ─────────────
# CLAUDE.md rule #45: Acumatica's SiteMap-node access check reads RolesInCache +
# RolesInGraph + RolesInMember (all three). Inserting only RolesInGraph is a
# silent no-op for screen access — the screen still redirects to 00000000.
# 2026-04-21 incident: client-asthetik#40 shipped RolesInGraph-only; all 7
# screens (SB302040 etc.) still redirected api-bot for ~8 hours.

_ROLES_IN_TABLES = ("RolesInGraph", "RolesInMember", "RolesInCache")


def validate_screen_rights_trio(root, file_path: Path, strict: bool = False):
    """Check that <ScreenWithRights> blocks have plugin coverage for all three
    RolesIn* tables (RolesInGraph, RolesInMember, RolesInCache).

    For each <ScreenWithRights> block found in project.xml, verify that at least
    one plugin .cs file referenced by this package mentions all three table names.
    Missing any of the three → ERROR in strict mode, WARN otherwise.

    Category: screen_rights_trio
    """
    screen_rights_blocks = root.findall(".//ScreenWithRights")
    if not screen_rights_blocks:
        return  # No custom screen-rights blocks — nothing to check.

    screen_ids = []
    for block in screen_rights_blocks:
        # ScreenWithRights contains a SiteMap sub-tree; pull ScreenID from rows
        for row in block.findall(".//row"):
            sid = row.get("ScreenID")
            if sid:
                screen_ids.append(sid)

    if not screen_ids:
        return

    # Collect all C# code from this package's plugin files.
    all_cs_code = ""

    def _read_graph_cs(src: str) -> str:
        """Read inline CDATA or external .cs file content."""
        if src == "#CDATA":
            return ""  # handled separately below
        if src and src.endswith(".cs"):
            cs_path = file_path.parent / src.replace("\\", "/")
            if cs_path.exists():
                try:
                    return cs_path.read_text(encoding="utf-8")
                except Exception:
                    pass
        return ""

    for graph in root.findall(".//Graph"):
        source = graph.get("Source", "")
        if source == "#CDATA":
            cdata = graph.find("CDATA")
            if cdata is not None and cdata.text:
                all_cs_code += cdata.text + "\n"
        else:
            all_cs_code += _read_graph_cs(source)

    # Also scan src/ DLL directories (DLL-compiled pattern, same as rule-18).
    # Try both acumatica/src/ (shallow layout) and repo-root src/ (client-asthetik layout
    # where project.xml lives in acumatica/Customization/<pkg>/ but Install.cs is at src/).
    for _src_dir in (
        file_path.parent.parent.parent / "src",
        file_path.parent.parent.parent.parent / "src",
    ):
        if _src_dir.exists():
            for cs_file in _src_dir.rglob("*Install*.cs"):
                try:
                    all_cs_code += cs_file.read_text(encoding="utf-8") + "\n"
                except Exception:
                    pass

    missing_tables = [t for t in _ROLES_IN_TABLES if t not in all_cs_code]
    if missing_tables:
        screen_list = ", ".join(screen_ids[:5])
        msg = (
            f"<ScreenWithRights> present for screen(s): {screen_list}\n"
            f"         but CustomizationPlugin .cs files do NOT reference all three\n"
            f"         RolesIn* tables required for SiteMap-node access.\n"
            f"         Missing: {missing_tables}\n"
            f"         Inserting only RolesInGraph is a silent no-op — screens still\n"
            f"         redirect non-admin users to ScreenId=00000000.\n"
            f"         Plugin must INSERT into RolesInGraph, RolesInMember, AND RolesInCache.\n"
            f"         Reference: AesthetikContainersInstall.EnsureScreenRights().\n"
            f"         Root cause of 2026-04-21 incident (client-asthetik#40 → #43).\n"
            f"         See CLAUDE.md rule #45."
        )
        if strict:
            error(msg)
        else:
            warn(msg)
    else:
        ok(
            f"Screen rights: <ScreenWithRights> has plugin coverage for all three "
            f"RolesIn* tables ({len(screen_ids)} screen(s))"
        )


# ── 2026-05-10 W4: role-grant copy empty-source fallback ─────────────────────
# CLAUDE.md rule (W4 incident, 2026-05-10): EnsureScreenRights() copies rows
# from a known-working source screen (SB501000) to all target screens. If the
# source has ZERO rows in any company (CID), the INSERT…SELECT silently inserts
# nothing — no error, no log signal. Every target GI then returns HTTP 404 on
# OData because no role has access. The 2026-05-10 Heritage W4 rebrand produced
# this exact failure: "grants by table: Graph=0 Member=0 Cache=0" for all 4 CIDs.
#
# Static lint heuristic: detect the INSERT…SELECT copy pattern in plugin .cs code
# and require that the SAME method/class also contains either:
#   (a) a direct-write fallback that inserts a Rolename='*' literal row, OR
#   (b) the marker string "EnsureScreenRights ABORT" (the canary from the runtime
#       guard that confirms the dev wired the fallback intentionally).
#
# Detection pattern (DOTALL, across C# verbatim string literals):
#   INSERT INTO RolesIn(Graph|Member|Cache)
#   ...
#   SELECT ... FROM RolesIn(Graph|Member|Cache)
#   ... WHERE ... ScreenID = @?<identifier>

_ROLE_COPY_PATTERN = re.compile(
    r"INSERT\s+INTO\s+[^\s]*RolesIn(?:Graph|Member|Cache)[^\n]*"
    r".*?"
    r"SELECT\s+.*?FROM\s+[^\s]*RolesIn(?:Graph|Member|Cache)[^\n]*"
    r".*?"
    r"WHERE\s+.*?ScreenID\s*=\s*@?\w+",
    re.DOTALL | re.IGNORECASE,
)

_ROLE_COPY_FALLBACK_DIRECT = re.compile(
    r"INSERT\s+INTO\s+[^\s]*RolesIn(?:Graph|Member|Cache)[^;]+"
    r"VALUES\s*\([^)]*'?\*'?[^)]*\)",
    re.DOTALL | re.IGNORECASE,
)

_ROLE_COPY_FALLBACK_MARKER = "EnsureScreenRights ABORT"


def validate_role_copy_has_fallback(root, file_path: Path, strict: bool = False):
    """Error/warn when a CustomizationPlugin copies role grants from a source
    screen but has no fallback for the case where the source has zero rows.

    If the source screen has zero rows in any RolesIn* table for a given
    CompanyID, the INSERT…SELECT silently inserts nothing. Every target GI then
    returns HTTP 404 on OData because no role has access.

    A compliant plugin MUST either:
      (a) include a direct INSERT INTO RolesIn* … VALUES (…'*'…) fallback, OR
      (b) contain the string 'EnsureScreenRights ABORT' (the runtime canary that
          proves the developer wired an explicit empty-source fallback).

    This check fires only when the copy pattern is detected (INSERT…SELECT from
    RolesIn*). Plugins that only do direct-write grants are exempt.

    Category: role_copy_fallback
    Reference: 2026-05-10 W4 incident; see CLAUDE.md.
    """

    # Collect all plugin .cs code for this package (same strategy as
    # validate_screen_rights_trio — inline CDATA + external .cs + src/ DLL dirs).
    all_cs_code = ""

    for graph in root.findall(".//Graph"):
        source = graph.get("Source", "")
        if source == "#CDATA":
            cdata = graph.find("CDATA")
            if cdata is not None and cdata.text:
                all_cs_code += cdata.text + "\n"
        elif source.endswith(".cs"):
            cs_path = file_path.parent / source.replace("\\", "/")
            if cs_path.exists():
                try:
                    all_cs_code += cs_path.read_text(encoding="utf-8") + "\n"
                except Exception:
                    pass

    for _src_dir in (
        file_path.parent.parent.parent / "src",
        file_path.parent.parent.parent.parent / "src",
    ):
        if _src_dir.exists():
            for cs_file in _src_dir.rglob("*Install*.cs"):
                try:
                    all_cs_code += cs_file.read_text(encoding="utf-8") + "\n"
                except Exception:
                    pass

    if not all_cs_code.strip():
        return  # No C# code to inspect.

    # If no role-copy pattern is present, this check is not applicable.
    if not _ROLE_COPY_PATTERN.search(all_cs_code):
        return

    # Copy pattern found — require a fallback.
    has_direct_fallback = bool(_ROLE_COPY_FALLBACK_DIRECT.search(all_cs_code))
    has_marker_fallback = _ROLE_COPY_FALLBACK_MARKER in all_cs_code

    if has_direct_fallback or has_marker_fallback:
        ok(
            "Role-grant copy: empty-source fallback present "
            f"({'direct-write' if has_direct_fallback else 'marker'} pattern)"
        )
        return

    msg = (
        "Role-grant copy from source screen has no fallback for empty-source case.\n"
        "         If the source screen has zero rows in any company, the copy\n"
        "         silently null-ops and every target screen returns HTTP 404 on OData.\n"
        "         Add either:\n"
        "           (a) a direct-write fallback: INSERT INTO RolesIn* … VALUES (…'*'…)\n"
        "           (b) emit 'EnsureScreenRights ABORT — source has zero rows; falling\n"
        "               back to Rolename=*' and execute the direct write.\n"
        "         See 2026-05-10 W4 incident (Heritage Fabrics Bolt rebrand: all 17 GIs\n"
        "         returned HTTP 404; publish log showed Graph=0 Member=0 Cache=0 for\n"
        "         all 4 CIDs because SB501000 had zero rows in every RolesIn* table)."
    )
    if strict:
        error(msg)
    else:
        warn(msg)


# ── Rule-74: <EntityEndpoint><Mapping> rows are non-idempotent ───────────────
# CLAUDE.md rule #74: Re-publishing a customization re-INSERTs <Mapping> rows
# into Acumatica's EntityMapping table. On tenants other than CID=1, the
# EntityFieldId allocator picks MAX+1=1, colliding with existing rows on
# MappingKey=E/<EntityId>/<EntityFieldId>. MetadataProvider.GetEntityMappings.
# ToDictionary throws ArgumentException: An item with the same key has already
# been added → every /entity/Default/* returns HTTP 500.
# 2026-04-26 sandbox outage: 16 hours of 500s from Path 2 α residue.
# Recovery: DB-level DELETE in CustomizationPlugin carrying SAFE_DELETE_EXEMPT.

_ENTITY_MAPPING_CLEANUP_RE = re.compile(r"EntityMapping", re.IGNORECASE)


def validate_entity_mapping_cleanup(root, file_path: Path):
    """Warn when <EntityEndpoint> contains <Mapping> rows without corresponding
    EntityMapping cleanup in any plugin .cs file.

    The cleanup DELETE must be in a CustomizationPlugin.Install() method and
    carry a '-- SAFE_DELETE_EXEMPT: <reason>' comment (per Rule #79 guard).
    This check warns (not errors) — first-publish packages legitimately have no
    rows to clean up yet; the warning reminds authors to add it before the second
    publish touches prod.

    Category: entity_mapping_cleanup
    """
    # Find <EntityEndpoint> blocks with at least one <Mapping> child.
    has_mappings = False
    for endpoint in root.findall(".//EntityEndpoint"):
        for tle in endpoint.findall(".//TopLevelEntity"):
            if tle.findall(".//Mapping"):
                has_mappings = True
                break
        if has_mappings:
            break

    if not has_mappings:
        return  # No mapping rows — nothing to check.

    # Scan all plugin .cs code for EntityMapping reference.
    def _collect_cs() -> str:
        code = ""
        for graph in root.findall(".//Graph"):
            src = graph.get("Source", "")
            if src == "#CDATA":
                cdata = graph.find("CDATA")
                if cdata is not None and cdata.text:
                    code += cdata.text + "\n"
            elif src.endswith(".cs"):
                cs_path = file_path.parent / src.replace("\\", "/")
                if cs_path.exists():
                    try:
                        code += cs_path.read_text(encoding="utf-8") + "\n"
                    except Exception:
                        pass
        for _src_dir in (
            file_path.parent.parent.parent / "src",
            file_path.parent.parent.parent.parent / "src",
        ):
            if _src_dir.exists():
                for cs_file in _src_dir.rglob("*Install*.cs"):
                    try:
                        code += cs_file.read_text(encoding="utf-8") + "\n"
                    except Exception:
                        pass
        return code

    all_cs = _collect_cs()
    if not _ENTITY_MAPPING_CLEANUP_RE.search(all_cs):
        warn(
            "<EntityEndpoint> contains <Mapping> rows but no CustomizationPlugin .cs\n"
            "         file references 'EntityMapping'.\n"
            "         Re-publishing re-INSERTs mapping rows; on tenants other than CID=1 this\n"
            "         causes duplicate MappingKey collisions → ArgumentException in\n"
            "         MetadataProvider.GetEntityMappings → HTTP 500 on every /entity/* request.\n"
            "         Add an idempotent DELETE + re-INSERT in your CustomizationPlugin.Install()\n"
            "         with a '-- SAFE_DELETE_EXEMPT: <reason>' comment (required by validate-project Rule #79).\n"
            "         Reference: AesthetikContainersInstall.cs EntityMapping cleanup.\n"
            "         Root cause of 2026-04-26 sandbox 16-hour outage (client-asthetik#53/#55).\n"
            "         See CLAUDE.md rule #74."
        )
    else:
        ok("EntityEndpoint mappings: plugin references EntityMapping cleanup")


# ── W4 Guard A: GI inline RolesInGraph required ──────────────────────────────
# CLAUDE.md rule #17 (revised after 2026-05-10 W4 incident):
# Every <GenericInquiryScreen> with ExposeViaOData="1" MUST declare
# <RolesInGraph Rolename="*" Accessrights="4" ApplicationName="/" /> inside its
# <SiteMap>/<row> block in project.xml. The plugin EnsureGIRoleAccess() path is
# defense-in-depth only — if the plugin's source-copy silently null-ops (e.g.
# because the source ScreenID template has zero rows in a company), no grants
# are issued and OData returns HTTP 404.
#
# 2026-05-10 W4 evidence: 10 of 17 Bolt GIs relied solely on the plugin path;
# EnsureScreenRights null-op'd (source SB501000 had zero rows on Heritage);
# publish log showed "grants by table: Graph=0 Member=0 Cache=0" for all 4 CIDs;
# all 17 OData GIs returned HTTP 404.
#
# Reference: client-asthetik/acumatica/docs/runbooks/aar-2026-05-10-bolt-gi-recovery-cascade.md
# See CLAUDE.md rule #17.

def validate_gi_grant_required_in_xml(root, file_path: Path):
    """Every OData-exposed GI MUST declare <RolesInGraph> inline in project.xml.

    Checks each <GenericInquiryScreen> block whose GIDesign row has
    ExposeViaOData="1". For each, verifies that the block's <SiteMap>/<row>
    contains at least one <RolesInGraph Rolename="*" Accessrights="4" ...> child.

    Category: gi_inline_roles_required
    Reference: CLAUDE.md rule #17 (revised 2026-05-10); W4 AAR guard #1.
    """
    gi_blocks = root.findall(".//GenericInquiryScreen")
    if not gi_blocks:
        return

    missing = []  # (gi_name, screen_id)

    for gi_block in gi_blocks:
        # Determine if this GI is OData-exposed.
        exposed = False
        gi_name = "(unknown)"
        screen_id = "(unknown)"

        # Support both direct child and nested-under-data-set layout.
        # Real Acumatica export: GenericInquiryScreen/data-set/GIDesign/row
        # Simplified fixture:    GenericInquiryScreen/GIDesign (attrs on element itself)
        gi_design = gi_block.find(".//GIDesign")
        if gi_design is not None:
            # Check direct GIDesign attrs (simplified fixture format)
            if gi_design.get("ExposeViaOData") == "1":
                exposed = True
                gi_name = gi_design.get("Name", gi_name)
                screen_id = (
                    gi_design.get("PrimaryScreenIDNew")
                    or gi_design.get("ScreenID")
                    or screen_id
                )
            # Check GIDesign/row children (real Acumatica export format)
            for row in gi_design.findall("row"):
                if row.get("ExposeViaOData", "0") == "1":
                    exposed = True
                    gi_name = row.get("Name", gi_name)
                    screen_id = (
                        row.get("PrimaryScreenIDNew")
                        or row.get("ScreenID")
                        or screen_id
                    )

        # Also check legacy format: SiteMap row with ExposeViaOData="1"
        for sm_row in gi_block.findall(".//SiteMap/row"):
            if sm_row.get("ExposeViaOData") == "1":
                exposed = True
                sid = sm_row.get("ScreenID")
                if sid:
                    screen_id = sid
                # Try to get name from GIDesign if not already set
                if gi_name == "(unknown)" and gi_design is not None:
                    gi_name = gi_design.get("Name", gi_name)

        if not exposed:
            continue

        # This GI is OData-exposed — check for inline <RolesInGraph>
        has_inline_roles = False
        for sm_row in gi_block.findall(".//SiteMap/row"):
            roles = sm_row.findall("RolesInGraph")
            if roles:
                has_inline_roles = True
                break

        if not has_inline_roles:
            missing.append((gi_name, screen_id))

    if missing:
        for gi_name, screen_id in missing:
            error(
                f"GI '{gi_name}' (ScreenID={screen_id}) is ExposeViaOData=\"1\" but has NO\n"
                f"         <RolesInGraph> declaration inside its <SiteMap>/<row> in project.xml.\n"
                f"         Plugin-only grants (GI_SCREENS_REQUIRING_GRANT / EnsureGIRoleAccess) are\n"
                f"         defense-in-depth only — they silently null-op when the source template\n"
                f"         has zero rows (e.g., SB501000 on a fresh tenant).\n"
                f"         Add inline: <RolesInGraph Rolename=\"*\" Accessrights=\"4\" ApplicationName=\"/\" />\n"
                f"         inside the <SiteMap>/<row> for this GI.\n"
                f"         Root cause: 2026-05-10 W4 Heritage Fabrics incident — 10 of 17 Bolt GIs\n"
                f"         relied solely on plugin path; all 17 returned HTTP 404 on OData.\n"
                f"         AAR: client-asthetik/acumatica/docs/runbooks/aar-2026-05-10-bolt-gi-recovery-cascade.md\n"
                f"         See CLAUDE.md rule #17."
            )
    else:
        if gi_blocks:
            sum(
                1 for (n, s) in [(gi_block.find("GIDesign"), gi_block) for gi_block in gi_blocks]
                if n is not None and n.get("ExposeViaOData") == "1"
            )
            ok("GI inline RolesInGraph: all OData-exposed GI(s) have inline role declarations")


# ── W4 Guard B: GI SiteMap no orphan ParentID ────────────────────────────────
# CLAUDE.md rule #125:
# A GI SiteMap row with ParentID="00000000-0000-0000-0000-000000000000" (the
# all-zeros NULL GUID) is an orphan node — invisible in SM205010 (Access Rights
# by Role) tree, unreachable for role grants, OData returns HTTP 404 (not 403,
# because no role has visibility at all).
#
# Also flag placeholder/sequential-byte GUIDs that indicate a developer typed
# a dummy value (e.g. d9e3f4a5-b2c3-4678-9abc-def012345678).
#
# 2026-05-10 W4 evidence: 15 of 17 Bolt GIs had ParentID=zero; 1 had a
# sequential-byte placeholder GUID. Combined: 16 orphans.
#
# Reference: client-asthetik/acumatica/docs/runbooks/aar-2026-05-10-bolt-gi-recovery-cascade.md
# See CLAUDE.md rule #125.

_ORPHAN_PARENT_ID = "00000000-0000-0000-0000-000000000000"

# Heuristic: hex digits of the GUID (without dashes) form an obvious sequential
# pattern. Detect the most common placeholder patterns:
#   d9e3f4a5b2c346789abcdef012345678 (sequential nibbles starting at d)
#   01234567890123456789012345678901 (pure incrementing)
#   aabbccddeeff00112233445566778899 (repeated pairs)
# Conservative: flag only obvious patterns to avoid false positives on real GUIDs.
_PLACEHOLDER_GUID_PATTERNS = re.compile(
    r"""(?x)
    ^(?:
        # All-same digit (00000... already caught above)
        ([0-9a-f])\1{31}
        |
        # Sequential nibbles 0→f (0123456789abcdef repeated twice)
        0123456789abcdef0123456789abcdef
        |
        # Sequential nibbles starting at any point (e.g. d9e3f4a5...)
        # Detect if 16+ of the 32 hex chars are in ascending order
        # by checking if sorted(chars) == chars for long runs — too complex;
        # use simpler: flag if it contains obvious 01234 or abcde* runs ≥8 chars
        .*(?:0123456789|abcdefghijklm|23456789abc).*
    )$
    """,
    re.IGNORECASE,
)


def _is_placeholder_guid(guid_str: str) -> bool:
    """Return True if the GUID looks like a human-typed placeholder.

    Conservative: only flags obvious sequential patterns.
    Does NOT flag crypto-random GUIDs or real Acumatica module GUIDs.

    Extended 2026-05-12 (W4 recovery guards) to also detect:
    - Byte-pair monotonic ascending sequence (e.g. a1b2c3d4-e5f6-7890-...)
      where each successive byte-pair value >= previous (12 of 16 byte-pairs
      in non-decreasing order across the full 128-bit value).
    """
    # Strip dashes for analysis
    hex_only = guid_str.replace("-", "").lower()
    if len(hex_only) != 32:
        return False
    # Known-bad all-zeros is handled separately; all-same-char catches all-f etc.
    if len(set(hex_only)) == 1:
        return True
    # Check for obviously sequential runs of 10+ ascending hex chars
    sequential_runs = re.search(r'(?:0123456789|123456789a|23456789ab|456789abcd|9abcdef012)', hex_only)
    if sequential_runs:
        return True
    # Byte-pair ascending sequence heuristic:
    # Split the 32 hex chars into 16 byte-pair values and check if at least
    # 12 consecutive pairs are in non-decreasing order. This catches patterns
    # like a1b2c3d4e5f678901234567890abcdef where each byte increments.
    byte_values = [int(hex_only[i:i+2], 16) for i in range(0, 32, 2)]
    ascending_run = 1
    max_ascending_run = 1
    for i in range(1, len(byte_values)):
        if byte_values[i] >= byte_values[i - 1]:
            ascending_run += 1
            max_ascending_run = max(max_ascending_run, ascending_run)
        else:
            ascending_run = 1
    if max_ascending_run >= 12:
        return True
    return False


def validate_sitemap_no_orphans(root):
    """Flag GI <SiteMap>/<row> entries with orphan or placeholder ParentIDs.

    - FAIL (error) if ParentID is the all-zeros NULL GUID.
    - FAIL (error) if ParentID matches obvious placeholder patterns.
    - WARN (warn) if ParentID is non-zero, non-placeholder, but doesn't appear
      as any other row's NodeID in the same project.xml (unknown parent).

    Category: sitemap_orphan_parent
    Reference: CLAUDE.md rule #125; W4 AAR guard #2.
    """
    gi_blocks = root.findall(".//GenericInquiryScreen")
    if not gi_blocks:
        return

    # Collect all NodeIDs present anywhere in the document (from SiteMap rows,
    # ScreenWithRights rows, etc.) so we can validate ParentID references.
    all_node_ids: set[str] = set()
    for row in root.findall(".//SiteMap//row"):
        nid = row.get("NodeID")
        if nid:
            all_node_ids.add(nid.lower())
    for row in root.findall(".//ScreenWithRights//row"):
        nid = row.get("NodeID")
        if nid:
            all_node_ids.add(nid.lower())

    orphan_count = 0
    placeholder_count = 0
    unknown_parent_count = 0

    for gi_block in gi_blocks:
        # Get GI name for error messages
        gi_name = "(unknown)"
        gi_design = gi_block.find("GIDesign")
        if gi_design is not None:
            gi_name = gi_design.get("Name") or gi_design.get("PrimaryScreenIDNew", gi_name)
            for row in gi_design.findall("row"):
                gi_name = row.get("Name", gi_name)

        for sm_row in gi_block.findall(".//SiteMap/row"):
            parent_id = sm_row.get("ParentID", "")
            if not parent_id:
                continue

            if parent_id == _ORPHAN_PARENT_ID:
                orphan_count += 1
                error(
                    f"GI '{gi_name}': <SiteMap>/<row ParentID=\"{parent_id}\"> is the all-zeros\n"
                    f"         NULL GUID — this is an orphan SiteMap node. Orphan rows are invisible\n"
                    f"         in SM205010 (Access Rights by Role), so no role can grant access,\n"
                    f"         and OData returns HTTP 404 (not 403) for this GI.\n"
                    f"         Fix: set ParentID to the NodeID of the GI's parent module node.\n"
                    f"         2026-05-10 W4: 15 of 17 Bolt GIs had this exact ParentID.\n"
                    f"         AAR: client-asthetik/acumatica/docs/runbooks/aar-2026-05-10-bolt-gi-recovery-cascade.md\n"
                    f"         See CLAUDE.md rule #125."
                )
            elif _is_placeholder_guid(parent_id):
                placeholder_count += 1
                error(
                    f"GI '{gi_name}': <SiteMap>/<row ParentID=\"{parent_id}\"> looks like a\n"
                    f"         human-typed placeholder GUID (sequential/repeated byte pattern).\n"
                    f"         This ParentID will not point to a real SiteMap module node.\n"
                    f"         Fix: replace with the actual NodeID of the parent module.\n"
                    f"         2026-05-10 W4: one Bolt GI had d9e3f4a5-b2c3-4678-9abc-def012345678.\n"
                    f"         See CLAUDE.md rule #125."
                )
            elif parent_id.lower() not in all_node_ids:
                # ParentID is non-zero and non-placeholder but not found locally.
                # Could be a valid Acumatica stock module GUID (not in this project.xml).
                # Warn conservatively rather than failing.
                unknown_parent_count += 1
                warn(
                    f"GI '{gi_name}': <SiteMap>/<row ParentID=\"{parent_id}\"> does not appear\n"
                    f"         as any other row's NodeID in this project.xml. If this is a stock\n"
                    f"         Acumatica module GUID, this warning is a false positive — verify by\n"
                    f"         checking SM205010 > Customizations module tree.\n"
                    f"         If this is a custom GUID, the parent node must be declared in the same\n"
                    f"         project.xml or the GI will be invisible in the screen tree.\n"
                    f"         See CLAUDE.md rule #125."
                )

    total_bad = orphan_count + placeholder_count
    if total_bad == 0 and unknown_parent_count == 0:
        if gi_blocks:
            ok("SiteMap ParentIDs: all GI SiteMap rows have non-orphan ParentIDs")


# ── W4 Guard D: zip name must match acuops.yaml primary project name ──────────
# 2026-05-10 W4 incident: acuops.yaml declared project.name="AcuOps" but the
# build packaged Bolt_*.zip as the artifact. publishBegin ran
# [Bolt, Bolt, AsthetikTheme] — duplicate Bolt, AcuOps absent.
#
# This guard reads acuops.yaml (using the same search logic as validate_isv_copublish)
# and compares project.name against the Customization/<dir> name that contains this
# project.xml. If they differ, the deploy pipeline will package the wrong artifact.
#
# Reference: client-asthetik/acumatica/docs/runbooks/aar-2026-05-10-bolt-gi-recovery-cascade.md
# See W4 AAR guard #4.

def validate_zip_name_matches_acuops_yaml_primary(file_path: Path):
    """Check that the Customization/<dir> name matches project.name in acuops.yaml.

    The zip artifact name is derived from the Customization/<dir> name.
    If it doesn't match acuops.yaml's project.name, the wrong primary package
    will be deployed (or co-publish list may be duplicated/absent).

    Skips silently when acuops.yaml is not found (same as validate_isv_copublish).

    Category: zip_name_yaml_mismatch
    Reference: W4 AAR guard #4.
    """
    try:
        import yaml
    except ImportError:
        warn("pyyaml not available — zip-name/yaml-primary check skipped")
        return

    def _find_git_root(start: Path):
        current = start
        for _ in range(20):
            if (current / ".git").exists():
                return current
            parent = current.parent
            if parent == current:
                return None
            current = parent
        return None

    git_root = _find_git_root(file_path.parent)
    if git_root is not None:
        search_dirs = []
        current = file_path.parent
        for _ in range(8):  # walk further up than isv check (need to find acuops.yaml at acumatica/)
            search_dirs.append(current)
            if current == git_root:
                break
            parent = current.parent
            if parent == current:
                break
            current = parent
    else:
        search_dirs = [file_path.parent]

    acuops_yaml = None
    for d in search_dirs:
        candidate = d / "acuops.yaml"
        if candidate.exists():
            acuops_yaml = candidate
            break

    if acuops_yaml is None:
        # No acuops.yaml found — skip check (same behavior as isv guard)
        return

    try:
        with acuops_yaml.open() as f:
            config = yaml.safe_load(f) or {}
    except Exception as e:
        warn(f"Could not parse {acuops_yaml} for zip-name check: {e}")
        return

    yaml_primary = (config.get("project", {}) or {}).get("name", "")
    if not yaml_primary:
        warn(
            f"acuops.yaml at {acuops_yaml} has no project.name field — "
            f"cannot verify zip/yaml alignment. Add 'project.name' to acuops.yaml."
        )
        return

    # The Customization package dir name is the parent of project.xml's parent
    # (i.e., Customization/<PackageName>/project.xml → <PackageName>).
    # Only run this check when the project.xml lives inside a "Customization/<dir>/"
    # structure — otherwise the guard fires on test fixtures, temp directories, etc.
    grandparent = file_path.parent.parent
    if grandparent.name.lower() != "customization":
        # Not inside a Customization/<PackageName>/ layout — skip silently.
        return

    pkg_dir_name = file_path.parent.name

    if pkg_dir_name != yaml_primary:
        # Check if pkg_dir_name appears in co_publish list (it might be intentional)
        co_publish = (config.get("publish", {}) or {}).get("co_publish", []) or []
        pipeline_known = (config.get("pipeline", {}) or {}).get("known_projects", []) or []
        in_co_publish = pkg_dir_name in co_publish
        in_known = pkg_dir_name in pipeline_known

        if in_co_publish:
            ok(
                f"zip/yaml alignment: '{pkg_dir_name}' is in co_publish (primary='{yaml_primary}') — "
                f"co-publish packages may differ from primary"
            )
        else:
            msg = (
                f"Customization package dir name '{pkg_dir_name}' does NOT match\n"
                f"         project.name='{yaml_primary}' in {acuops_yaml.name}.\n"
                f"         The build pipeline derives the zip filename from the dir name;\n"
                f"         if the primary package name differs, the wrong zip will be deployed.\n"
                f"         Fix options:\n"
                f"           (a) rename the Customization dir to match project.name ('{yaml_primary}'), OR\n"
                f"           (b) update project.name in acuops.yaml to match the dir ('{pkg_dir_name}'), OR\n"
                f"           (c) if this is intentionally a co-publish package, add it to\n"
                f"               publish.co_publish in acuops.yaml.\n"
                f"         2026-05-10 W4: yaml said primary=AcuOps but zip packaged Bolt; "
                f"publishBegin ran [Bolt, Bolt, AsthetikTheme] (duplicate, AcuOps absent).\n"
                f"         AAR: aar-2026-05-10-bolt-gi-recovery-cascade.md"
            )
            if in_known:
                # Known project but not in co_publish: warn (might be intentional)
                warn(msg)
            else:
                error(msg)
    else:
        ok(f"zip/yaml alignment: package dir '{pkg_dir_name}' matches project.name='{yaml_primary}'")


# ── W4 Guard E: RolesInMember/Cache fallback must include Cachetype ──────────
# Extends validate_role_copy_has_fallback() (acuops-pipeline#95).
#
# The #95 lint requires a direct-write fallback when the role-copy pattern is
# detected. But the fallback in acuops-pipeline#95's first shipped version
# used INFORMATION_SCHEMA-discovered columns with NULL as the fallback for
# unknown columns. Cachetype (column in RolesInMember and RolesInCache) is NOT NULL
# → INSERT fails with "Cannot insert NULL into column 'Cachetype'" → zero role
# grants → all target screens return HTTP 404.
#
# This guard inspects the fallback INSERT block for RolesInMember/RolesInCache
# and requires that either:
#   (a) the fallback includes "Cachetype" explicitly in the column list, OR
#   (b) the fallback uses a constant-value form (not schema-discovery) with a
#       non-NULL Cachetype entry, OR
#   (c) the code contains a comment "// cachetype-handled" or "Cachetype" near
#       the fallback INSERT, OR
#   (d) the fallback is absent (role-copy pattern not detected) → exempt.
#
# 2026-05-11 evidence: acuops-pipeline#95 fallback landed with "else fallbackValueExprs.Add("NULL")"
# catch-all; INSERT INTO RolesInMember/Cache failed for all 4 CIDs.
# See CLAUDE.md rule #122 (revised note).

_CACHETYPE_PRESENT_RE = re.compile(r'Cachetype', re.IGNORECASE)
_ROLEIN_MEMBER_CACHE_INSERT_RE = re.compile(
    r'INSERT\s+INTO\s+[^\s]*RolesIn(?:Member|Cache)[^;]+',
    re.DOTALL | re.IGNORECASE,
)
_NULL_FALLBACK_RE = re.compile(
    r'fallback\w*\s*\.?\s*Add\s*\(\s*["\']NULL["\']\s*\)|=\s*"NULL"',
    re.IGNORECASE,
)


def validate_role_grant_column_whitelist(root, file_path: Path, strict: bool = False):
    """Extend role-copy fallback check: RolesInMember/Cache INSERTs need Cachetype.

    When a plugin's direct-write fallback (detected by validate_role_copy_has_fallback)
    generates INSERT statements for RolesInMember or RolesInCache via schema discovery,
    the column whitelist MUST include Cachetype with a non-NULL value — it's NOT NULL
    in those tables and schema-discovery with a NULL catch-all will fail.

    Fires only when: role-copy pattern AND direct-write fallback AND Member/Cache INSERT
    are all present, AND Cachetype is NOT mentioned near the fallback block.

    Category: role_grant_cachetype
    Reference: CLAUDE.md rule #122 (revised 2026-05-11); W4 AAR guard #6.
    """
    # Collect all plugin C# code (same strategy as validate_role_copy_has_fallback)
    all_cs_code = ""

    for graph in root.findall(".//Graph"):
        source = graph.get("Source", "")
        if source == "#CDATA":
            cdata = graph.find("CDATA")
            if cdata is not None and cdata.text:
                all_cs_code += cdata.text + "\n"
        elif source.endswith(".cs"):
            cs_path = file_path.parent / source.replace("\\", "/")
            if cs_path.exists():
                try:
                    all_cs_code += cs_path.read_text(encoding="utf-8") + "\n"
                except Exception:
                    pass

    for _src_dir in (
        file_path.parent.parent.parent / "src",
        file_path.parent.parent.parent.parent / "src",
    ):
        if _src_dir.exists():
            for cs_file in _src_dir.rglob("*Install*.cs"):
                try:
                    all_cs_code += cs_file.read_text(encoding="utf-8") + "\n"
                except Exception:
                    pass

    if not all_cs_code.strip():
        return

    # Guard only fires when the role-copy pattern is present (same prerequisite as #95 guard)
    if not _ROLE_COPY_PATTERN.search(all_cs_code):
        return

    # Guard only fires when a direct-write fallback is present (we're extending #95, not replacing)
    if not _ROLE_COPY_FALLBACK_DIRECT.search(all_cs_code):
        return  # No fallback at all — let #95 guard handle that

    # Now check: does the code have a RolesInMember or RolesInCache INSERT?
    member_cache_inserts = _ROLEIN_MEMBER_CACHE_INSERT_RE.findall(all_cs_code)
    if not member_cache_inserts:
        return  # No Member/Cache INSERT — Cachetype not relevant

    # Is Cachetype mentioned anywhere in the plugin code?
    if _CACHETYPE_PRESENT_RE.search(all_cs_code):
        ok("RolesInMember/Cache fallback: Cachetype column is referenced in plugin code")
        return

    # Cachetype not mentioned — check for NULL fallback pattern which is the specific
    # dangerous form: schema-discovery with NULL as the catch-all for unknown columns.
    has_null_fallback = bool(_NULL_FALLBACK_RE.search(all_cs_code))

    msg = (
        "Plugin has RolesInMember/RolesInCache INSERT fallback but does NOT reference\n"
        "         'Cachetype' in the column whitelist.\n"
        "         Cachetype is NOT NULL in RolesInMember and RolesInCache — using\n"
        "         schema-discovery with a NULL catch-all (e.g., 'fallbackValueExprs.Add(\"NULL\")')\n"
        "         will cause INSERT to fail: 'Cannot insert NULL into column Cachetype'.\n"
        "         Fix: add an explicit 'Cachetype' entry with a sensible default (0 or 1)\n"
        "         to the column whitelist before the NULL fallback.\n"
        "         2026-05-11 evidence: acuops-pipeline#95 fallback failed for all 4 CIDs;\n"
        "         EnsureScreenRights null-op'd on RolesInMember/Cache → zero grants → HTTP 404.\n"
        "         See CLAUDE.md rule #122 (revised note)."
    )
    if strict or has_null_fallback:
        error(msg)
    else:
        warn(msg)


# ── W4 Recovery Guards (2026-05-11/12): GIWhere format + ParentID placeholders ─
#
# Two Bolt GIs (Bolt_DRP_SalesHistory, Bolt_DRP_OpenSOLines) returned OData 404
# after the rebrand because their <GIWhere> elements used invalid attribute values
# that Acumatica's ValFromStr.GetCondition parser rejected, causing SM208000 to
# fail to render the GI and excluding it from the OData catalog.
#
# Root causes (client-asthetik PRs #93 + #94):
#   - Condition="EQ" is invalid; Acumatica only accepts "E ", "NE", etc.
#   - Operator= attribute is misnamed; correct name is Operation= (no R).
#   - ParentID="d9e3f4a5-b2c3-4678-9abc-def012345678" is a human-typed placeholder.
#
# References: CLAUDE.md rule #128 #10/#11/#12 (post-W4 recovery additions).

# Valid Acumatica GIWhere Condition= attribute values.
# Source: Acumatica source ValFromStr.GetCondition + live GI XML from working
# Bolt GIs (2026-05-11 Heritage sample: "E ", "NE", "NU", "NN" all observed).
# "EQ" is the canonical wrong value — the parser throws on it.
_VALID_GIWHERE_CONDITIONS = frozenset({
    "E ",   # Equal (NOTE: trailing space is required)
    "G ",   # Greater (NOTE: trailing space is required)
    "L ",   # Less (NOTE: trailing space is required)
    "NE",   # Not Equal
    "NN",   # Not Null
    "NU",   # Null
    "BT",   # Between
    "GE",   # Greater or Equal
    "LE",   # Less or Equal
    "LK",   # Like
    "IS",   # Is (type-based)
    "IL",   # Is Like
    "IN",   # In
    "NI",   # Not In
})

# Override marker for GIWhere Condition checks (rare legitimate exceptions)
_GIWHERE_CONDITION_EXEMPT_RE = re.compile(
    r"giwhere-condition-exempt\s*:", re.IGNORECASE
)


def validate_giwhere_condition_vocabulary(root, raw_xml: str = ""):
    """Check all <GIWhere> elements for invalid Condition= attribute values.

    Acumatica's ValFromStr.GetCondition parser accepts only a fixed vocabulary
    of 2-character codes (some with trailing spaces). "EQ" is the canonical
    wrong value — the parser throws, SM208000 fails to render the GI, and OData
    returns HTTP 404 for that GI.

    Override marker: add a comment `<!-- giwhere-condition-exempt: <reason> -->`
    on the GIWhere row line to suppress this check for that specific element.

    Category: giwhere_condition_vocab
    Reference: CLAUDE.md rule #128 #10; W4 recovery client-asthetik PRs #93 + #94.
    """
    gi_blocks = root.findall(".//GenericInquiryScreen")
    if not gi_blocks:
        return

    bad_count = 0

    for gi_block in gi_blocks:
        # Resolve GI name for error messages
        gi_name = "(unknown)"
        gi_design = gi_block.find("GIDesign")
        if gi_design is not None:
            gi_name = gi_design.get("Name") or gi_design.get("PrimaryScreenIDNew", gi_name)
            for row in gi_design.findall("row"):
                gi_name = row.get("Name", gi_name)

        for where_elem in gi_block.findall(".//GIWhere"):
            condition = where_elem.get("Condition")
            if condition is None:
                continue  # No Condition attribute — not our problem

            line_nbr = where_elem.get("LineNbr", "?")

            # Check for override marker in the raw XML near this element.
            # We use a simple heuristic: look for the marker within 200 chars
            # before this element's Condition value in the raw XML.
            if raw_xml:
                # Find the Condition="EQ" (or whatever) text in the raw XML.
                search_snippet = f'LineNbr="{line_nbr}"'
                idx = raw_xml.find(search_snippet)
                if idx != -1:
                    context = raw_xml[max(0, idx - 200):idx + 200]
                    if _GIWHERE_CONDITION_EXEMPT_RE.search(context):
                        continue  # exempted

            if condition not in _VALID_GIWHERE_CONDITIONS:
                bad_count += 1
                error(
                    f"GI '{gi_name}' GIWhere LineNbr={line_nbr}: Condition=\"{condition}\" "
                    f"is not a valid Acumatica condition code.\n"
                    f"         Valid codes: \"E \" (Equal), \"G \" (Greater), \"L \" (Less),\n"
                    f"                      \"NE\" (Not Equal), \"NU\" (Null), \"NN\" (Not Null),\n"
                    f"                      \"BT\" (Between), \"GE\" (GE), \"LE\" (LE),\n"
                    f"                      \"LK\" (Like), \"IS\" (Is), \"IL\" (Is Like),\n"
                    f"                      \"IN\" (In), \"NI\" (Not In).\n"
                    f"         \"EQ\" is the canonical wrong value (Rule #128 #10).\n"
                    f"         Override: add <!-- giwhere-condition-exempt: <reason> --> near the row."
                )

    if bad_count == 0 and gi_blocks:
        ok("GIWhere Condition values: all rows use valid Acumatica condition codes")


def validate_giwhere_operator_attribute_typo(root):
    """Check all <GIWhere> elements for the misnamed Operator= attribute.

    The correct attribute name in Acumatica's project.xml schema is Operation=
    (AND/OR logic connector between where clauses). Operator= is silently
    ignored at publish time — the attribute is not recognized, and Acumatica
    defaults the Operation to a space, causing SM208000 to fail to render
    the GI with a ValFromStr.GetCondition exception.

    Category: giwhere_operator_typo
    Reference: CLAUDE.md rule #128 #11; W4 recovery client-asthetik PRs #93 + #94.
    """
    gi_blocks = root.findall(".//GenericInquiryScreen")
    if not gi_blocks:
        return

    bad_count = 0

    for gi_block in gi_blocks:
        gi_name = "(unknown)"
        gi_design = gi_block.find("GIDesign")
        if gi_design is not None:
            gi_name = gi_design.get("Name") or gi_design.get("PrimaryScreenIDNew", gi_name)
            for row in gi_design.findall("row"):
                gi_name = row.get("Name", gi_name)

        for where_elem in gi_block.findall(".//GIWhere"):
            if where_elem.get("Operator") is not None:
                line_nbr = where_elem.get("LineNbr", "?")
                bad_count += 1
                error(
                    f"GI '{gi_name}' GIWhere LineNbr={line_nbr}: attribute \"Operator=\" "
                    f"is misnamed.\n"
                    f"         Acumatica's project.xml schema requires \"Operation=\" (no R).\n"
                    f"         Publish silently ignores unrecognized attributes — value will be lost.\n"
                    f"         SM208000 then receives a blank Operation value and fails to render\n"
                    f"         the GI, causing ValFromStr.GetCondition exceptions + OData 404.\n"
                    f"         Fix: rename Operator= → Operation= on this GIWhere element.\n"
                    f"         Rule #128 #11; W4 recovery client-asthetik PR #94."
                )

    if bad_count == 0 and gi_blocks:
        ok("GIWhere Operation attribute: no 'Operator=' typos found (correct name is 'Operation=')")


# ── Rule-31 secondary: 5 additional <GenericInquiryScreen> failure modes ─────
# These were the target of PR #25's validate_generic_inquiry_screen_blocks but
# were not captured by PR #86's narrower validate_gi_modern_format (which only
# checks the 24.208 attribute set). Root-cause evidence: PR #462 sandbox
# 24-hour outage from a stuck-403 GI cluster; see CLAUDE.md rule #31 and
# memory/context/lessons-learned.md "Generic Inquiry XML Format (24.208)".

# Known-bad GIFilter Condition values that interfere with GI registration.
# These are parameter type/scope combos that Acumatica silently rejects or
# that produce screened-but-unreachable GIs. Expand as new failure modes emerge.
_GIFILTER_BLOCKED_CONDITIONS = frozenset({
    "EQ",  # placeholder — see below; real filter blocks documented per incident
})

# System-reserved ScreenID prefix for Acumatica internal GI screens.
# Custom GIs that claim an ID in this range collide with Acumatica's own
# catalog and behave unpredictably (phantom 404s, registration skips).
_GI_RESERVED_PREFIX = "GI007"


def validate_gi_secondary_modes(root):
    """Check <GenericInquiryScreen> blocks for 5 secondary failure modes.

    These are separate from the primary 24.208 attribute-set check
    (validate_gi_modern_format / CLAUDE.md rule #31 primary). Each mode maps
    to a real production incident in the PR #462 sandbox outage cycle.

    Failure modes checked:
      (1) Dual-row <GenericInquiryScreen> blocks — multi-row blocks attach
          RolesInGraph to the first row's NodeID only; second and subsequent GIs
          in the same block land 403 on every OData access.
      (2) System-reserved GI007xxx ScreenIDs — Acumatica reserves the GI007xxx
          range for its own internal GIs. Custom GIs that claim a ScreenID in
          this range collide with the catalog and behave unpredictably.
      (3) Phantom DAC refs — <GITable Name="..."> referencing a DAC that isn't
          a well-formed PascalCase identifier (contains namespace separators or
          obvious non-DAC tokens). Acumatica silently aborts GI processing when
          a GITable Name references a type it cannot resolve.
      (4) <GIFilter> parameter declarations — empty or attribute-only GIFilter
          rows (no nested <GIFilter> element children) can block GI registration
          when the parameter's data type isn't resolvable at publish time.
          This emits a WARNING, not a hard error, because GIFilter rows are
          legitimate in most cases. The warning prompts authors to verify
          registration with an OData probe post-deploy.
      (5) Self-closing <MUIScreen /> — an empty self-closing MUIScreen element
          registers the GI in metadata but makes it unreachable from the UI
          navigation tree, surfacing as "screen exists, doesn't render" tickets.
          A well-formed MUIScreen block contains at least one child element.

    All five checks are ERROR-level (not warnings) for modes (1)–(3) and (5),
    which have clear-cut bad states. Mode (4) is WARNING-level.

    Category: gi_secondary_modes
    """
    gi_blocks = root.findall(".//GenericInquiryScreen")
    if not gi_blocks:
        return

    issues_found = False

    for gi_block in gi_blocks:
        # ------------------------------------------------------------------
        # Determine the GI name for diagnostic messages.
        # Prefer GIDesign.Name; fall back to first SiteMap row Title.
        gi_design = gi_block.find("GIDesign")
        gi_name = "(unnamed)"
        if gi_design is not None:
            gi_name = gi_design.get("Name") or gi_name

        # Collect all SiteMap rows inside this block.
        sitemap_rows = gi_block.findall(".//SiteMap/row")

        # ── (1) Dual-row block ────────────────────────────────────────────
        # A <GenericInquiryScreen> block with more than one <SiteMap><row>
        # attaches RolesInGraph only to the first row's NodeID. All subsequent
        # rows land 403 on OData access until manually re-granted.
        # Root cause: CLAUDE.md rule #31 footnote "one <row> per block".
        if len(sitemap_rows) > 1:
            issues_found = True
            node_ids = [r.get("NodeID", "(missing)") for r in sitemap_rows]
            screen_ids = [r.get("ScreenID", "(missing)") for r in sitemap_rows]
            error(
                f"<GenericInquiryScreen Name=\"{gi_name}\"> contains {len(sitemap_rows)} "
                f"<SiteMap><row> entries — DUAL-ROW BLOCK.\n"
                f"         RolesInGraph attaches to the FIRST row's NodeID only; all subsequent\n"
                f"         rows land 403 on every OData access at runtime.\n"
                f"         ScreenIDs in this block: {screen_ids}\n"
                f"         NodeIDs in this block:   {node_ids}\n"
                f"         Fix: one <GenericInquiryScreen> block per GI ScreenID. Split into\n"
                f"         separate blocks, each with exactly one <SiteMap><row>.\n"
                f"         Root cause of PR #462 sandbox 24h outage (stuck-403 GI cluster).\n"
                f"         See CLAUDE.md rule #31 ('always one <row> per block')."
            )

        # ── (2) GI007xxx reserved ScreenIDs ──────────────────────────────
        # Acumatica reserves the GI007xxx range for its own internal GI screens.
        # Custom GIs claiming an ID in this range collide with the catalog.
        for row in sitemap_rows:
            screen_id = row.get("ScreenID", "")
            if screen_id.startswith(_GI_RESERVED_PREFIX):
                issues_found = True
                error(
                    f"<GenericInquiryScreen Name=\"{gi_name}\"> uses ScreenID \"{screen_id}\" "
                    f"— SYSTEM-RESERVED RANGE.\n"
                    f"         Acumatica reserves the GI007xxx ScreenID range for its own internal\n"
                    f"         GI catalog entries. Custom GIs that claim IDs in this range collide\n"
                    f"         with Acumatica's SiteMap, causing unpredictable registration failures,\n"
                    f"         phantom 404s on OData probes, and publish-time GI registration skips.\n"
                    f"         Fix: assign a ScreenID in your package's allocated range\n"
                    f"         (e.g., SB4xxxxx for Studio B packages).\n"
                    f"         See CLAUDE.md rule #31 (system-reserved GI007xxx range)."
                )

        # ── (3) Phantom DAC refs in <GITable Name="..."> ─────────────────
        # <GITable Name="..."> must reference a valid DAC type name (PascalCase,
        # no namespace separators, no spaces). Acumatica's GI processing engine
        # silently aborts when it can't resolve the type, leaving the GI in a
        # half-registered state: it appears in the SiteMap but returns empty
        # results (or 404) on every OData probe.
        # Heuristic: flag names that contain '.', '/', '\\', ' ', or are entirely
        # lowercase (DAC names are always PascalCase by Acumatica convention).
        for gi_table in gi_block.findall(".//GITable"):
            dac_name = gi_table.get("Name", "")
            if not dac_name:
                continue
            phantom = False
            reason = ""
            if "." in dac_name or "/" in dac_name or "\\" in dac_name:
                phantom = True
                reason = (
                    f"contains a namespace separator ('{dac_name}') — "
                    f"GITable Name must be the simple DAC class name, not a fully-qualified type."
                )
            elif " " in dac_name:
                phantom = True
                reason = (
                    f"contains a space ('{dac_name}') — "
                    f"DAC names never contain spaces."
                )
            elif dac_name and dac_name[0].islower() and not dac_name.startswith("usr"):
                # All-lowercase or camelCase is a strong signal of a mis-paste.
                # Allow 'usr*' (custom field prefix) which is intentionally lowercase.
                phantom = True
                reason = (
                    f"starts with a lowercase character ('{dac_name}') — "
                    f"Acumatica DAC class names always start with an uppercase letter."
                )
            if phantom:
                issues_found = True
                error(
                    f"<GenericInquiryScreen Name=\"{gi_name}\"> has <GITable Name=\"{dac_name}\"> "
                    f"— PHANTOM DAC REF.\n"
                    f"         {reason}\n"
                    f"         Acumatica's GI processing engine silently aborts when it cannot\n"
                    f"         resolve the referenced DAC type. The GI appears in the SiteMap\n"
                    f"         but returns empty results or 404 on every OData probe.\n"
                    f"         Fix: use the simple PascalCase DAC class name (e.g., 'POOrder',\n"
                    f"         'INSiteStatus') — not a fully-qualified or namespaced form.\n"
                    f"         See CLAUDE.md rule #31 ('phantom DAC refs in <GITable Name>')."
                )

        # ── (4) <GIFilter> parameter declarations ────────────────────────
        # GIFilter rows with no nested child elements (pure attribute-only
        # declarations) can block GI registration when the parameter's
        # data type isn't resolvable at publish time. This is a WARNING rather
        # than an error because GIFilter rows are common and mostly harmless;
        # the warning prompts a post-deploy OData probe to confirm registration.
        # Distinguish: <GIFilter ... /> (self-closing / no children) vs
        # <GIFilter ...><GICondition .../></GIFilter> (child conditions, safe).
        for gi_filter in gi_block.findall(".//GIFilter"):
            if len(list(gi_filter)) == 0:
                # No child elements — this is an attribute-only parameter row.
                param_name = gi_filter.get("Name") or gi_filter.get("DataField") or "(unnamed)"
                issues_found = True
                warn(
                    f"<GenericInquiryScreen Name=\"{gi_name}\"> has attribute-only "
                    f"<GIFilter Name=\"{param_name}\"> with no child elements.\n"
                    f"         GIFilter parameter declarations without resolved child conditions\n"
                    f"         can block GI registration when the parameter data type is not\n"
                    f"         resolvable at publish time. The GI may appear registered but\n"
                    f"         return no results on OData probes.\n"
                    f"         Action: after deploy, probe the GI via OData to confirm registration.\n"
                    f"         If the GI returns 404 or empty results, remove or simplify the filter.\n"
                    f"         See CLAUDE.md rule #31 ('GIFilter params can block registration')."
                )

        # ── (5) Self-closing <MUIScreen /> ───────────────────────────────
        # An empty/self-closing <MUIScreen> element registers the GI in
        # Acumatica's metadata but makes it unreachable from the UI navigation
        # tree. The screen appears in the OData catalog and /entity/ endpoints
        # but users cannot navigate to it from the menus — it surfaces as
        # "screen exists, doesn't render" support tickets.
        # A well-formed MUIScreen must contain at least one child element
        # (typically <MUIPinnedScreen>).
        for row in sitemap_rows:
            for mui in row.findall("MUIScreen"):
                if len(list(mui)) == 0 and not mui.text:
                    sid = row.get("ScreenID", "(unknown)")
                    issues_found = True
                    error(
                        f"<GenericInquiryScreen Name=\"{gi_name}\"> ScreenID \"{sid}\" has "
                        f"an empty self-closing <MUIScreen /> — UI-UNREACHABLE GI.\n"
                        f"         An empty <MUIScreen /> registers the GI in metadata but removes\n"
                        f"         it from the UI navigation tree. Users cannot navigate to it from\n"
                        f"         the menus — it surfaces as 'screen exists, doesn't render' tickets.\n"
                        f"         Fix: replace with a well-formed MUIScreen block, e.g.:\n"
                        f"           <MUIScreen>\n"
                        f"             <MUIPinnedScreen IsPortal=\"0\" Username=\"\" IsPinned=\"1\" />\n"
                        f"           </MUIScreen>\n"
                        f"         See CLAUDE.md rule #31 ('self-closing MUIScreen blocks')."
                    )

    if not issues_found and gi_blocks:
        ok(
            f"GI secondary modes: all {len(gi_blocks)} GenericInquiryScreen block(s) "
            f"pass dual-row, reserved-ScreenID, phantom-DAC, GIFilter, and MUIScreen checks"
        )


# ── AAR-2026-03-09: <Sql> CREATE TABLE silently ignored ──────────────────────
# <Sql> elements with CREATE TABLE are silently ignored on cloud Acumatica.
# Must use PXDatabase.Execute() in a CustomizationPlugin instead.

_SQL_CREATE_TABLE_PATTERN = re.compile(r"\bCREATE\s+TABLE\b", re.IGNORECASE)


def validate_sql_create_table(root):
    """Block <Sql> elements containing CREATE TABLE — silently ignored on cloud.

    Category: sql_create_table
    """
    for elem in root.findall(".//Sql"):
        name = elem.get("Name", "(unnamed)")
        cdata = elem.find("CDATA")
        if cdata is None or not (cdata.text or "").strip():
            continue
        sql_text = cdata.text or ""
        if _SQL_CREATE_TABLE_PATTERN.search(sql_text):
            error(
                f"<Sql Name=\"{name}\"> contains CREATE TABLE.\n"
                f"         <Sql> CREATE TABLE statements are silently ignored on cloud Acumatica —\n"
                f"         the publish log shows the script ran but the table is never created.\n"
                f"         Root cause of AAR-StudioBPORelations-2026-03-09 (7 hours, 15 approaches).\n"
                f"         Fix: use PXDatabase.Execute() with raw ADO.NET in a CustomizationPlugin\n"
                f"         (with TrustServerCertificate=True in the connection string).\n"
                f"         See CLAUDE.md rule #24 and AAR-StudioBPORelations-2026-03-09.md."
            )


# ── AAR-2026-03-29: Plugin INSERT into GI tables ─────────────────────────────
# See validate_gi_sql() below for the existing detect-and-block guard.
# The plugin_gi_insert check below covers a different angle: any C# string
# literal containing INSERT INTO GI* is flagged (the existing guard also
# fires — these are complementary). The category string differs: this is
# `plugin_gi_insert` while the existing guard uses `gi_sql`.
#
# Since validate_gi_sql() already covers INSERT INTO GI*, we don't add a
# redundant check here — the existing guard IS the catch for this AAR.
# The fixture for aar-2026-03-29 will exercise validate_gi_sql() directly.

GI_SQL_PATTERN = re.compile(
    r"(?:INSERT\s+INTO|DELETE\s+FROM|UPDATE|DROP\s+TABLE|TRUNCATE\s+TABLE|ALTER\s+TABLE)"
    r"\s+GI\w*",
    re.IGNORECASE,
)

GI_SQL_REVIEW_MARKER = "-- REVIEWED: gi-sql-safe"

# ── INUnit SQL guard ──────────────────────────────────────────────────────
# CRITICAL: Destructive INUnit SQL detection (AAR 2026-03-28)
# DELETE FROM INUnit destroys self-conversion records; items break on all
# order-entry screens. INSERT INTO INUnit creates ORM-invisible records
# unless CompanyMask is correctly copied from existing visible records.
# Root cause of 2026-03-28 production outage (restored from snapshot).

INUNIT_SQL_PATTERN = re.compile(
    r"(?:DELETE\s+FROM|INSERT\s+INTO)\s+INUnit",
    re.IGNORECASE,
)

INUNIT_SQL_REVIEW_MARKER = "-- REVIEWED: inunit-sql-safe"

# ── System-table column reference guard (AAR 2026-04-17) ──────────────────
# CRITICAL: PR #431 INSERTed into GIDesign/GITable/GIRelation/GISort using
# columns that don't exist in Acumatica 24.208 (Description, IsActive,
# IsDescending). The SQL failed at runtime, poisoned the app-pool's
# in-memory DAC + UserRecords registry, and every subsequent
# ProjectMaintenance.Persist() / SOOrderEntry.CreateShipment NRE'd in the
# favorites-refresh loop for 14 hours until a full publish triggered a real
# app-pool restart. CLAUDE.md rules #18 + #20.
#
# Allowlist strategy: minimum set of columns our plugins legitimately
# reference (derived from the known-good CleanupOrphanDRPGIRows in
# AesthetikContainersInstall.cs) plus the standard Acumatica audit columns
# that are universal across every DAC. Columns PR #431 invented are
# DELIBERATELY absent — listing them here would defeat the guard.
#
# If a schema change makes a new column legitimate (e.g. Acumatica 25.x
# adds a field), either (a) extend this allowlist in a reviewed PR or
# (b) add `-- REVIEWED: schema-safe` in a comment near the SQL to bypass.

SCHEMA_SAFE_REVIEW_MARKER = "-- REVIEWED: schema-safe"

# ── Extension-safety review marker ───────────────────────────────────────
# Rule 2 of validate_extension_safety flags every instance
# `.GetExtension<T>()` as MEDIUM RISK because on records from
# foreign-graph / uncached sources the extension collection may not be
# initialized. In practice, records obtained via
# `SelectFrom<T>.View.Select(graph, ...)`, `Base.Document.Current`, or
# `Base.Transactions.Select()` route through a PXCache and the instance
# call is safe.
#
# The `// REVIEWED: extension-safe` marker suppresses the warning for a
# reviewed call site. It is LINE-LOCAL (same line or the line
# immediately above) on purpose — file-wide opt-outs defeat the audit
# trail. Every suppressed site must carry its own justification next to
# the code it describes.
#
# This is a C# comment (`//`) rather than a SQL comment (`--`) because
# the call being reviewed is C# code, not SQL inside a C# string literal.

EXTENSION_SAFE_REVIEW_MARKER = "// REVIEWED: extension-safe"


def _has_extension_safe_review_marker(code: str, clean: str, match_pos: int) -> bool:
    """Return True if `// REVIEWED: extension-safe` appears at a position
    that covers the call at `match_pos`.

    Two accepted placements:
      1. Trailing marker on the same line as the call:
             var ext = x.GetExtension<Foo>();  // REVIEWED: extension-safe — why
      2. Standalone marker on the line immediately above (pure-comment line only):
             // REVIEWED: extension-safe — why
             var ext = x.GetExtension<Foo>();

    A marker trailing a line that ALSO contains code (e.g. another
    `.GetExtension<>()` call) applies to that line only, not to the line
    below — this prevents one reviewer's signoff from silently absorbing
    an unrelated unaudited call placed immediately after.

    `match_pos` is a position in `clean` (post-comment-strip). We derive a
    1-indexed line number via newline count and look the same line up in
    the original `code` (the marker itself is a comment and has been
    stripped from `clean`).

    Multi-line `/* ... */` blocks appearing before the match can shift
    the mapping between clean-line-number and code-line-number. This
    function fails closed in that case: the marker won't be found and
    the reviewer either refactors to the `PXCache<T>.GetExtension<>()`
    form or moves the marker closer. False positives here cost a
    refactor; false negatives (accepting unaudited code) would defeat
    the guard.
    """
    line_no = clean[:match_pos].count("\n") + 1  # 1-indexed
    code_lines = code.split("\n")
    if not (1 <= line_no <= len(code_lines)):
        return False
    # Placement 1: trailing on the same line as the call
    if EXTENSION_SAFE_REVIEW_MARKER in code_lines[line_no - 1]:
        return True
    # Placement 2: standalone comment on the immediately-above line
    if line_no >= 2:
        prev = code_lines[line_no - 2].strip()
        if prev.startswith("//") and EXTENSION_SAFE_REVIEW_MARKER in prev:
            return True
    return False

# Standard Acumatica audit columns present on every CompanyID-scoped DAC.
# Safe to reference on any system table that carries CompanyID.
_AUDIT_COLUMNS = frozenset({
    "CompanyID",
    "CreatedByID", "CreatedByScreenID", "CreatedDateTime",
    "LastModifiedByID", "LastModifiedByScreenID", "LastModifiedDateTime",
    "NoteID", "tstamp",
})

# Per-table allowed column set (union'd with _AUDIT_COLUMNS at lookup time).
# Built from working plugin precedent — not from speculation. Columns PR
# #431 used that don't exist (Description, IsActive on GITable/GIRelation,
# IsDescending on GISort) are deliberately omitted.
#
# The conservative default here means ANY new INSERT/UPDATE/SELECT column
# list against a system table will trip the guard unless the column is
# either already in this allowlist, a universal audit column, or the SQL
# carries the `-- REVIEWED: schema-safe` marker. That asymmetry is load-
# bearing: false positives are cheap (tell the reviewer to add the
# marker); false negatives caused a 14-hour prod outage.
_SYSTEM_TABLE_COLUMN_ALLOWLIST = {
    # Columns confirmed present in 24.208 by the working CleanupOrphanDRPGIRows
    # SELECT in src/StudioB.Containers/Graphs/AesthetikContainersInstall.cs.
    # PrimaryScreenIDNew added 2026-05-15 for Bolt V9 GI recovery
    # (FixBoltGIDesignPrimaryScreens — matches PR #93's working pattern).
    "GIDesign": frozenset({"DesignID", "Name", "PrimaryScreenIDNew"}),
    # GI child tables are only ever DELETEd with WHERE by working plugins —
    # no INSERT/UPDATE/SELECT column lists exist in known-good code. Allow
    # only the relationship key so any new column list lands in review.
    "GITable":       frozenset({"DesignID"}),
    "GIResult":      frozenset({"DesignID"}),
    # Condition + Operation + LineNbr added 2026-05-15 for Bolt V9 GI recovery
    # (RepairBoltGIWhereGIOnFormat — matches PR #94's working pattern: Condition
    # 'EQ'->'E ', Operation ' '->per-line, LineNbr as predicate column).
    "GIWhere":       frozenset({"DesignID", "Condition", "Operation", "LineNbr"}),
    "GISort":        frozenset({"DesignID"}),
    "GIFilter":      frozenset({"DesignID"}),
    "GIRelation":    frozenset({"DesignID"}),
    # Condition + LineNbr added 2026-05-15 for Bolt V9 GI recovery
    # (RepairBoltGIWhereGIOnFormat Phase 3 — 'E'->'E ' padding, matches PR #94).
    "GIOn":          frozenset({"DesignID", "Condition", "LineNbr"}),
    "GIGroupBy":     frozenset({"DesignID"}),
    # Platform-owned projection + favorites tables. Writes from a plugin
    # would have caused the 2026-04-17 outage if even a single stray
    # column landed; keep locked to audit columns only.
    "CustProject":    frozenset(),
    "UserRecords":    frozenset(),
    "FavoriteRecord": frozenset(),
}


def _is_system_table(name: str) -> bool:
    return name in _SYSTEM_TABLE_COLUMN_ALLOWLIST


def _allowed_columns_for(table: str) -> "frozenset[str]":
    return _SYSTEM_TABLE_COLUMN_ALLOWLIST[table] | _AUDIT_COLUMNS


def _normalize_table_name(raw: str) -> str:
    """Strip [brackets], `backticks`, "quotes", and schema prefix.
    e.g. `[dbo].[GIDesign]` → `GIDesign`."""
    cleaned = re.sub(r"[\[\]`\"]", "", raw)
    return cleaned.split(".")[-1]


def _normalize_column_name(raw: str) -> str:
    """Strip qualifier, brackets, alias (AS ...), whitespace. Returns bare
    column name or empty string if it doesn't look like a simple column.

    Returns empty for SQL function-call expressions (CAST(...), ISNULL(...),
    etc.) — the function call may legitimately reference a real column, but
    the function expression itself is not a column ref we should validate.
    Added 2026-05-15: prior versions returned 'CAST(DesignID' as a
    pseudo-column-name, false-flagging LogGIDesignState-style diagnostic
    SELECTs that wrap real columns in CAST/ISNULL.
    """
    s = raw.strip()
    if not s:
        return ""
    # Drop AS <alias>
    s = re.split(r"\s+AS\s+", s, flags=re.IGNORECASE)[0].strip()
    # Drop trailing alias (col alias) — keep only first token
    s = s.split()[0] if s else s
    # Strip brackets/backticks/quotes
    s = re.sub(r"[\[\]`\"]", "", s)
    # Drop qualifier (t.Col → Col)
    if "." in s:
        s = s.split(".")[-1]
    # Skip function-call expressions and string literals — these wrap real
    # columns but the expression itself isn't a column to validate.
    if "(" in s or ")" in s or s.startswith("'"):
        return ""
    return s


def validate_gi_sql(class_name: str, code: str):
    """Block direct SQL statements targeting GI (Generic Inquiry) tables.

    INSERT, DELETE, UPDATE, DROP, TRUNCATE, and ALTER against GI* tables
    are extremely dangerous — they bypass Acumatica's GI engine and can
    corrupt the GI metadata, bricking screens that depend on Generic Inquiries.

    On 2026-03-29 a CustomizationPlugin that ran INSERT INTO GIDesign/GIFilter/etc.
    took production down for 45 minutes. This check prevents that at build time.

    If the SQL is intentional and has been reviewed, add the comment:
        -- REVIEWED: gi-sql-safe
    """
    if GI_SQL_REVIEW_MARKER in code:
        return

    match = GI_SQL_PATTERN.search(code)
    if match:
        error(
            f"{class_name}: Direct SQL against GI table detected: \"{match.group()}\"\n"
            f"         Direct SQL against GI* tables (GIDesign, GIFilter, GIWhere, GISort, etc.)\n"
            f"         corrupts Generic Inquiry metadata and can brick the instance.\n"
            f"         Root cause of 2026-03-29 production outage (45 min down).\n"
            f"         Fix: Use the GI screen (SM208000) or Acumatica GI API instead.\n"
            f"         If reviewed and intentional, add: -- REVIEWED: gi-sql-safe"
        )


def validate_inunit_sql(class_name: str, code: str):
    """Block DELETE FROM INUnit and INSERT INTO INUnit in CustomizationPlugins.

    Self-conversion records (BaseUnit->BaseUnit, rate 1.0) are mandatory at
    item level. Deleting them breaks all order entry screens. Raw SQL INSERT
    creates ORM-invisible records unless CompanyMask is copied from existing
    visible records.

    Root cause of 2026-03-28 production outage (restored from snapshot).

    If reviewed and intentional, add: -- REVIEWED: inunit-sql-safe
    """
    if INUNIT_SQL_REVIEW_MARKER in code:
        return

    match = INUNIT_SQL_PATTERN.search(code)
    if match:
        error(
            f"{class_name}: Destructive SQL against INUnit detected: \"{match.group()}\"\n"
            f"         DELETE FROM INUnit destroys self-conversion records that items depend on.\n"
            f"         INSERT INTO INUnit creates ORM-invisible records without correct CompanyMask.\n"
            f"         Root cause of 2026-03-28 production outage (restored from snapshot).\n"
            f"         Fix: Use PXDatabase.Insert<INUnit>() or the Unit Conversions screen (IN209000).\n"
            f"         If reviewed and intentional, add: -- REVIEWED: inunit-sql-safe"
        )


def validate_plugin_sql_column_refs(class_name: str, code: str):
    """Block C# plugin SQL that references columns absent on an Acumatica
    system table.

    Scans INSERT/UPDATE/SELECT column lists in C# string literals for
    references to Acumatica system tables (GIDesign, GITable, GIResult,
    GIWhere, GISort, GIFilter, GIRelation, GIOn, GIGroupBy, CustProject,
    UserRecords, FavoriteRecord). Any column not in the per-table
    allowlist is a HARD FAIL — the SQL would throw at runtime, poison the
    app-pool's in-memory DAC cache, and NRE every subsequent
    ProjectMaintenance.Persist() / SOOrderEntry.CreateShipment call
    (root cause of the 2026-04-17 14-hour production outage).

    Handles three syntaxes:
      * INSERT INTO <table> (col1, col2, ...) VALUES (...)
      * UPDATE <table> SET col1 = @p1, col2 = @p2
      * SELECT col1, col2 FROM <table>    (skips SELECT * and SELECT @v =)

    DELETE statements are NOT checked — they have no column list to
    validate, and the working CleanupOrphanDRPGIRows plugin is DELETE-
    heavy by design. Other destructive-SQL guards (validate_gi_sql,
    validate_inunit_sql) cover DELETE from specific tables.

    Handles C# string concatenation across lines (reuses the same
    `"..." + "..."` flattener as validate_customization_plugin_ban).

    Escape hatch: add `-- REVIEWED: schema-safe` in a comment near the
    SQL to bypass the check (e.g. when extending an allowed DAC in a
    reviewed PR). Matches the existing `-- REVIEWED: gi-sql-safe` and
    `-- REVIEWED: inunit-sql-safe` pattern family.

    See: CLAUDE.md rules #18 + #20, AAR-2026-04-17-custproject-nre-transient.md
    on the acumatica-ci-cd repo.
    """
    if SCHEMA_SAFE_REVIEW_MARKER in code:
        return

    # Strip comments so SQL inside /* ... */ or // ... doesn't false-trigger
    clean = re.sub(r"///.*$", "", code, flags=re.MULTILINE)
    clean = re.sub(r"//.*$", "", clean, flags=re.MULTILINE)
    clean = re.sub(r"/\*.*?\*/", "", clean, flags=re.DOTALL)

    # Flatten C# string concatenation so SQL spanning multiple lines is
    # matched as a single string — same approach as validate_customization_plugin_ban.
    #   "INSERT INTO Foo " +
    #   "(col1, col2) VALUES ..."
    # becomes
    #   "INSERT INTO Foo (col1, col2) VALUES ..."
    sql_flat = re.sub(r'"\s*\+\s*\n\s*"', " ", clean)

    reported = set()  # (table, col) pairs we've already flagged — keep output terse

    def _flag(table: str, col: str, verb: str):
        key = (table, col)
        if key in reported:
            return
        reported.add(key)
        error(
            f"{class_name}: BANNED — {verb} {table} references unknown column '{col}'.\n"
            f"         {table}.{col} does not exist in Acumatica 24.208 (verified against the\n"
            f"         working CleanupOrphanDRPGIRows plugin). Raw SQL with a bad column\n"
            f"         poisons the app-pool's in-memory DAC + UserRecords cache — every\n"
            f"         subsequent ProjectMaintenance.Persist() and SOOrderEntry.CreateShipment\n"
            f"         call NREs in the favorites-refresh loop. Root cause of the 2026-04-17\n"
            f"         CustProject NRE outage (14 hours; PR #431 EnsureDRPGenericInquiries).\n"
            f"         See CLAUDE.md rules #18 + #20.\n"
            f"         Fix: remove '{col}' from the column list, or use a safer API\n"
            f"         (GI editor SM208000, Acumatica GI import XML, etc.).\n"
            f"         If reviewed and intentional, add: {SCHEMA_SAFE_REVIEW_MARKER}"
        )

    # ── INSERT INTO <table> (cols) ──
    # Non-greedy column list up to the matching ')'. \w+ for table handles
    # plain identifiers; _normalize_table_name scrubs [brackets]/schema.
    for m in re.finditer(
        r"INSERT\s+INTO\s+([\[\]\.\w]+)\s*\(([^)]+)\)",
        sql_flat,
        re.IGNORECASE,
    ):
        table = _normalize_table_name(m.group(1))
        if not _is_system_table(table):
            continue
        allowed = _allowed_columns_for(table)
        for col_raw in m.group(2).split(","):
            col = _normalize_column_name(col_raw)
            if col and col not in allowed:
                _flag(table, col, "INSERT INTO")

    # ── UPDATE <table> SET col = ..., col = ... ──
    # Match the SET clause until WHERE, end-of-statement, or the literal
    # terminator of the containing C# string. The non-greedy .+? paired
    # with a lookahead keeps this tractable.
    for m in re.finditer(
        r"UPDATE\s+([\[\]\.\w]+)\s+SET\s+(.+?)(?=\s+WHERE\b|;|\"|$)",
        sql_flat,
        re.IGNORECASE | re.DOTALL,
    ):
        table = _normalize_table_name(m.group(1))
        if not _is_system_table(table):
            continue
        allowed = _allowed_columns_for(table)
        set_clause = m.group(2)
        # Each comma-separated assignment; the column is the text before `=`
        for assignment in set_clause.split(","):
            lhs = assignment.split("=", 1)[0]
            col = _normalize_column_name(lhs)
            if col and col not in allowed:
                _flag(table, col, "UPDATE")

    # ── SELECT cols FROM <table> ──
    # Skip SELECT * (no cols to check) and SELECT @var = col ... (variable
    # assignment — a T-SQL pattern where we can't reason cleanly about the
    # projection columns; the actual column reference will be re-checked
    # if anyone tries to INSERT/UPDATE it).
    for m in re.finditer(
        r"SELECT\s+(.+?)\s+FROM\s+([\[\]\.\w]+)",
        sql_flat,
        re.IGNORECASE | re.DOTALL,
    ):
        cols_raw = m.group(1).strip()
        table = _normalize_table_name(m.group(2))
        if not _is_system_table(table):
            continue
        # Strip leading DISTINCT / TOP N
        cols_raw = re.sub(r"^\s*DISTINCT\s+", "", cols_raw, flags=re.IGNORECASE)
        cols_raw = re.sub(r"^\s*TOP\s+\d+\s+", "", cols_raw, flags=re.IGNORECASE)
        if cols_raw.startswith("*") or "=" in cols_raw:
            continue
        allowed = _allowed_columns_for(table)
        for col_raw in cols_raw.split(","):
            col = _normalize_column_name(col_raw)
            if col and col not in allowed:
                _flag(table, col, "SELECT")


# ── DLL-sourced plugin scan (AAR 2026-04-17, gap PR #24 left) ────────────
# PR #24's validate_plugin_sql_column_refs runs on <Graph Source="#CDATA"> and
# <Graph Source="Code\..cs"> only. The canonical build pattern at
# acumatica-ci-cd is:
#   src/{DllName}/**/*.cs   →   compiled   →   Bin\{DllName}.dll
#   project.xml: <File AppRelativePath="Bin\{DllName}.dll" />
# AesthetikContainers and AesthetikWMS both ship this pattern today;
# validate-project.py never opens their src/ trees, so the rule-18 column-
# ref check has zero coverage for them. PR #431's EnsureDRPGenericInquiries
# lived in exactly this path when it triggered the 2026-04-17 14-hour NRE
# outage.  This scan closes the gap.

# Directories inside src/{DllName}/ that hold generated output, not source.
_DLL_SRC_SKIP_DIRS = frozenset({"bin", "obj", ".vs", "packages"})

# Auto-generated / assembly-metadata files that don't hold plugin source.
_DLL_SRC_SKIP_BASENAMES = frozenset({
    "AssemblyInfo.cs",
    ".NETFramework,Version=v4.8.AssemblyAttributes.cs",
})


def _find_src_tree(project_xml_path: Path, dll_basename: str, max_levels: int = 5) -> "Path | None":
    """Walk up from project_xml_path's parent searching for src/{dll_basename}/.

    Returns the first match, or None if no match within max_levels levels.
    Matches the acumatica-ci-cd repo layout where project.xml lives at
    Customization/{Pkg}/ and source at src/{DllName}/ under repo root."""
    current = project_xml_path.parent
    for _ in range(max_levels + 1):
        candidate = current / "src" / dll_basename
        if candidate.is_dir():
            return candidate
        parent = current.parent
        if parent == current:
            break
        current = parent
    return None


def _iter_plugin_cs_files(src_dir: Path):
    """Yield .cs files under src_dir, skipping build output + generated files."""
    for path in sorted(src_dir.rglob("*.cs")):
        rel_parts = path.relative_to(src_dir).parts
        if any(seg.lower() in _DLL_SRC_SKIP_DIRS for seg in rel_parts[:-1]):
            continue
        if path.name in _DLL_SRC_SKIP_BASENAMES:
            continue
        yield path


def validate_dll_source_references(
    project_xml_path: str,
    strict: bool = False,
    src_root_override: "str | None" = None,
):
    """For every <File AppRelativePath="Bin\\{X}.dll" /> in project.xml,
    find the corresponding src/{X}/ tree and run every plugin check
    validate() already runs on <Graph Source="#CDATA"> / <Graph
    Source="Code\\*.cs"> on each .cs file:

      * validate_plugin_sql_column_refs   (rule-18, AAR 2026-04-17)
      * validate_customization_plugin_ban (AAR 2026-03-28)
      * validate_gi_sql                   (AAR 2026-03-29)
      * validate_inunit_sql               (AAR 2026-03-28)
      * validate_pxdb_has_sql             (Vendor PXDB ban, 2026-03-28)
      * scan_security                     (hardcoded secrets)
      * validate_csharp                   (braces, Base.Transactions.Insert
                                           in RowUpdated, problematic types)
      * validate_extension_safety         (inquiry e.Row.GetExtension, etc.)
      * validate_crm_dac_safety           (CRM DACs on non-CRM graphs)

    PR #24's column-ref guard protects against the rule-18 failure mode
    (plugin SQL with non-existent system-table columns → app-pool cache
    poisoning → UserRecordsDBUpdater NRE for 14 hours), but it only
    scans C# code visible to <Graph Source="#CDATA"> and <Graph
    Source="Code\\*.cs">. PR #27 closed the rule-18 gap on DLL source;
    this function closes the equivalent gap for every other plugin check.
    Severity matches CDATA mode: hard-fails stay hard-fails, warns stay
    warns.

    Args:
        project_xml_path: Path to Customization/<pkg>/project.xml.
        strict: Propagated to validate_csharp / validate_extension_safety /
            validate_crm_dac_safety — same semantics as CDATA mode.
        src_root_override: Test hook. If set, skip walk-up discovery and
            look for {src_root_override}/{DllName}/ directly.

    See CLAUDE.md rule #18; AAR-2026-04-17-custproject-nre-transient.md.
    """
    p = Path(project_xml_path)
    try:
        tree = ET.parse(str(p))
    except ET.ParseError:
        return  # XML parse errors are already reported by validate().
    root = tree.getroot()

    dll_refs = []
    for f in root.findall(".//File"):
        app_rel = f.get("AppRelativePath", "")
        if not app_rel:
            continue
        norm = app_rel.replace("\\", "/")
        if not norm.lower().startswith("bin/") or not norm.lower().endswith(".dll"):
            continue
        basename = Path(norm).stem
        if basename:
            dll_refs.append(basename)

    if not dll_refs:
        return

    for dll_name in dll_refs:
        if src_root_override:
            candidate = Path(src_root_override) / dll_name
            src_dir = candidate if candidate.is_dir() else None
        else:
            src_dir = _find_src_tree(p, dll_name)

        if src_dir is None:
            warn(
                f'<File AppRelativePath="Bin\\{dll_name}.dll"> — no sibling '
                f'src/{dll_name}/ tree found (walked up from {p.parent}). '
                f'Rule-18 column-ref guard cannot run on DLL source; see '
                f'AAR-2026-04-17-custproject-nre-transient.md.'
            )
            continue

        # Collect every .cs file + concatenated text once. The
        # concatenated text is used as the `all_sql_text` argument to
        # validate_pxdb_has_sql — in DLL-source packages the DDL is in
        # the CustomizationPlugin body, not in project.xml <Sql>
        # elements, so the per-field "missing <Sql>" warn is only
        # meaningful against the combined C# source.
        cs_files = list(_iter_plugin_cs_files(src_dir))
        combined_cs_text = ""
        for cs_path in cs_files:
            try:
                combined_cs_text += cs_path.read_text(encoding="utf-8") + "\n"
            except (OSError, UnicodeDecodeError):
                continue

        for cs_path in cs_files:
            try:
                code = cs_path.read_text(encoding="utf-8")
            except (OSError, UnicodeDecodeError):
                continue
            rel = cs_path.relative_to(src_dir.parent)
            class_name = str(rel)

            # Rule-18 column-ref guard (PR #27).
            validate_plugin_sql_column_refs(class_name, code)

            # Extended plugin checks (this PR) — same severity as CDATA.
            validate_customization_plugin_ban(class_name, code)
            validate_gi_sql(class_name, code)
            validate_inunit_sql(class_name, code)
            validate_pxdb_has_sql(class_name, code, combined_cs_text)
            scan_security(class_name, code)
            validate_csharp(class_name, code, strict)
            validate_extension_safety(class_name, code, strict)
            validate_crm_dac_safety(class_name, code, strict)


def validate_customization_plugin_ban(class_name: str, code: str):
    """Check CustomizationPlugin for unsafe patterns.

    CustomizationPlugin is SAFE when:
    - Uses System.Configuration.ConfigurationManager (works in all contexts)
    - Has null check on connection string
    - Has try/catch around UpdateDatabase body
    - Only references own code (no ISV/vendor package imports)

    CustomizationPlugin is DANGEROUS when:
    - Uses System.Web.Configuration.WebConfigurationManager (null outside HTTP context)
    - Uses HttpContext.Current (null during cloud maintenance)
    - Missing null check on ConnectionStrings["ProjectX"]
    - No try/catch (unhandled exception kills app pool)

    The 2026-03-28 outage was caused by WebConfigurationManager, NOT by
    CustomizationPlugin itself. AesthetikWMS uses CustomizationPlugin with
    ConfigurationManager and has been stable in production.
    """
    # Strip comments to avoid false positives
    clean = re.sub(r"///.*$", "", code, flags=re.MULTILINE)
    clean = re.sub(r"//.*$", "", clean, flags=re.MULTILINE)
    clean = re.sub(r"/\*.*?\*/", "", clean, flags=re.DOTALL)

    if not re.search(r"class\s+\w+\s*:\s*CustomizationPlugin", clean):
        return  # Not a CustomizationPlugin — skip

    # HARD FAIL: WebConfigurationManager — crashes outside HTTP context
    if "WebConfigurationManager" in clean:
        error(
            f"{class_name}: BANNED — WebConfigurationManager in CustomizationPlugin.\n"
            f"         WebConfigurationManager depends on HTTP context which is absent during\n"
            f"         cloud maintenance app pool restarts. Use ConfigurationManager instead.\n"
            f"         Root cause of 2026-03-28 production outage (14+ hours)."
        )

    # HARD FAIL: HttpContext.Current — null during cloud maintenance
    if "HttpContext.Current" in clean:
        error(
            f"{class_name}: BANNED — HttpContext.Current in CustomizationPlugin.\n"
            f"         HttpContext is null during app pool init (cloud maintenance).\n"
            f"         Use ConfigurationManager.ConnectionStrings[\"ProjectX\"] instead."
        )

    # WARN: Missing null check on connection string
    if "ConfigurationManager" in clean and ".ConnectionString" in clean:
        if "== null" not in clean and "is null" not in clean:
            warn(
                f"{class_name}: CustomizationPlugin accesses .ConnectionString without null check.\n"
                f"         Add: if (cs == null) {{ WriteLog(...); return; }}"
            )

    # WARN: Missing try/catch
    if "UpdateDatabase" in clean and "catch" not in clean:
        warn(
            f"{class_name}: CustomizationPlugin.UpdateDatabase() has no try/catch.\n"
            f"         Unhandled exceptions in UpdateDatabase() kill the entire app pool.\n"
            f"         Wrap body in try/catch with WriteLog for error reporting."
        )

    # ── Destructive SQL guard ──────────────────────────────────────────
    # UpdateDatabase() must be additive and idempotent only.
    # ALTER TABLE ADD (with IF NOT EXISTS), INSERT (with idempotency check),
    # and CREATE TABLE (with IF NOT EXISTS) are safe.
    # DELETE, UPDATE, DROP, and TRUNCATE are destructive and cannot be
    # rolled back by redeploying the previous package.
    #
    # The 2026-03-29 P0 outage was caused by DELETE FROM INUnit.
    # Package rollback re-publishes old code but does NOT undo SQL changes.
    # Destructive data operations require a separate, manually-approved
    # migration project — never the CI/CD auto-publish pipeline.

    # Collapse C# string concatenation so SQL spanning multiple lines is
    # matched as a single string.  e.g.:
    #   "UPDATE InventoryItem " +
    #   "SET SalesUnit = BaseUnit "
    # becomes:
    #   "UPDATE InventoryItem SET SalesUnit = BaseUnit "
    sql_flat = re.sub(r'"\s*\+\s*\n\s*"', " ", clean)

    # Honor the `-- REVIEWED: inunit-sql-safe` marker across both checks
    # that cover INUnit destructive SQL. validate_inunit_sql already uses
    # this marker; without aligning here, a reviewed INUnit DELETE that
    # passes validate_inunit_sql falsely trips the generic destructive-
    # SQL guard below. Real precedent: AesthetikContainersInstall.cs has
    # the marker and a `DELETE u FROM INUnit u` alias-form statement —
    # which the regex below captures as a single-letter "table" (`u`)
    # because T-SQL's DELETE-JOIN form puts the alias first. The
    # alias-form detection skips only when the file carries the marker
    # AND INUnit appears in a small window around the match.
    #
    # Note: check against raw `code`, not `clean`. The marker may appear
    # inside a C# verbatim SQL string (@"-- REVIEWED: inunit-sql-safe\n
    # DELETE ...") which survives comment-stripping, OR as a C# line
    # comment (// -- REVIEWED: inunit-sql-safe) which `clean` removes.
    # validate_inunit_sql / validate_plugin_sql_column_refs both use
    # `code` for the same reason — keep this consistent.
    inunit_reviewed = INUNIT_SQL_REVIEW_MARKER in code

    def _looks_like_inunit_op(match_obj):
        """Match target is INUnit — either directly captured or via
        an alias in the DELETE-JOIN / UPDATE-FROM form where the
        captured token is a short lowercase alias and INUnit appears
        nearby in the statement. Window sized for multi-line verbatim
        SQL strings (T-SQL UPDATE-FROM puts FROM INUnit hundreds of
        chars past UPDATE u SET)."""
        tbl = match_obj.group(1)
        if tbl.lower() == "inunit":
            return True
        if len(tbl) <= 2 and tbl.islower():
            window = sql_flat[max(0, match_obj.start() - 50): match_obj.end() + 600]
            if re.search(r"\bINUnit\b", window, re.IGNORECASE):
                return True
        return False

    # HARD FAIL: DELETE FROM — destroys data that package rollback cannot restore
    # Exception: GI metadata tables and user preference tables are safe to DELETE
    # from during ISV cleanup — they contain UI state and inquiry definitions,
    # not business data. Rollback re-publishes the old package which doesn't
    # re-create ISV artifacts anyway.
    SAFE_DELETE_TABLES = {
        "GIDesign", "GITable", "GIRelation", "GIOn", "GIFilter",
        "GIWhere", "GIGroupBy", "GISort", "GIResult",
        "PivotFieldPreferences", "FilterPresets", "SiteMap",
    }
    # Per-DELETE exemption marker. When the SQL string contains a
    # `-- SAFE_DELETE_EXEMPT: <reason>` SQL comment within ~500 chars
    # preceding a DELETE, the author has explicitly justified the
    # delete and the ban is bypassed (with audit-trail warning).
    # Use case: cleaning corrupt metadata rows that would otherwise
    # poison Acumatica's MetadataProvider — e.g. the 2026-04-26 Path
    # 2 α residue in EntityMapping (validated empirically that <Sql>
    # blocks don't re-execute on merge=true publishes per Rule #24,
    # so plugin C# is the only path).
    # The marker survives C# comment stripping because it's a SQL
    # comment inside a string literal, not a C# comment.
    SAFE_DELETE_EXEMPT_PATTERN = re.compile(
        r"--\s*SAFE_DELETE_EXEMPT:\s*([^\r\n]+)", re.IGNORECASE
    )
    # Regex tightened to require literal FROM (with optional alias-form
    # word in between). Previously a degenerate match like "DELETE failed"
    # in a log string captured "failed" as the table — false positive.
    # Now both DELETE-FROM and DELETE-alias-FROM forms still match.
    for delete_match in re.finditer(
        r"\bDELETE\s+(?:\w+\s+)?FROM\s+(\w+)", sql_flat, re.IGNORECASE
    ):
        table = delete_match.group(1)
        if table in SAFE_DELETE_TABLES:
            continue
        if inunit_reviewed and _looks_like_inunit_op(delete_match):
            continue
        # Look 500 chars back for the per-DELETE exemption marker.
        window = sql_flat[max(0, delete_match.start() - 500): delete_match.start()]
        exempt_match = SAFE_DELETE_EXEMPT_PATTERN.search(window)
        if exempt_match:
            warn(
                f"{class_name}: DELETE FROM {table} authorized by SAFE_DELETE_EXEMPT marker.\n"
                f"         Reason: {exempt_match.group(1).strip()}"
            )
            continue
        error(
            f"{class_name}: BANNED — DELETE FROM {table} in CustomizationPlugin.\n"
            f"         UpdateDatabase() must be additive only. DELETE cannot be undone by\n"
            f"         package rollback — the old package's UpdateDatabase() doesn't know\n"
            f"         to re-INSERT the deleted rows.\n"
            f"         If this is a data migration, use a separate one-time project with\n"
            f"         a pre-tested rollback plan.\n"
            f"         If this DELETE is intentional and pre-vetted (e.g. cleaning corrupt\n"
            f"         Acumatica metadata that <Sql> blocks can't reach per Rule #24), add\n"
            f"         a SQL comment immediately preceding the DELETE inside the SQL string:\n"
            f"           -- SAFE_DELETE_EXEMPT: <one-line reason for audit trail>"
        )

    # HARD FAIL: UPDATE ... SET — mutates data that package rollback cannot restore
    # Exception: GI-design and SiteMap metadata tables — these are owned by the
    # customization (GIDesign rows are declared in project.xml's <GenericInquiryScreen>
    # blocks, SiteMap rows in <SiteMap> children, GITable rows + GISort rows in
    # <GITable> / <GISort> children of <GenericInquiryScreen>, etc.) and Acumatica
    # re-creates them from project.xml on every publish (or silent-skips per Rule #24,
    # in which case stale rows persist and require this recovery-surgery path).
    # UPDATEs on these tables are recovery surgery for stuck publish state:
    #   - GIDesign.PrimaryScreenIDNew = NULL after a malformed prior publish — per
    #     W4 AAR + Bolt V9 recovery, 2026-05-15.
    #   - GITable.Name carrying a stale namespace prefix after a DAC rename that
    #     Rule #24 silent-skipped from propagating — per Bolt V17 recovery, 2026-05-18.
    #   - GISort.DataFieldName carrying a phantom field name (e.g., 'Receipt.Date'
    #     when POReceipt has 'ReceiptDate', not 'Date') that PR #99 fixed on
    #     GIResult but missed on GISort — per Bolt V18 recovery, 2026-05-18.
    #     Rule #128 #6 (phantom DAC field) causes catalog walker to exclude the GI
    #     from /OData/$metadata. SOAP SM208000 can't fix a stuck-excluded GI; a
    #     plugin UPDATE is the only path. Adding GISort to the allowlist mirrors
    #     PR #109 (which added GITable for V17).
    SAFE_UPDATE_TABLES = {"SiteMap", "GIDesign", "GIWhere", "GIOn", "GITable", "GISort"}
    # Tables that pass the SAFE check but require the 2-cycle catalog-cache advisory.
    # Acumatica's OData GI catalog cache needs TWO publish-restart cycles to refresh
    # after GITable or GISort UPDATEs — a cycle-1 404 probe is NOT a fix failure.
    RULE_194_ADVISORY_TABLES = {"GITable", "GISort"}
    for update_match in re.finditer(r"\bUPDATE\s+(\w+)\s+SET\b", sql_flat, re.IGNORECASE):
        table = update_match.group(1)
        if table in SAFE_UPDATE_TABLES:
            if table in RULE_194_ADVISORY_TABLES:
                warn(
                    f"{class_name}: Rule #194 advisory — UPDATE {table} SET detected in CustomizationPlugin.\n"
                    f"         Acumatica's OData GI catalog cache needs TWO publish-restart cycles to refresh\n"
                    f"         after GITable/GISort UPDATEs. Cycle 1 commits the row state; cycle 2 triggers\n"
                    f"         the full catalog rebuild that re-reads the rows.\n"
                    f"\n"
                    f"         A cycle-1 probe of /OData/{{tenant}}/{{GI_Name}}?$top=1 may return HTTP 404 even\n"
                    f"         when the UPDATE landed correctly. That 404 is NOT a fix failure — it's\n"
                    f"         catalog-cache latency.\n"
                    f"\n"
                    f"         Diagnostic recipe:\n"
                    f"           1. Grep publishEnd log for [Bolt] <Method> CID=N: UPDATE affected N rows — COMMITTED\n"
                    f"              (proves the UPDATE actually ran)\n"
                    f"           2. Probe DAC OData: /t/<tenant>/api/odata/dac/{table}?$filter=DesignID eq <guid>\n"
                    f"              (proves the DB row state is correct)\n"
                    f"           3. If both confirm the UPDATE landed but $metadata still shows 404, trigger a\n"
                    f"              SECOND publish-restart via workflow_dispatch — NO code change needed.\n"
                    f"           4. Probe $metadata again after cycle 2's prod publish completes.\n"
                    f"\n"
                    f"         See CLAUDE.md Rule #194 + client-asthetik/acumatica/docs/runbooks/2026-05-18-2-cycle-catalog-cache-pattern.md."
                )
            continue
        if inunit_reviewed and _looks_like_inunit_op(update_match):
            continue
        error(
            f"{class_name}: BANNED — UPDATE {table} SET in CustomizationPlugin.\n"
            f"         UpdateDatabase() must be additive only. UPDATE cannot be undone by\n"
            f"         package rollback — the old package doesn't know the previous values.\n"
            f"         If this is a data migration, use a separate one-time project with\n"
            f"         a pre-tested rollback plan."
        )

    # HARD FAIL: DROP TABLE — destroys structure that package rollback cannot restore
    if re.search(r"\bDROP\s+TABLE\b", sql_flat, re.IGNORECASE):
        error(
            f"{class_name}: BANNED — DROP TABLE in CustomizationPlugin.\n"
            f"         UpdateDatabase() must be additive only. DROP TABLE destroys data\n"
            f"         and structure that cannot be restored by package rollback."
        )

    # HARD FAIL: TRUNCATE TABLE — destroys data that package rollback cannot restore
    if re.search(r"\bTRUNCATE\s+TABLE\b", sql_flat, re.IGNORECASE):
        error(
            f"{class_name}: BANNED — TRUNCATE TABLE in CustomizationPlugin.\n"
            f"         UpdateDatabase() must be additive only. TRUNCATE destroys all rows\n"
            f"         and cannot be restored by package rollback."
        )


def validate_pxdb_has_sql(class_name: str, code: str, all_sql_text: str):
    """Check [PXDB*] fields on PXCacheExtension DACs.

    HARD FAIL only for BANNED_PXDB_DACS (Vendor → phantom EPEmployee_Vendor table).
    For all other DACs, [PXDB*] attributes auto-create columns during publish on
    existing tables, so missing <Sql> is a WARNING not an error.

    Note: <Sql> elements are silently ignored during Customization API import.
    CustomizationPlugin with ConfigurationManager is the correct DDL path for
    new tables. [PXDB*] handles column creation on existing tables automatically.
    """
    # Strip comments
    clean = re.sub(r"///.*$", "", code, flags=re.MULTILINE)
    clean = re.sub(r"//.*$", "", clean, flags=re.MULTILINE)
    clean = re.sub(r"/\*.*?\*/", "", clean, flags=re.DOTALL)

    # Find PXCacheExtension declarations
    ext_matches = re.finditer(r"class\s+(\w+)\s*:\s*PXCacheExtension<(\w+)>", clean)
    for m in ext_matches:
        m.group(1)
        base_dac = m.group(2)

        # Extract the class body (rough — find matching braces)
        start = m.end()
        brace_count = 0
        class_body = ""
        for i, ch in enumerate(clean[start:], start):
            if ch == "{":
                brace_count += 1
            elif ch == "}":
                brace_count -= 1
                if brace_count == 0:
                    class_body = clean[start:i + 1]
                    break

        # HARD FAIL: [PXDB*] on Vendor extensions is always fatal.
        # Vendor DAC generates phantom EPEmployee_Vendor SQL references
        # that don't map to any real table. No ALTER TABLE can fix it.
        # Confirmed by Acumatica Cloud Support 2026-03-28.
        BANNED_PXDB_DACS = {"Vendor"}
        if base_dac in BANNED_PXDB_DACS:
            any_pxdb = re.search(
                r"\[(PXDBInt|PXDBString|PXDBDecimal|PXDBBool|PXDBDate|PXDBDouble|PXDBFloat|PXDBLong|PXDBShort|PXDBByte|PXDBGuid)",
                class_body,
            )
            if any_pxdb:
                error(
                    f"{class_name}: [PXDB*] field on PXCacheExtension<{base_dac}> is BANNED.\n"
                    f"         {base_dac} DAC generates phantom SQL table references (EPEmployee_Vendor)\n"
                    f"         that don't exist. No ALTER TABLE can fix this.\n"
                    f"         Caused 14+ hour production outage on 2026-03-28.\n"
                    f"         Fix: Use ONLY non-persisted attributes ([PXInt], [PXString], etc.)."
                )
                continue  # Skip per-field SQL check — entire extension is invalid

        # Find all [PXDB*] fields in this extension
        pxdb_fields = re.findall(
            r"\[(PXDBInt|PXDBString|PXDBDecimal|PXDBBool|PXDBDate|PXDBDouble|PXDBFloat|PXDBLong|PXDBShort|PXDBByte|PXDBGuid)"
            r"[^\]]*\]"
            r".*?"
            r"public\s+\w+\??\s+(Usr\w+)\s*\{",
            class_body,
            re.DOTALL,
        )

        for attr_type, field_name in pxdb_fields:
            # [PXDB*] attributes auto-create columns on existing tables during publish.
            # Missing <Sql> is informational — the columns WILL be created.
            # Only warn so developers know to verify after publish.
            if field_name not in all_sql_text:
                warn(
                    f"{class_name}: [{attr_type}] field '{field_name}' on PXCacheExtension<{base_dac}> "
                    f"— no explicit <Sql> ALTER TABLE (columns auto-created by [PXDB*] during publish)"
                )


def scan_security(class_name: str, code: str):
    """Scan C# CDATA for hardcoded credentials and sensitive values.

    Restored from AcuOps v1.0 (commit 435ce43). The Heritage port in #1
    accidentally dropped the security scan; tests still assert it so this
    function is re-introduced verbatim (plus "Hardcoded" in each message
    so the existing test assertions match).

    Every match is a HARD error — hardcoded passwords/keys/connection
    strings in customization code are a real exfiltration risk and are
    trivially detectable in `project.xml` exports.
    """
    sensitive_patterns = [
        (r'[Pp]assword\s*=\s*"[^"]+"', "Hardcoded password detected"),
        (r'[Cc]onnection[Ss]tring\s*=\s*"[^"]+"', "Hardcoded connection string detected"),
        (r'[Aa]pi[Kk]ey\s*=\s*"[^"]+"', "Hardcoded API key detected"),
        (r'[Ss]ecret\s*=\s*"[^"]+"', "Hardcoded secret detected"),
        (r'[Tt]oken\s*=\s*"[A-Za-z0-9+/=]{20,}"', "Possible hardcoded token detected"),
    ]

    for pattern, message in sensitive_patterns:
        if re.search(pattern, code):
            error(f"{class_name}: SECURITY — {message}")


def detect_destructive_sql(root):
    """Scan <Sql> and <SqlScript> elements for destructive operations.

    Restored from AcuOps v1.0 (commit 435ce43). The Heritage port in #1
    dropped this function but the tests still assert it — and the
    2026-03-29 P0 outage (DELETE FROM INUnit) is a reminder that
    destructive-SQL heuristics are load-bearing, not decorative.

    This is a warning-only check: DROP/TRUNCATE/DELETE are not always
    wrong (e.g. idempotent cleanup with WHERE guards), but they should
    always surface in review. Hard bans for specific tables live in
    validate_customization_plugin_ban, validate_inunit_sql, and
    validate_gi_sql.
    """
    for elem in root.findall(".//Sql") + root.findall(".//SqlScript"):
        name = elem.get("Name", "(unnamed)")
        cdata = elem.find("CDATA")
        if cdata is None:
            continue
        sql_text = (cdata.text or "").upper()
        destructive_ops = ["DROP TABLE", "DROP COLUMN", "TRUNCATE TABLE", "DELETE FROM"]
        for op in destructive_ops:
            if op in sql_text:
                warn(
                    f'<Sql/SqlScript Name="{name}"> contains destructive operation: {op}. '
                    f"Ensure this is intentional."
                )


def validate_csharp(class_name: str, code: str, strict: bool):
    """Basic C# code validation for CDATA blocks."""

    # Check for balanced braces
    open_count = code.count("{")
    close_count = code.count("}")
    if open_count != close_count:
        error(
            f"{class_name}: Unbalanced braces — {open_count} open, {close_count} close"
        )

    # Check for namespace
    if "namespace " not in code:
        warn(f"{class_name}: No namespace declaration found")

    # Check for IsActive method (required for extensions)
    if "PXCacheExtension" in code or "PXGraphExtension" in code:
        if "IsActive" not in code:
            error(f"{class_name}: Extension class missing IsActive() method")

    # Check for known problematic types (skip comments)
    code_no_comments = re.sub(r"///.*$", "", code, flags=re.MULTILINE)  # strip /// doc comments
    code_no_comments = re.sub(r"//.*$", "", code_no_comments, flags=re.MULTILINE)  # strip // comments
    code_no_comments = re.sub(r"/\*.*?\*/", "", code_no_comments, flags=re.DOTALL)  # strip /* */ blocks
    problematic_types = {
        "ARCustomerClass": "Not a public type in v24.2 (CS0246). Use PX.Objects.AR.CustomerClass",
    }
    for bad_type, fix in problematic_types.items():
        if bad_type in code_no_comments:
            error(f"{class_name}: References '{bad_type}' — {fix}")

    # Check custom field naming convention
    field_pattern = re.findall(r"public\s+\w+\??\s+(Usr\w+)\s*\{", code)
    for field in field_pattern:
        if not field.startswith("Usr"):
            warn(f"{class_name}: Field '{field}' should start with 'Usr' prefix")

    # Check BQL field naming (should be lowercase first letter)
    bql_pattern = re.findall(r"public\s+abstract\s+class\s+(\w+)\s*:", code)
    for bql_class in bql_pattern:
        if bql_class[0].isupper() and bql_class.startswith("Usr"):
            warn(
                f"{class_name}: BQL field class '{bql_class}' should start lowercase "
                f"(e.g., 'usr{bql_class[3:]}')"
            )

    # CRITICAL: Detect Base.Transactions.Insert/Update inside RowUpdated/RowInserted handlers
    # This desyncs SOOrder.openLineCntr and other PXDBCount aggregates.
    # Caused "data corruption state detected" production incident 2026-03-28.
    # Safe alternative: use Persist() override for batch child row manipulation.
    code_no_comments = re.sub(r"///.*$", "", code, flags=re.MULTILINE)
    code_no_comments = re.sub(r"//.*$", "", code_no_comments, flags=re.MULTILINE)
    code_no_comments = re.sub(r"/\*.*?\*/", "", code_no_comments, flags=re.DOTALL)

    # Find RowUpdated/RowInserted handler bodies
    for event_match in re.finditer(
        r"(Events\.Row(?:Updated|Inserted)<(\w+)>.*?\{)",
        code_no_comments,
        re.DOTALL,
    ):
        event_type = "RowUpdated" if "Updated" in event_match.group(1) else "RowInserted"
        dac_name = event_match.group(2)
        # Extract the handler body (rough — find matching braces)
        start = event_match.end()
        brace_count = 1
        handler_body = ""
        for i, ch in enumerate(code_no_comments[start:], start):
            if ch == "{":
                brace_count += 1
            elif ch == "}":
                brace_count -= 1
                if brace_count == 0:
                    handler_body = code_no_comments[start:i]
                    break

        if not handler_body:
            continue

        # Check for dangerous patterns inside the handler
        if "Base.Transactions.Insert" in handler_body or "Transactions.Insert(new" in handler_body:
            error(
                f"{class_name}: Base.Transactions.Insert() inside {event_type}<{dac_name}> handler.\n"
                f"         Inserting child rows inside row events desyncs PXDBCount aggregates\n"
                f"         (openLineCntr, lineCntr). Caused 'data corruption state detected' 2026-03-28.\n"
                f"         Fix: Move row insertion to Persist() override or PXAction."
            )

        if re.search(r"Base\.Transactions\.(?:Cache\.)?Update\(", handler_body):
            warn(
                f"{class_name}: Base.Transactions.Update() inside {event_type}<{dac_name}> handler.\n"
                f"         Calling Update on the view inside a row event causes re-entrant event loops\n"
                f"         and can desync aggregate counters. Use e.Cache.SetValue() instead,\n"
                f"         or move logic to Persist() override."
            )

    if strict:
        # Check for PXUIField on all PXDBx fields
        pxdb_fields = re.findall(r"\[PXDB\w+[^\]]*\]\s*\n\s*(?!\[PXUIField)", code)
        if pxdb_fields:
            warn(f"{class_name}: Some [PXDB*] fields may be missing [PXUIField] attribute")


def validate_extension_safety(class_name: str, code: str, strict: bool):
    """Detect unsafe extension patterns that compile but crash at runtime.

    These patterns cause NullReferenceException or InvalidCastException on
    inquiry result DACs and foreign-graph records where extension collections
    may not be initialized.
    """

    # Strip comments to avoid false positives
    clean = re.sub(r"///.*$", "", code, flags=re.MULTILINE)
    clean = re.sub(r"//.*$", "", clean, flags=re.MULTILINE)
    clean = re.sub(r"/\*.*?\*/", "", clean, flags=re.DOTALL)

    # Rule 1: e.Row.GetExtension<T>() in inquiry/projection graph extensions
    # HIGH risk — crashes on inquiry result DACs (InventoryAllocDetEnqResult, etc.)
    # Safe alternative: e.Cache.GetValue(e.Row, "FieldName")
    # Only flag in inquiry graphs (*Enq*) where DAC rows are projections.
    # In normal entry graphs (POOrderEntry, etc.), e.Row is the real DAC and this is safe.
    is_inquiry_graph = bool(re.search(r"PXGraphExtension<\w*Enq\w*>", clean))
    row_ext_matches = re.findall(r"e\.Row\.GetExtension<(\w+)>\(\)", clean)
    for match in row_ext_matches:
        if is_inquiry_graph:
            msg = (
                f"{class_name}: e.Row.GetExtension<{match}>() in inquiry extension — HIGH RISK\n"
                f"         Crashes on inquiry/projection DACs. Use:\n"
                f"         e.Cache.GetValue(e.Row, \"FieldName\") / e.Cache.SetValue(...)"
            )
            if strict:
                error(msg)
            else:
                warn(msg)
        else:
            # In normal graphs, instance GetExtension on e.Row is generally safe
            # but still worth a note in strict mode
            if strict:
                warn(
                    f"{class_name}: e.Row.GetExtension<{match}>() — consider using\n"
                    f"         e.Cache.GetValue/SetValue for defensive coding"
                )

    # Rule 2: Instance .GetExtension<T>() on PXSelect results (not via PXCache<T>)
    # MEDIUM risk — unsafe on records from foreign graphs
    # Safe alternative: PXCache<Entity>.GetExtension<Ext>(record)
    # Find all .GetExtension<T>() calls, then exclude safe patterns
    for m in re.finditer(r"\.GetExtension<(\w+)>\(\)", clean):
        ext_type = m.group(1)
        # Get context before the match to check if it's a safe pattern
        prefix = clean[:m.start()]
        # Skip if already caught by Rule 1 (e.Row.GetExtension)
        if prefix.rstrip().endswith("e.Row"):
            continue
        # Skip if it's the safe static form: PXCache<T>.GetExtension
        if re.search(r"PXCache<\w+>\s*$", prefix):
            continue
        # Skip if the reviewer has signed off on this specific call site
        # with `// REVIEWED: extension-safe` on the same line or the line
        # immediately above. Line-local, not file-wide — each site carries
        # its own audit signature.
        if _has_extension_safe_review_marker(code, clean, m.start()):
            continue
        msg = (
            f"{class_name}: Instance .GetExtension<{ext_type}>() — MEDIUM RISK\n"
            f"         Use static PXCache<Entity>.GetExtension<{ext_type}>(record) instead.\n"
            f"         If reviewed and intentional, add: {EXTENSION_SAFE_REVIEW_MARKER}"
        )
        if strict and is_inquiry_graph:
            error(msg)
        else:
            warn(msg)

    # Rule 3: Inquiry graph extension with RowSelected but no try-catch
    # HIGH risk — inquiry DACs are most fragile for extension failures
    is_inquiry_ext = bool(re.search(r"PXGraphExtension<\w*Enq\w*>", clean))
    has_row_selected = bool(re.search(r"RowSelected", clean))
    has_catch = "catch" in clean
    if is_inquiry_ext and has_row_selected and not has_catch:
        msg = (
            f"{class_name}: Inquiry graph extension with RowSelected but no try-catch\n"
            f"         Inquiry result DACs are projection types — extension access is fragile.\n"
            f"         Wrap handler body in try-catch to prevent screen crashes."
        )
        if strict:
            error(msg)
        else:
            warn(msg)


def validate_crm_dac_safety(class_name: str, code: str, strict: bool):
    """Detect CRM DAC usage on non-CRM graphs.

    CRM DACs (CRRelation, CRPMTimeActivity, CRActivity, PMTimeActivity) have
    [PXSelector] field attributes that reference CRM views. When these DACs are
    used in PXSelect views on non-CRM graphs (POOrderEntry, INReceiptEntry, etc.),
    the graph crashes at runtime even though it compiles successfully.

    CI/CD smoke tests may pass (HTTP 200 on entity query) but the screen itself
    will fail with "The view doesn't exist" when opened in the browser.
    """

    # Strip comments
    clean = re.sub(r"///.*$", "", code, flags=re.MULTILINE)
    clean = re.sub(r"//.*$", "", clean, flags=re.MULTILINE)
    clean = re.sub(r"/\*.*?\*/", "", clean, flags=re.DOTALL)

    # CRM DACs that are incompatible with non-CRM graphs
    crm_dacs = {
        "CRRelation": "CRM Relations DAC — has [PXSelector] on EntityID/ContactID referencing CRM views",
        "CRPMTimeActivity": "CRM Activities projection — joins PMTimeActivity + CRActivity (both CRM-dependent)",
        "CRActivity": "CRM Activity DAC — field attributes reference CRM-only views",
        "PMTimeActivity": "PM Time Activity DAC — field attributes reference CRM-only views",
        "CRRelationsList": "Removed in Acumatica 2022 R2 — type does not exist in 24.2",
        "CRActivityList": "Removed in Acumatica 24.2 — type does not exist",
    }

    # Non-CRM graphs where CRM DACs will crash
    non_crm_graphs = [
        "POOrderEntry", "POReceiptEntry", "INReceiptEntry",
        "APInvoiceEntry", "APPaymentEntry", "INTransferEntry",
        "INIssueEntry", "INAdjustmentEntry",
    ]

    # Detect which graph this extension targets
    graph_match = re.search(r"PXGraphExtension<(\w+)>", clean)
    if not graph_match:
        return  # Not a graph extension — skip

    target_graph = graph_match.group(1)
    is_non_crm = target_graph in non_crm_graphs

    # Check for CRM DAC usage
    for dac, reason in crm_dacs.items():
        # Match usage in PXSelect, PXSelectBase, field declarations, etc.
        # But skip if it's just in a comment or string
        pattern = rf"\b{re.escape(dac)}\b"
        if re.search(pattern, clean):
            if is_non_crm:
                msg = (
                    f"{class_name}: Uses '{dac}' on non-CRM graph '{target_graph}' — WILL CRASH AT RUNTIME\n"
                    f"         {reason}\n"
                    f"         Solution: Create custom DACs (e.g., UsrPORelation) with custom tables.\n"
                    f"         See lessons-learned.md: 'CRM DACs Are Fundamentally Incompatible with Non-CRM Graphs'"
                )
                error(msg)
            else:
                # On CRM graphs it's fine, but note it
                if strict:
                    warn(
                        f"{class_name}: Uses CRM DAC '{dac}' — ensure target graph has CRM infrastructure"
                    )

    # Also detect CRRelationDetailsExt on non-CRM graphs
    cr_ext_match = re.search(r"CRRelationDetailsExt<(\w+)", clean)
    if cr_ext_match:
        ext_target = cr_ext_match.group(1)
        if ext_target in non_crm_graphs:
            error(
                f"{class_name}: CRRelationDetailsExt<{ext_target}> — WILL CRASH AT RUNTIME\n"
                f"         CRRelationDetailsExt requires CRM infrastructure (contact/address views).\n"
                f"         Non-CRM graph '{ext_target}' does not provide these views.\n"
                f"         Solution: Use custom DACs with custom tables instead."
            )


def main():
    strict = "--strict" in sys.argv
    no_semantic = "--no-semantic" in sys.argv
    dll_source_only = "--dll-source-only" in sys.argv

    # Parse --isv-prefix <value>
    isv_prefix = ""
    argv_no_flags = []
    i = 1
    while i < len(sys.argv):
        arg = sys.argv[i]
        if arg == "--isv-prefix":
            if i + 1 >= len(sys.argv):
                print("Error: --isv-prefix requires a value (e.g. --isv-prefix AO)", file=sys.stderr)
                sys.exit(2)
            isv_prefix = sys.argv[i + 1]
            i += 2
            continue
        if not arg.startswith("--"):
            argv_no_flags.append(arg)
        i += 1
    args = argv_no_flags

    if not args:
        print("Usage: acumatica-lint [--strict] [--no-semantic] [--isv-prefix PREFIX] [--dll-source-only] <project.xml>")
        print()
        print("Validates Acumatica customization project XML format.")
        print("  --strict           Enable additional warnings for best practices")
        print("  --no-semantic      Skip semantic cross-reference checks")
        print("  --isv-prefix NAME  Enforce ISV prefix on Graph ClassNames (e.g. AO)")
        print("  --dll-source-only  Run ONLY the DLL-source plugin checks")
        print("                     (debug aid — skips XML/Graph/semantic checks)")
        sys.exit(1)

    path = args[0]

    # --dll-source-only: isolate the DLL-source plugin checks (see
    # AAR-2026-04-17). Debug aid; skips XML/Graph/semantic checks for a
    # fast, focused run against src/{DllName}/**/*.cs.
    if dll_source_only:
        print(f"Scanning DLL sources for: {path}")
        print("=" * 60)
        validate_dll_source_references(path, strict=strict)
        print("=" * 60)
        if errors:
            print(f"{RED}FAILED — {len(errors)} error(s), {len(warnings)} warning(s){RESET}")
            sys.exit(1)
        if warnings:
            print(f"{YELLOW}PASSED with {len(warnings)} warning(s){RESET}")
        else:
            print(f"{GREEN}PASSED — no issues found{RESET}")
        sys.exit(0)

    print(f"Validating: {path}")
    if isv_prefix:
        print(f"ISV Prefix: {isv_prefix}")
    print("=" * 60)

    success = validate(path, strict, no_semantic=no_semantic, isv_prefix=isv_prefix)

    # Destructive SQL is a warning-only scan — run it separately so it
    # surfaces on every validate run regardless of hard-fail state.
    try:
        tree = ET.parse(path)
        detect_destructive_sql(tree.getroot())
    except ET.ParseError:
        pass  # Already reported above.

    print("=" * 60)
    if success:
        if warnings:
            print(f"{YELLOW}PASSED with {len(warnings)} warning(s){RESET}")
        else:
            print(f"{GREEN}PASSED — no issues found{RESET}")
        sys.exit(0)
    else:
        print(f"{RED}FAILED — {len(errors)} error(s), {len(warnings)} warning(s){RESET}")
        sys.exit(1)


if __name__ == "__main__":
    main()
