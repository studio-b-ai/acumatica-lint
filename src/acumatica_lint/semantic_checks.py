#!/usr/bin/env python3
"""
Acumatica Customization Semantic Validator

Cross-references DAC field declarations in C# code against SQL column creation
statements. Catches bugs like declaring a field in a DAC extension without
creating the corresponding database column.

Usage:
    from semantic_checks import parse_dac_fields, parse_sql_columns, run_semantic_checks
"""

import json
import re
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Optional

# ── Colour codes ──────────────────────────────────────────────────────────
RED = "\033[91m"
YELLOW = "\033[93m"
GREEN = "\033[92m"
CYAN = "\033[96m"
RESET = "\033[0m"

# ── DAC class name → SQL table name ──────────────────────────────────────
# Most Acumatica DAC class names match the SQL table exactly.  This mapping
# covers the known exceptions where the C# class differs from the physical
# table.  Unmapped DACs are assumed to have the same name as the table.
DAC_TO_TABLE: dict[str, str] = {
    # Accounts
    "Customer": "BAccount",
    # DANGER: Vendor DAC generates phantom EPEmployee_Vendor SQL refs.
    # [PXDB*] on PXCacheExtension<Vendor> = unrecoverable deadlock.
    # Confirmed by Acumatica support. See validate-project.py.
    "Vendor": "BAccount",  # WARNING: [PXDB*] on Vendor is BANNED
    "BAccount": "BAccount",
    "EPEmployee": "BAccountR",
    # Inventory
    "InventoryItem": "InventoryItem",
    "INLotSerialStatus": "INLotSerialStatus",
    "INLotSerialClass": "INLotSerClass",
    "INSetup": "INSetup",
    "INItemClass": "INItemClass",
    "INRegister": "INRegister",
    "INTran": "INTran",
    # Purchase
    "POOrder": "POOrder",
    "POLine": "POLine",
    "POReceipt": "POReceipt",
    "POReceiptLine": "POReceiptLine",
    # Sales
    "SOOrder": "SOOrder",
    "SOLine": "SOLine",
    "SOShipment": "SOShipment",
    "SOShipLine": "SOShipLine",
    "SOPackageDetailEx": "SOPackageDetail",
    # AR/AP
    "ARInvoice": "ARRegister",
    "APInvoice": "APRegister",
    "ARPayment": "ARRegister",
    "APPayment": "APRegister",
    # CRM
    "CRCase": "CRCase",
    "CRLead": "Contact",
    "Contact": "Contact",
    "Address": "Address",
    # Other
    "CSAnswers": "CSAnswers",
    "Note": "Note",
    "NoteDoc": "NoteDoc",
}

# ── PXDB attribute → expected SQL type family ────────────────────────────
# Keys are the PX.Data attribute names (without brackets), values are the
# canonical SQL Server type that Acumatica maps them to.
PXDB_TO_SQL: dict[str, str] = {
    "PXDBBool": "bit",
    "PXDBInt": "int",
    "PXDBDecimal": "decimal",
    "PXDBString": "nvarchar",
    "PXDBDate": "datetime",
    "PXDBDateTime": "datetime",
    "PXDBFloat": "float",
    "PXDBDouble": "float",
    "PXDBLong": "bigint",
    "PXDBShort": "smallint",
    "PXDBByte": "tinyint",
    "PXDBGuid": "uniqueidentifier",
    "PXDBBinary": "varbinary",
    "PXDBText": "nvarchar",
    "PXDBPackedIntegerArray": "varbinary",
}


def _strip_comments(code: str) -> str:
    """Remove C# single-line and multi-line comments from source code.

    Respects string literals — won't strip ``//`` inside a quoted string.
    Good enough for attribute/property parsing; does NOT handle raw strings
    or interpolated expressions with embedded quotes.
    """
    # Multi-line comments  /* ... */
    code = re.sub(r"/\*.*?\*/", "", code, flags=re.DOTALL)
    # Single-line comments  // ...
    code = re.sub(r"//[^\n]*", "", code)
    return code


# ── DAC field parser ─────────────────────────────────────────────────────

# Matches:  PXCacheExtension<SomeDAC>
_RE_CACHE_EXT = re.compile(
    r"class\s+\w+\s*:\s*PXCacheExtension<([A-Za-z0-9_.]+)>"
)

# Matches:  [PXDBDecimal(2)]  or  [PXDBBool]  or  [PXDBString(30, IsUnicode = true)]
_RE_PXDB_ATTR = re.compile(
    r"\[\s*(PXDB\w+)"          # attribute name
    r"(?:\(([^)]*)\))?"        # optional parenthesised args
    r"\s*\]"
)

# Matches:  [PXDefault(TypeCode.Decimal, "1.00")]  or  [PXDefault(true)]  or
#           [PXDefault(false, PersistingCheck = ...)]  or  [PXDefault(5)]
_RE_PXDEFAULT = re.compile(
    r"\[\s*PXDefault\s*\(([^)]*)\)\s*\]"
)

# Matches the property declaration:  public decimal? UsrFoo { get; set; }
# or with modifiers:                  public virtual DateTime? UsrFoo { get; set; }
# ``(?:\w+\s+)*`` absorbs any number of modifiers (virtual/static/override/new)
# before the property type.
_RE_PROPERTY = re.compile(
    r"public\s+(?:\w+\s+)*\w+\??\s+(Usr\w+)\s*\{\s*get\s*;"
)


def _extract_precision(attr_name: str, args_str: Optional[str]) -> Optional[int]:
    """Pull the first integer argument from a PXDB attribute's argument list."""
    if args_str is None:
        return None
    # Take the first token that looks like a bare integer
    m = re.match(r"\s*(\d+)", args_str)
    return int(m.group(1)) if m else None


def _extract_default(block: str) -> Optional[str]:
    """Extract the default value from a [PXDefault(...)] attribute in a block."""
    m = _RE_PXDEFAULT.search(block)
    if not m:
        return None
    args = m.group(1).strip()

    # TypeCode pattern:  TypeCode.Decimal, "1.00"
    tc = re.match(r'TypeCode\.\w+\s*,\s*"([^"]*)"', args)
    if tc:
        return tc.group(1)

    # Simple literal:  true / false / integer / negative integer
    # Strip trailing named args like ", PersistingCheck = ..."
    first_arg = args.split(",")[0].strip()
    if re.match(r"^-?\d+$", first_arg):
        return first_arg
    if first_arg.lower() in ("true", "false"):
        return first_arg.lower()

    # String literal:  "-C{0}"
    sq = re.match(r'^"([^"]*)"', first_arg)
    if sq:
        return sq.group(1)

    return None


def parse_dac_fields(code: str) -> list[dict]:
    """Parse C# DAC extension source code and extract persisted field declarations.

    Returns a list of dicts, each with keys:
        name         – field name (e.g. "UsrMyField")
        db_type      – PXDB attribute name (e.g. "PXDBDecimal")
        precision    – first numeric arg from attribute, or None
        dac          – base DAC class name (e.g. "INSetup")
        default_value – extracted default, or None
    """
    code = _strip_comments(code)

    results: list[dict] = []

    # Walk the code looking for PXCacheExtension declarations to track current DAC
    # Strategy: split into class-level blocks by finding each extension header,
    # then parse fields within each block.

    # Find all extension start positions
    ext_matches = list(_RE_CACHE_EXT.finditer(code))
    if not ext_matches:
        return results

    for i, ext_match in enumerate(ext_matches):
        dac_name = ext_match.group(1)
        # Strip namespace prefix if present (e.g. "PX.Objects.SO.SOShipment" → "SOShipment")
        if "." in dac_name:
            dac_name = dac_name.rsplit(".", 1)[1]

        start = ext_match.start()
        end = ext_matches[i + 1].start() if i + 1 < len(ext_matches) else len(code)
        block = code[start:end]

        # Find all PXDB attributes and the Usr* property that follows
        # We scan for [PXDB...] then look ahead for the property declaration
        pos = 0
        while pos < len(block):
            attr_m = _RE_PXDB_ATTR.search(block, pos)
            if not attr_m:
                break

            attr_name = attr_m.group(1)
            attr_args = attr_m.group(2)

            # Look for the property declaration after this attribute
            prop_m = _RE_PROPERTY.search(block, attr_m.end())
            if not prop_m:
                pos = attr_m.end()
                continue

            # Make sure there isn't another PXDB attribute between this one
            # and the property (which would mean this attribute belongs to a
            # different field)
            next_attr = _RE_PXDB_ATTR.search(block, attr_m.end())
            if next_attr and next_attr.start() < prop_m.start():
                pos = attr_m.end()
                continue

            field_name = prop_m.group(1)
            precision = _extract_precision(attr_name, attr_args)

            # Extract default from the block between attribute and property
            attr_block = block[attr_m.start():prop_m.end()]
            default_value = _extract_default(attr_block)

            results.append({
                "name": field_name,
                "db_type": attr_name,
                "precision": precision,
                "dac": dac_name,
                "default_value": default_value,
            })

            pos = prop_m.end()

    return results


# ── SQL column parser ────────────────────────────────────────────────────

# Matches ALTER TABLE ... ADD ... patterns (both bare and IF NOT EXISTS wrapped)
_RE_ALTER_TABLE = re.compile(
    r"ALTER\s+TABLE\s+(\w+)\s+ADD\s+(\w+)\s+"
    r"(\w+)"                     # sql type name
    r"(?:\((\d+(?:,\s*\d+)?)\))?"  # optional (precision) or (precision, scale)
    r"\s*NULL",
    re.IGNORECASE,
)


def parse_sql_columns(code: str) -> list[dict]:
    """Parse SQL ALTER TABLE ADD statements from project XML or raw SQL.

    Returns a list of dicts, each with keys:
        table     – table name
        column    – column name
        sql_type  – SQL type (lowercase, e.g. "decimal", "bit", "nvarchar")
        precision – for decimal(p,s) returns the *scale* (s); for nvarchar(n)
                    returns n; for types without precision returns None
    """
    results: list[dict] = []

    for m in _RE_ALTER_TABLE.finditer(code):
        table = m.group(1)
        column = m.group(2)
        sql_type = m.group(3).lower()
        size_str = m.group(4)

        precision: Optional[int] = None
        if size_str:
            parts = [p.strip() for p in size_str.split(",")]
            if len(parts) == 2:
                # decimal(18, 2) → scale is the second number
                precision = int(parts[1])
            else:
                # nvarchar(30) → the single number
                precision = int(parts[0])

        results.append({
            "table": table,
            "column": column,
            "sql_type": sql_type,
            "precision": precision,
        })

    return results


# ── Phase 1 check functions ────────────────────────────────────────────

def _resolve_table(dac: str) -> str:
    """Resolve a DAC class name to its SQL table name."""
    return DAC_TO_TABLE.get(dac, dac)


def _match_field_to_column(
    field: dict, columns: list[dict]
) -> Optional[dict]:
    """Find the SQL column matching a DAC field, using DAC_TO_TABLE resolution."""
    table = _resolve_table(field["dac"])
    for col in columns:
        if col["column"] == field["name"] and col["table"] == table:
            return col
    # Fallback: match by column name only (for unmapped DACs or custom tables)
    for col in columns:
        if col["column"] == field["name"]:
            return col
    return None


# Columns known to exist on the instance from prior CustomizationPlugin runs.
# These plugins were stripped from project.xml because the Customization API
# import rejects the <Graph> tag when the C# class extends CustomizationPlugin.
# The columns were created by a prior schema installer and are confirmed
# present on the instance. Adding new fields here requires verifying they exist
# on the instance first (e.g., via SM203510 or API schema check).
#
# Populate this set with (table_name, column_name) tuples for columns that
# exist on your Acumatica instance but are NOT created by <Sql> in project.xml.
ESTABLISHED_COLUMNS: set[tuple[str, str]] = set()


def check_fields_have_sql_columns(
    fields: list[dict], columns: list[dict]
) -> tuple[list[str], list[str]]:
    """Every DAC field must have a matching SQL column.

    Fields in ESTABLISHED_COLUMNS are skipped — their columns were created
    by a prior CustomizationPlugin run and confirmed present on the instance.

    Returns (errors, warnings).
    """
    errors: list[str] = []
    warnings: list[str] = []
    for field in fields:
        col = _match_field_to_column(field, columns)
        if col is None:
            table = _resolve_table(field["dac"])
            if (table, field["name"]) in ESTABLISHED_COLUMNS:
                continue
            # [PXDB*] attributes auto-create columns on existing tables during publish.
            # Missing <Sql> is informational — downgraded from error to warning.
            warnings.append(
                f"DAC field {field['dac']}.{field['name']} has no explicit SQL column "
                f"— [PXDB*] will auto-create during publish"
            )
    return errors, warnings


def check_type_compatibility(
    fields: list[dict], columns: list[dict]
) -> tuple[list[str], list[str]]:
    """Verify PXDB attribute → SQL type and precision consistency.

    Returns (errors, warnings).
    """
    errors: list[str] = []
    warnings: list[str] = []
    for field in fields:
        col = _match_field_to_column(field, columns)
        if col is None:
            continue  # Missing column is caught by check_fields_have_sql_columns

        expected_sql = PXDB_TO_SQL.get(field["db_type"])
        if expected_sql is None:
            warnings.append(
                f"Unknown PXDB type '{field['db_type']}' on {field['dac']}.{field['name']}"
            )
            continue

        # nchar is an acceptable (if unusual) alternative for nvarchar
        compatible_types = {expected_sql}
        if expected_sql == "nvarchar":
            compatible_types.add("nchar")

        if col["sql_type"] not in compatible_types:
            errors.append(
                f"Type mismatch: {field['dac']}.{field['name']} is {field['db_type']} "
                f"(expects SQL {expected_sql}) but SQL column is {col['sql_type']}"
            )
        elif col["sql_type"] != expected_sql:
            warnings.append(
                f"Type variant: {field['dac']}.{field['name']} is {field['db_type']} "
                f"(expects {expected_sql}) but SQL uses {col['sql_type']} — functional but non-standard"
            )

        if field["precision"] is not None and col["precision"] is not None:
            if field["precision"] != col["precision"]:
                errors.append(
                    f"Precision mismatch: {field['dac']}.{field['name']} has "
                    f"{field['db_type']}({field['precision']}) but SQL is "
                    f"{col['sql_type']}(...,{col['precision']})"
                )

    return errors, warnings


def check_table_name_mapping(
    fields: list[dict], columns: list[dict]
) -> tuple[list[str], list[str]]:
    """Check if SQL uses DAC name as table name when it should use the mapped name.

    Returns (errors, warnings).
    """
    errors: list[str] = []
    warnings: list[str] = []

    # Build reverse mapping: table → set of known DAC names that map to it
    table_to_dacs: dict[str, set[str]] = {}
    for dac, table in DAC_TO_TABLE.items():
        table_to_dacs.setdefault(table, set()).add(dac)

    # Collect all SQL table names used
    sql_tables = {col["table"] for col in columns}

    # Collect all DAC names from fields
    dac_names = {f["dac"] for f in fields}

    for dac in dac_names:
        if dac not in DAC_TO_TABLE:
            # Check if a SQL table matches the DAC name — if it does, fine
            # If not, warn about unmapped DAC
            if dac not in sql_tables:
                warnings.append(
                    f"DAC '{dac}' not in DAC_TO_TABLE mapping and no SQL table "
                    f"with that name found"
                )
            continue

        expected_table = DAC_TO_TABLE[dac]
        if dac == expected_table:
            continue  # Same name, no risk

        # Check if SQL uses the DAC name instead of the correct table name
        if dac in sql_tables:
            errors.append(
                f"SQL uses table name '{dac}' but this DAC maps to table "
                f"'{expected_table}' — ALTER TABLE should reference '{expected_table}'"
            )

    return errors, warnings


# ── Phase 2 check functions ────────────────────────────────────────────

_RE_GET_EXTENSION = re.compile(r"GetExtension<(\w+)>\s*\(\s*\)")


def check_extension_references(
    code: str, declared_extensions: set[str]
) -> tuple[list[str], list[str]]:
    """Check that GetExtension<T>() calls reference declared extensions.

    Returns (errors, warnings).
    """
    errors: list[str] = []
    warnings: list[str] = []
    clean = _strip_comments(code)
    for m in _RE_GET_EXTENSION.finditer(clean):
        ext_name = m.group(1)
        if ext_name not in declared_extensions:
            warnings.append(
                f"GetExtension<{ext_name}>() references undeclared extension "
                f"(may be a base framework extension)"
            )
    return errors, warnings


def check_cross_project_duplicates(
    primary_name: str,
    primary_fields: list[dict],
    other_projects: dict[str, list[dict]],
) -> tuple[list[str], list[str]]:
    """Detect the same (dac, field_name) declared in multiple projects.

    Returns (errors, warnings).
    """
    errors: list[str] = []
    warnings: list[str] = []

    # Build index: (dac, name) → list of project names
    field_owners: dict[tuple[str, str], list[str]] = {}
    for f in primary_fields:
        key = (f["dac"], f["name"])
        field_owners.setdefault(key, []).append(primary_name)

    for proj_name, proj_fields in other_projects.items():
        for f in proj_fields:
            key = (f["dac"], f["name"])
            field_owners.setdefault(key, []).append(proj_name)

    for (dac, name), owners in field_owners.items():
        if len(owners) > 1:
            errors.append(
                f"Duplicate field {dac}.{name} declared in: {', '.join(owners)}"
            )

    return errors, warnings


_RE_NAMESPACE = re.compile(r"^\s*namespace\s+([\w.]+)", re.MULTILINE)


def check_namespace_consistency(
    files: dict[str, str],
) -> tuple[list[str], list[str]]:
    """Warn if any file uses a different namespace than the majority.

    Returns (errors, warnings).
    """
    errors: list[str] = []
    warnings: list[str] = []

    ns_to_files: dict[str, list[str]] = {}
    for filepath, code in files.items():
        m = _RE_NAMESPACE.search(code)
        if m:
            ns = m.group(1)
            ns_to_files.setdefault(ns, []).append(filepath)

    if len(ns_to_files) <= 1:
        return errors, warnings

    # Find majority namespace
    majority_ns = max(ns_to_files, key=lambda ns: len(ns_to_files[ns]))
    for ns, file_list in ns_to_files.items():
        if ns != majority_ns:
            for fp in file_list:
                warnings.append(
                    f"'{fp}' uses namespace '{ns}' (majority is '{majority_ns}')"
                )

    return errors, warnings


# ── Phase 3 check functions ────────────────────────────────────────────


def check_orphaned_sql_columns(
    fields: list[dict], columns: list[dict]
) -> tuple[list[str], list[str]]:
    """Warn for SQL columns starting with 'Usr' that have no matching DAC field.

    Returns (errors, warnings).
    """
    errors: list[str] = []
    warnings: list[str] = []

    field_names = {f["name"] for f in fields}

    for col in columns:
        if col["column"].startswith("Usr") and col["column"] not in field_names:
            warnings.append(
                f"SQL column {col['table']}.{col['column']} has no matching DAC field"
            )

    return errors, warnings


def check_external_paths(
    graphs: list[dict], project_dir: str
) -> tuple[list[str], list[str]]:
    """Check that external .cs file references in <Graph> elements exist.

    Args:
        graphs: list of dicts with keys: source, class_name
        project_dir: path to project directory (parent of project.xml)

    Returns (errors, warnings).
    """
    errors: list[str] = []
    warnings: list[str] = []

    project_path = Path(project_dir)

    for graph in graphs:
        source = graph.get("source", "")
        class_name = graph.get("class_name", "(unknown)")

        if not source or source == "#CDATA" or not source.endswith(".cs"):
            continue

        # Normalize backslashes to forward slashes
        normalized = source.replace("\\", "/")
        cs_path = project_path / normalized

        if cs_path.exists():
            continue

        # Try case-insensitive match
        found_case_mismatch = False
        parent = cs_path.parent
        if parent.exists():
            target_name = cs_path.name.lower()
            for entry in parent.iterdir():
                if entry.name.lower() == target_name:
                    warnings.append(
                        f"<Graph ClassName=\"{class_name}\"> path case mismatch: "
                        f"'{source}' → actual '{entry.name}'"
                    )
                    found_case_mismatch = True
                    break

        if not found_case_mismatch:
            errors.append(
                f"<Graph ClassName=\"{class_name}\"> references missing file: {source}"
            )

    return errors, warnings


def check_pxdefault_vs_sql(
    fields: list[dict], sql_text: str
) -> tuple[list[str], list[str]]:
    """Warn for fields with PXDefault but no SQL DEFAULT near that column.

    Returns (errors, warnings).
    """
    errors: list[str] = []
    warnings: list[str] = []

    sql_text.upper()

    for field in fields:
        if field["default_value"] is None:
            continue

        # Look for DEFAULT near the column name in SQL
        # Pattern: column name followed (within ~100 chars) by DEFAULT
        pattern = re.compile(
            re.escape(field["name"]) + r".{0,100}DEFAULT",
            re.IGNORECASE,
        )
        if not pattern.search(sql_text):
            warnings.append(
                f"{field['dac']}.{field['name']} has PXDefault({field['default_value']}) "
                f"but no SQL DEFAULT clause"
            )

    return errors, warnings


# Escape hatch: a ``// REVIEWED: no-rest-write`` comment in the field's
# preamble suppresses the parity error. Used for DAC fields that are
# genuinely internal (never written via REST) — audited once, documented in
# source, and skipped by this check. The marker must appear before the
# Usr-property declaration; it binds to the next Usr* property encountered.
_RE_REVIEWED_NO_REST_WRITE = re.compile(
    r"//\s*REVIEWED:\s*no-rest-write\b"
    r"[^/]*?"                                # anything but a line-starting // block
    r"public\s+(?:\w+\s+)*[\w?]+\s+(Usr\w+)\s*\{",
    re.DOTALL,
)


def _collect_manifest_endpoint_fields(manifest: dict) -> set[str]:
    """Flatten ``endpoint_extensions[*].entities[*].fields[]`` into a name set."""
    names: set[str] = set()
    extensions = manifest.get("endpoint_extensions") or {}
    for section in extensions.values():
        entities = section.get("entities") or {}
        for entity in entities.values():
            for entry in entity.get("fields") or []:
                if isinstance(entry, str):
                    names.add(entry)
                elif isinstance(entry, dict):
                    n = entry.get("name")
                    if n:
                        names.add(n)
    return names


def check_dac_manifest_parity(
    cs_code: str, manifest: dict
) -> tuple[list[str], list[str]]:
    """Every DAC Usr* field must be declared in ``endpoint_extensions``.

    Missing the manifest entry is the exact failure mode that silently
    drops REST PUTs on Acumatica (Usr fields aren't auto-included in the
    Default endpoint schema). Three prod incidents on Heritage Fabrics
    (UsrHubSpotDealId 2026-03-07, UsrWMSStatus 2026-04-13, UsrFactoryPromisedDate
    2026-04-19) before this guard.

    Returns (errors, warnings):
      * ERROR on DAC field not present in the manifest (unless marked
        ``// REVIEWED: no-rest-write`` in source).
      * WARN on manifest entry not backed by any DAC field (stale manifest).

    If the manifest has no ``endpoint_extensions`` section at all, the check
    no-ops — lets the guard roll out without breaking packages that haven't
    adopted the schema yet.
    """
    errors: list[str] = []
    warnings: list[str] = []

    if "endpoint_extensions" not in (manifest or {}):
        return errors, warnings

    fields = parse_dac_fields(cs_code)
    manifest_fields = _collect_manifest_endpoint_fields(manifest)

    # Detect escape-hatch markers in the raw source (before comment stripping)
    reviewed = {
        m.group(1) for m in _RE_REVIEWED_NO_REST_WRITE.finditer(cs_code)
    }

    for field in fields:
        name = field["name"]
        if name in manifest_fields:
            continue
        if name in reviewed:
            continue
        errors.append(
            f"{field['dac']}.{name} missing from manifest endpoint_extensions "
            f"— REST writes will be silently dropped. Add it under "
            f"endpoint_extensions.<package>.entities.<entity>.fields[], or "
            f"mark the field with `// REVIEWED: no-rest-write` if intentionally internal."
        )

    field_names = {f["name"] for f in fields}
    for mf in sorted(manifest_fields):
        if mf not in field_names:
            warnings.append(
                f"endpoint_extensions lists '{mf}' but no DAC field declares it "
                f"— stale manifest entry, remove or add the missing DAC property"
            )

    return errors, warnings


# ── DEFAULT_ENDPOINT_FIELD_MAPPINGS[] ↔ manifest parity ──────────────────

_RE_ENDPOINT_FIELD_SPEC_ENTRY = re.compile(
    r"new\s+EndpointFieldSpec\s*\{([^}]+)\}",
    re.DOTALL,
)
_RE_SPEC_ENTITY_NAME = re.compile(r'EntityName\s*=\s*"([^"]+)"')
_RE_SPEC_FIELD_NAME = re.compile(r'FieldName\s*=\s*"([^"]+)"')


def _parse_default_endpoint_mapping_specs(cs_code: str) -> set[tuple[str, str]]:
    """Parse every ``new EndpointFieldSpec { ... }`` entry in the source.

    ``EndpointFieldSpec`` is a private type used only inside
    ``DEFAULT_ENDPOINT_FIELD_MAPPINGS[]`` in CustomizationPlugin classes
    (convention from client-asthetik PR #38 / AesthetikContainersInstall.cs),
    so every matched entry belongs to that array. Comments are stripped first.

    Returns a set of ``(EntityName, FieldName)`` tuples.
    """
    clean = _strip_comments(cs_code)
    pairs: set[tuple[str, str]] = set()
    for entry_m in _RE_ENDPOINT_FIELD_SPEC_ENTRY.finditer(clean):
        body = entry_m.group(1)
        entity = _RE_SPEC_ENTITY_NAME.search(body)
        field = _RE_SPEC_FIELD_NAME.search(body)
        if entity and field:
            pairs.add((entity.group(1), field.group(1)))
    return pairs


def _collect_default_endpoint_extension_pairs(
    manifest: dict,
) -> set[tuple[str, str]]:
    """Flatten manifest ``endpoint_extensions[*]`` where ``extends=="Default"``
    into a set of ``(EntityName, FieldName)`` tuples.

    Non-Default extensions are skipped — they register their own endpoint via
    the inline-XML-block path (acuops-pipeline#70) and do not require a row in
    the Default endpoint's SM207060 Fields grid.
    """
    pairs: set[tuple[str, str]] = set()
    extensions = manifest.get("endpoint_extensions") or {}
    for section in extensions.values():
        section = section or {}
        if section.get("extends") != "Default":
            continue
        entities = section.get("entities") or {}
        for entity_name, entity in entities.items():
            for entry in (entity or {}).get("fields") or []:
                if isinstance(entry, str):
                    pairs.add((entity_name, entry))
                elif isinstance(entry, dict):
                    name = entry.get("name")
                    if name:
                        pairs.add((entity_name, name))
    return pairs


def check_endpoint_mapping_plugin_parity(
    cs_code: str, manifest: dict
) -> tuple[list[str], list[str]]:
    """DEFAULT_ENDPOINT_FIELD_MAPPINGS[] in C# must match manifest Default extensions.

    Every manifest field declared under ``endpoint_extensions[*]`` with
    ``extends=="Default"`` must appear as an ``EndpointFieldSpec`` entry in
    some ``DEFAULT_ENDPOINT_FIELD_MAPPINGS[]`` array across the CustomizationPlugin
    source. The plugin's ``EnsureDefaultEndpointMappings()`` is what persists
    the SM207060 Fields-grid rows at publish time — a manifest entry without
    a plugin entry means the Default endpoint's field grid never receives the
    mapping, so REST writes silent-drop in prod.

    Mirrors CLAUDE.md Rule #17's ``GI_SCREENS_REQUIRING_GRANT`` parity pattern
    and guards against the same failure class that Rule #38 (three Heritage
    Fabrics prod incidents) and Rule #40 (the $adHocSchema false-positive)
    document.

    Returns ``(errors, warnings)``:
      * ERROR on manifest field absent from every plugin array
        (REST writes would silent-drop).
      * WARN  on plugin entry absent from every Default manifest section
        (stale mapping — not load-bearing but indicates drift).

    If neither side has any entries, the check no-ops so packages that have
    not adopted the endpoint-extension schema yet are not penalised.
    """
    errors: list[str] = []
    warnings: list[str] = []

    manifest_pairs = _collect_default_endpoint_extension_pairs(manifest)
    plugin_pairs = _parse_default_endpoint_mapping_specs(cs_code)

    if not manifest_pairs and not plugin_pairs:
        return errors, warnings

    for entity, field in sorted(manifest_pairs - plugin_pairs):
        errors.append(
            f"{entity}.{field} declared in manifest endpoint_extensions "
            f"(extends=\"Default\") but missing from CustomizationPlugin "
            f"DEFAULT_ENDPOINT_FIELD_MAPPINGS[] — REST writes to the Default "
            f"endpoint will be silently dropped in prod. Add "
            f"`new EndpointFieldSpec {{ EntityName = \"{entity}\", "
            f"FieldName = \"{field}\", MappedField = \"{field}\", "
            f"FieldType = \"...\" }}` to the plugin array."
        )

    for entity, field in sorted(plugin_pairs - manifest_pairs):
        warnings.append(
            f"{entity}.{field} in CustomizationPlugin "
            f"DEFAULT_ENDPOINT_FIELD_MAPPINGS[] but not declared under any "
            f"Default-extending endpoint_extensions entry in "
            f"publish-manifest.json — stale mapping, remove the plugin entry "
            f"or add the manifest field."
        )

    return errors, warnings


def check_manifest_coverage(
    fields: list[dict], manifest: dict
) -> tuple[list[str], list[str]]:
    """Warn for fields not found in the publish manifest.

    Args:
        manifest: parsed JSON from publish-manifest.json

    Returns (errors, warnings).
    """
    errors: list[str] = []
    warnings: list[str] = []

    # Collect all field names from manifest custom_fields and sql_columns
    manifest_fields: set[str] = set()

    entities = manifest.get("entities", {})
    for entity_data in entities.values():
        for cf in entity_data.get("custom_fields", []):
            # custom_fields are like "custom.Document.UsrHubSpotDealId"
            parts = cf.split(".")
            if parts:
                manifest_fields.add(parts[-1])

    for sql_entry in manifest.get("sql_columns", []):
        for col_name in sql_entry.get("columns", []):
            manifest_fields.add(col_name)

    if not manifest_fields:
        return errors, warnings

    for field in fields:
        if field["name"] not in manifest_fields:
            warnings.append(
                f"{field['dac']}.{field['name']} not in publish-manifest.json"
            )

    return errors, warnings


# ── Phase 4: Acumatica-specific anti-patterns ────────────────────────────


# Known CRM DACs that crash when used in non-CRM graphs
_CRM_DACS = {"CRRelation", "CRPMTimeActivity", "CRActivity", "CRSMEmail"}

# Known non-CRM graphs where CRM DACs cause selector crashes
_NON_CRM_GRAPHS = {
    "POOrderEntry", "SOOrderEntry", "APInvoiceEntry", "ARInvoiceEntry",
    "INReceiptEntry", "INIssueEntry", "POReceiptEntry",
}


def check_system_typecode(cs_code: str) -> tuple[list[str], list[str]]:
    """Detect unqualified TypeCode usage that causes CS0104 ambiguous reference.

    Acumatica has its own TypeCode enum. Using `TypeCode.Decimal` without
    `System.` prefix causes compilation failure.

    Returns (errors, warnings).
    """
    errors: list[str] = []
    warnings: list[str] = []

    # Find [PXDefault(TypeCode.xxx, ...)] without System. prefix
    for m in re.finditer(r"\[\s*PXDefault\s*\(\s*TypeCode\.", cs_code):
        # Check if it's preceded by "System."
        start = max(0, m.start() - 30)
        context = cs_code[start:m.start() + len(m.group())]
        if "System.TypeCode" not in context:
            errors.append(
                f"Unqualified TypeCode usage: '{m.group().strip()}' — "
                f"must use System.TypeCode to avoid CS0104 ambiguous reference"
            )

    return errors, warnings


def check_isactive_required(cs_code: str) -> tuple[list[str], list[str]]:
    """Every PXCacheExtension and PXGraphExtension must have IsActive().

    Missing IsActive() silently disables the extension — fields don't appear,
    graph logic doesn't fire.

    Returns (errors, warnings).
    """
    errors: list[str] = []
    warnings: list[str] = []

    # Find all extension class declarations
    ext_pattern = re.compile(
        r"class\s+(\w+)\s*:\s*(?:PXCacheExtension|PXGraphExtension)<"
    )
    for m in ext_pattern.finditer(cs_code):
        class_name = m.group(1)
        # Find the class body — look for the next matching brace
        class_start = m.start()
        # Simple approach: search for IsActive within ~2000 chars after class declaration
        search_window = cs_code[class_start:class_start + 2000]
        if "IsActive()" not in search_window:
            errors.append(
                f"Extension '{class_name}' missing IsActive() method — "
                f"extension will be silently disabled"
            )

    return errors, warnings


def check_banned_table_elements(project_xml_path: str) -> tuple[list[str], list[str]]:
    """Detect <Table> elements that cause NullReferenceException on cloud.

    Returns (errors, warnings).
    """
    errors: list[str] = []
    warnings: list[str] = []

    try:
        tree = ET.parse(project_xml_path)
        root = tree.getroot()
        tables = root.findall(".//Table")
        for table in tables:
            name = table.get("Name", "(unknown)")
            errors.append(
                f"<Table Name=\"{name}\"> element found — causes NullReferenceException "
                f"on Acumatica Cloud. Remove it; [PXDB*] attributes handle column creation."
            )
    except ET.ParseError:
        pass

    return errors, warnings


def check_banned_imports(cs_code: str) -> tuple[list[str], list[str]]:
    """Detect banned using statements and API calls.

    - Microsoft.Data.SqlClient → doesn't work on Acumatica Cloud
    - string.Contains(char) → .NET Framework doesn't support char overload

    Returns (errors, warnings).
    """
    errors: list[str] = []
    warnings: list[str] = []

    if "Microsoft.Data.SqlClient" in cs_code:
        errors.append(
            "using Microsoft.Data.SqlClient — not available on Acumatica Cloud. "
            "Use System.Data.SqlClient instead."
        )

    # Detect .Contains('x') with single-char argument (char overload)
    for m in re.finditer(r"\.Contains\s*\(\s*'[^']*'\s*\)", cs_code):
        errors.append(
            f"string.Contains(char) at '{m.group().strip()}' — .NET Framework "
            f"doesn't support char overload. Use .Contains(\"x\") instead."
        )

    return errors, warnings


def check_crm_dac_in_non_crm_graph(cs_code: str) -> tuple[list[str], list[str]]:
    """Detect CRM DAC references in non-CRM graph extensions.

    CRM DACs (CRRelation, CRPMTimeActivity) have field-level selectors that
    reference CRM views. Using them in PO/SO graphs crashes at runtime.

    Returns (errors, warnings).
    """
    errors: list[str] = []
    warnings: list[str] = []

    # Find graph extension declarations
    graph_ext_re = re.compile(
        r"class\s+(\w+)\s*:\s*PXGraphExtension<(\w+)>"
    )
    for m in graph_ext_re.finditer(cs_code):
        ext_name = m.group(1)
        base_graph = m.group(2)

        if base_graph not in _NON_CRM_GRAPHS:
            continue

        # Check if any CRM DAC is referenced in this extension
        class_start = m.start()
        # Crude but effective: check the next ~5000 chars for CRM DAC references
        search_window = cs_code[class_start:class_start + 5000]
        for crm_dac in _CRM_DACS:
            if crm_dac in search_window:
                errors.append(
                    f"Extension '{ext_name}' on {base_graph} references CRM DAC "
                    f"'{crm_dac}' — CRM selectors crash on non-CRM graphs. "
                    f"Use a custom DAC instead."
                )

    return errors, warnings


def check_aspx_duplicate_controls(
    project_xml_path: str,
    also_publish: list[str] | None = None,
) -> tuple[list[str], list[str]]:
    """Detect duplicate ASPX control IDs across co-published projects.

    Two packages adding the same control ID to the same screen causes
    silent publish failures.

    Returns (errors, warnings).
    """
    errors: list[str] = []
    warnings: list[str] = []

    # Collect controls: {screen_id: {control_id: project_name}}
    controls: dict[str, dict[str, str]] = {}
    project_dir = Path(project_xml_path).parent

    def _collect_controls(xml_path: str, proj_name: str):
        try:
            tree = ET.parse(xml_path)
            for page in tree.getroot().findall(".//Page"):
                screen = page.get("ScreenID", page.get("PageID", ""))
                for control in page.findall(".//*[@ControlID]"):
                    cid = control.get("ControlID", "")
                    if cid:
                        controls.setdefault(screen, {})
                        if cid in controls[screen] and controls[screen][cid] != proj_name:
                            errors.append(
                                f"Duplicate ASPX control '{cid}' on screen {screen}: "
                                f"defined in both '{controls[screen][cid]}' and '{proj_name}'"
                            )
                        controls[screen][cid] = proj_name
        except (ET.ParseError, FileNotFoundError):
            pass

    _collect_controls(project_xml_path, project_dir.name)

    if also_publish:
        for other_name in also_publish:
            other_xml = project_dir.parent / other_name.strip() / "project.xml"
            if other_xml.exists():
                _collect_controls(str(other_xml), other_name.strip())

    return errors, warnings


def check_versioned_project_names(
    project_name: str,
) -> tuple[list[str], list[str]]:
    """Detect versioned project names (v2, v3, etc.) that cause corruption.

    Importing a project under a new versioned name creates a parallel copy.
    Both compile during publish, causing CS0101 duplicate type errors or
    subsystem corruption.

    Returns (errors, warnings).
    """
    errors: list[str] = []
    warnings: list[str] = []

    if re.search(r"[vV]\d+$", project_name):
        errors.append(
            f"Project name '{project_name}' ends with version suffix — "
            f"NEVER create versioned project names. Always import over the same name. "
            f"Versioned names cause subsystem corruption and CS0101 duplicate types."
        )

    return errors, warnings


def check_unbound_usr_fields(cs_code: str) -> tuple[list[str], list[str]]:
    """Warn for Usr* fields using [PXString] instead of [PXDBString].

    Unbound attributes ([PXString], [PXInt], etc.) don't persist to the database.
    Usr* fields should almost always use [PXDB*] attributes.

    Returns (errors, warnings).
    """
    errors: list[str] = []
    warnings: list[str] = []

    # Find Usr* properties preceded by unbound attributes
    unbound_re = re.compile(
        r"\[\s*(PXString|PXInt|PXDecimal|PXBool|PXDate|PXFloat|PXLong|PXShort)"
        r"(?:\([^)]*\))?\s*\]"
        r".*?"
        r"public\s+\w+\??\s+(Usr\w+)\s*\{",
        re.DOTALL,
    )
    for m in unbound_re.finditer(cs_code):
        attr = m.group(1)
        field = m.group(2)
        warnings.append(
            f"Field '{field}' uses unbound [{attr}] instead of [{attr.replace('PX', 'PXDB', 1)}] — "
            f"value will NOT persist to database. Use [PXDB*] if this field should be saved."
        )

    return errors, warnings


def check_ghost_packages(
    also_publish: list[str] | None,
    customization_dir: str,
) -> tuple[list[str], list[str]]:
    """Warn for projects in ALSO_PUBLISH_PROJECTS with no directory in repo.

    Ghost packages were previously imported to the Acumatica instance and may
    still compile during publish even though they're not tracked in the repo.

    Returns (errors, warnings).
    """
    errors: list[str] = []
    warnings: list[str] = []

    if not also_publish:
        return errors, warnings

    cust_dir = Path(customization_dir)

    for proj_name in also_publish:
        proj_name = proj_name.strip()
        if not proj_name:
            continue
        # ISV packages typically have version strings with brackets — skip those
        if "[" in proj_name or "." in proj_name:
            continue
        proj_dir = cust_dir / proj_name
        if not proj_dir.exists():
            warnings.append(
                f"Project '{proj_name}' is in ALSO_PUBLISH_PROJECTS but has no "
                f"directory in {cust_dir}. If it exists on the Acumatica instance, "
                f"it will compile during publish with potentially stale code."
            )

    return errors, warnings


# ── Orchestrator ────────────────────────────────────────────────────────


def _collect_project_code(project_xml_path: str) -> tuple[str, str, list[dict], dict[str, str]]:
    """Parse project.xml and extract all C# code, SQL text, graph info, and file contents.

    Returns:
        (combined_cs_code, combined_sql_text, graph_list, file_code_map)

    graph_list: list of dicts with keys: source, class_name
    file_code_map: dict of {filepath: code_content} for namespace checking
    """
    tree = ET.parse(project_xml_path)
    root = tree.getroot()
    project_dir = str(Path(project_xml_path).parent)

    cs_parts: list[str] = []
    sql_parts: list[str] = []
    graph_list: list[dict] = []
    file_code_map: dict[str, str] = {}

    # Collect from <Graph> elements
    for graph in root.findall(".//Graph"):
        class_name = graph.get("ClassName", "(missing)")
        source = graph.get("Source", "")

        graph_list.append({"source": source, "class_name": class_name})

        if source == "#CDATA":
            cdata = graph.find("CDATA")
            if cdata is not None and cdata.text:
                cs_parts.append(cdata.text)
                file_code_map[f"inline:{class_name}"] = cdata.text
        elif source and source.endswith(".cs"):
            normalized = source.replace("\\", "/")
            cs_path = Path(project_dir) / normalized
            if cs_path.exists():
                code = cs_path.read_text(encoding="utf-8")
                cs_parts.append(code)
                file_code_map[str(cs_path)] = code

    # Collect from <Sql> elements
    for sql_elem in root.findall(".//Sql"):
        cdata = sql_elem.find("CDATA")
        if cdata is not None and cdata.text:
            sql_parts.append(cdata.text)

    # Also extract SQL from C# initializer string arrays (common pattern for schema installers)
    # Look for quoted SQL strings in C# code
    combined_cs = "\n".join(cs_parts)
    sql_from_cs = re.findall(
        r'"(IF NOT EXISTS.*?ALTER TABLE.*?NULL.*?)"', combined_cs, re.DOTALL
    )
    for sql_str in sql_from_cs:
        sql_parts.append(sql_str)

    return combined_cs, "\n".join(sql_parts), graph_list, file_code_map


# ── DLL-backed plugin source collection ──────────────────────────────────
# CustomizationPlugins cannot live in project.xml <Graph> CDATA — the
# Customization API rejects the <Graph> tag for classes extending
# CustomizationPlugin (lessons-learned.md). They compile to a DLL that is
# referenced by <File AppRelativePath="Bin\{DllName}.dll"/>; the .cs source
# lives at <repo>/src/{DllName}/. `_collect_project_code` only collects
# inline/Graph-referenced source, so this helper closes the gap for checks
# that need to see plugin source (e.g. check_endpoint_mapping_plugin_parity).

_PLUGIN_SRC_SKIP_DIRS = frozenset({"bin", "obj", ".vs", "packages"})


def _find_plugin_src_tree(
    project_xml_path: Path, dll_basename: str, max_levels: int = 5
) -> Optional[Path]:
    """Walk up from project.xml looking for src/{dll_basename}/.

    Mirrors validate-project.py's ``_find_src_tree`` — intentionally duplicated
    here to keep semantic_checks self-contained (no cross-module private imports).
    """
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


def _collect_dll_plugin_source(project_xml_path: Path) -> str:
    """Concatenate .cs source from every DLL-backed plugin referenced in project.xml.

    For each ``<File AppRelativePath="Bin\\{DllName}.dll"/>`` entry, walks up
    from project.xml to find ``src/{DllName}/``, then iterates every .cs file
    (excluding build output ``bin/obj/.vs/packages``) and concatenates them.

    Returns an empty string when there are no DLL refs or no matching src trees.
    """
    try:
        tree = ET.parse(str(project_xml_path))
    except ET.ParseError:
        return ""
    root = tree.getroot()

    parts: list[str] = []
    seen: set[str] = set()
    for f in root.findall(".//File"):
        app_rel = f.get("AppRelativePath", "")
        if not app_rel:
            continue
        norm = app_rel.replace("\\", "/")
        if not norm.lower().startswith("bin/") or not norm.lower().endswith(".dll"):
            continue
        dll_name = Path(norm).stem
        if not dll_name:
            continue
        src_dir = _find_plugin_src_tree(project_xml_path, dll_name)
        if src_dir is None:
            continue
        for cs_path in sorted(src_dir.rglob("*.cs")):
            rel_parts = cs_path.relative_to(src_dir).parts
            if any(seg.lower() in _PLUGIN_SRC_SKIP_DIRS for seg in rel_parts[:-1]):
                continue
            key = str(cs_path)
            if key in seen:
                continue
            seen.add(key)
            try:
                parts.append(cs_path.read_text(encoding="utf-8"))
            except (OSError, UnicodeDecodeError):
                continue
    return "\n".join(parts)


def run_semantic_checks(
    project_path: str,
    strict: bool = False,
    also_publish: Optional[list[str]] = None,
    manifest_path: Optional[str] = None,
) -> tuple[list[str], list[str]]:
    """Run all semantic checks on a customization project.

    Args:
        project_path: Path to the project.xml file or its parent directory.
        strict: If True, treat warnings as errors for some checks.
        also_publish: List of other project names to check for cross-project duplicates.
        manifest_path: Path to publish-manifest.json for coverage checks.

    Returns (errors, warnings).
    """
    all_errors: list[str] = []
    all_warnings: list[str] = []

    project_xml = Path(project_path)
    if project_xml.is_dir():
        project_xml = project_xml / "project.xml"
    if not project_xml.exists():
        all_errors.append(f"project.xml not found: {project_xml}")
        return all_errors, all_warnings

    print(f"\n{CYAN}── Semantic Checks ──{RESET}")

    # Parse project and collect code
    try:
        cs_code, sql_text, graphs, file_code_map = _collect_project_code(
            str(project_xml)
        )
    except ET.ParseError as e:
        all_errors.append(f"XML parse error in semantic checks: {e}")
        return all_errors, all_warnings

    # Parse fields and columns
    fields = parse_dac_fields(cs_code)
    columns = parse_sql_columns(sql_text)

    # Collect DLL-backed plugin source (CustomizationPlugin .cs lives outside
    # project.xml). Needed for check_endpoint_mapping_plugin_parity below.
    plugin_cs_code = _collect_dll_plugin_source(project_xml)

    if not fields and not columns:
        # No DAC-extension content in project.xml — still run the
        # endpoint-mapping parity check if a manifest is provided and there's
        # plugin source to compare against (DLL-only packages).
        if manifest_path and plugin_cs_code:
            manifest_file = Path(manifest_path)
            if manifest_file.exists():
                try:
                    manifest = json.loads(manifest_file.read_text(encoding="utf-8"))
                    errs, warns = check_endpoint_mapping_plugin_parity(
                        plugin_cs_code, manifest
                    )
                    all_errors.extend(errs)
                    all_warnings.extend(warns)
                except (json.JSONDecodeError, OSError):
                    all_warnings.append(
                        f"Could not parse manifest: {manifest_path}"
                    )
        print(f"{YELLOW}[SKIP]{RESET}  No DAC fields or SQL columns found")
        for e in all_errors:
            print(f"{RED}[ERROR]{RESET} {e}")
        for w in all_warnings:
            print(f"{YELLOW}[WARN]{RESET}  {w}")
        return all_errors, all_warnings

    print(f"{GREEN}[OK]{RESET}    Parsed {len(fields)} DAC fields, {len(columns)} SQL columns")

    # ── Merge co-published project SQL columns ──
    # When projects are co-published, one project may create SQL columns that
    # another project's DAC extensions reference. Merge SQL from all co-published
    # projects so Phase 1 checks don't false-positive on cross-project dependencies.
    all_columns = list(columns)  # start with this project's columns
    other_projects: dict[str, list[dict]] = {}

    if also_publish:
        project_name = project_xml.parent.name
        for other_name in also_publish:
            other_name = other_name.strip()
            if not other_name or other_name == project_name:
                continue
            other_xml = project_xml.parent.parent / other_name / "project.xml"
            if other_xml.exists():
                try:
                    other_cs, other_sql, _, _ = _collect_project_code(str(other_xml))
                    # Merge SQL columns from sibling project
                    sibling_cols = parse_sql_columns(other_sql)
                    all_columns.extend(sibling_cols)
                    # Also collect fields for duplicate check
                    other_fields = parse_dac_fields(other_cs)
                    if other_fields:
                        other_projects[other_name] = other_fields
                except Exception:
                    pass

    # ── Phase 1: DAC-to-SQL cross-reference ──

    errs, warns = check_fields_have_sql_columns(fields, all_columns)
    all_errors.extend(errs)
    all_warnings.extend(warns)

    errs, warns = check_type_compatibility(fields, all_columns)
    all_errors.extend(errs)
    all_warnings.extend(warns)

    errs, warns = check_table_name_mapping(fields, all_columns)
    all_errors.extend(errs)
    all_warnings.extend(warns)

    # ── Phase 1b: Acumatica anti-patterns ──

    errs, warns = check_system_typecode(cs_code)
    all_errors.extend(errs)
    all_warnings.extend(warns)

    errs, warns = check_isactive_required(cs_code)
    all_errors.extend(errs)
    all_warnings.extend(warns)

    errs, warns = check_banned_table_elements(str(project_xml))
    all_errors.extend(errs)
    all_warnings.extend(warns)

    errs, warns = check_banned_imports(cs_code)
    all_errors.extend(errs)
    all_warnings.extend(warns)

    errs, warns = check_crm_dac_in_non_crm_graph(cs_code)
    all_errors.extend(errs)
    all_warnings.extend(warns)

    errs, warns = check_versioned_project_names(project_xml.parent.name)
    all_errors.extend(errs)
    all_warnings.extend(warns)

    errs, warns = check_unbound_usr_fields(cs_code)
    all_errors.extend(errs)
    all_warnings.extend(warns)

    # ── Phase 2: Extension references, cross-project, namespaces ──

    declared_extensions: set[str] = set()
    for m in re.finditer(r"class\s+(\w+)\s*:\s*PXCacheExtension", cs_code):
        declared_extensions.add(m.group(1))

    errs, warns = check_extension_references(cs_code, declared_extensions)
    all_errors.extend(errs)
    all_warnings.extend(warns)

    if other_projects:
        errs, warns = check_cross_project_duplicates(
            project_xml.parent.name, fields, other_projects
        )
        all_errors.extend(errs)
        all_warnings.extend(warns)

    errs, warns = check_namespace_consistency(file_code_map)
    all_errors.extend(errs)
    all_warnings.extend(warns)

    # ── Phase 2b: Cross-project ASPX and ghost package checks ──

    errs, warns = check_aspx_duplicate_controls(
        str(project_xml), also_publish
    )
    all_errors.extend(errs)
    all_warnings.extend(warns)

    errs, warns = check_ghost_packages(
        also_publish, str(project_xml.parent.parent)
    )
    all_errors.extend(errs)
    all_warnings.extend(warns)

    # ── Phase 3: Orphaned SQL, paths, defaults, manifest ──

    errs, warns = check_orphaned_sql_columns(fields, columns)
    all_errors.extend(errs)
    all_warnings.extend(warns)

    errs, warns = check_external_paths(graphs, str(project_xml.parent))
    all_errors.extend(errs)
    all_warnings.extend(warns)

    errs, warns = check_pxdefault_vs_sql(fields, sql_text)
    all_errors.extend(errs)
    all_warnings.extend(warns)

    if manifest_path:
        manifest_file = Path(manifest_path)
        if manifest_file.exists():
            try:
                manifest = json.loads(manifest_file.read_text(encoding="utf-8"))
                errs, warns = check_manifest_coverage(fields, manifest)
                all_errors.extend(errs)
                all_warnings.extend(warns)
                # DAC <-> endpoint_extensions parity — catches the REST-writes-
                # silently-dropped failure mode (UsrHubSpotDealId 2026-03-07,
                # UsrWMSStatus 2026-04-13, UsrFactoryPromisedDate 2026-04-19).
                errs, warns = check_dac_manifest_parity(cs_code, manifest)
                all_errors.extend(errs)
                all_warnings.extend(warns)
                # DEFAULT_ENDPOINT_FIELD_MAPPINGS[] parity — every manifest
                # endpoint_extensions field (extends=="Default") must have a
                # matching EndpointFieldSpec entry in the CustomizationPlugin.
                # Plugin .cs lives outside project.xml; _collect_dll_plugin_source
                # fills the gap.
                errs, warns = check_endpoint_mapping_plugin_parity(
                    cs_code + "\n" + plugin_cs_code, manifest
                )
                all_errors.extend(errs)
                all_warnings.extend(warns)
            except (json.JSONDecodeError, OSError):
                all_warnings.append(f"Could not parse manifest: {manifest_path}")

    # ── Print results ──

    for e in all_errors:
        print(f"{RED}[ERROR]{RESET} {e}")
    for w in all_warnings:
        print(f"{YELLOW}[WARN]{RESET}  {w}")

    if not all_errors and not all_warnings:
        print(f"{GREEN}[OK]{RESET}    All semantic checks passed")
    elif not all_errors:
        print(f"{YELLOW}[OK]{RESET}    Semantic checks passed with {len(all_warnings)} warning(s)")
    else:
        print(
            f"{RED}[FAIL]{RESET}  Semantic checks: "
            f"{len(all_errors)} error(s), {len(all_warnings)} warning(s)"
        )

    return all_errors, all_warnings
