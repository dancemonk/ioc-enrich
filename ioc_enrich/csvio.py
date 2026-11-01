"""Read, merge and write the analyst's iocs.csv format.

Columns the analyst owns (first_seen_utc, frame, context, role, confidence)
are never changed. The tool owns enrichment and checked_on.
"""

import csv
import io
from datetime import date, datetime
from pathlib import Path
from urllib.parse import urlsplit, urlunsplit

from ioc_enrich.fang import defang, refang
from ioc_enrich.format import checked_on, enrichment
from ioc_enrich.lookup_plan import LookupPlan
from ioc_enrich.models import IOC, SourceResult

COLUMNS = ["type", "value", "first_seen_utc", "frame", "context", "role",
           "confidence", "enrichment", "checked_on"]


def read_rows(path: Path) -> list[dict[str, str]]:
    with path.open(newline="", encoding="utf-8-sig") as handle:   # -sig: accept Excel's BOM
        reader = csv.DictReader(handle)
        if reader.fieldnames != COLUMNS:
            raise ValueError(f"{path}: expected columns {','.join(COLUMNS)}")
        rows = []
        for row in reader:
            # Too many fields land under the key None, too few leave None values.
            if None in row or None in row.values():
                raise ValueError(f"{path} line {reader.line_num}: expected {len(COLUMNS)} fields")
            rows.append(row)
        return rows


def row_key(row_type: str, value: str) -> tuple[str, str]:
    """Rows match on type + refanged, lowercase value.

    For URLs only the scheme and host are lowercased: "/Path" and "/path"
    can be different pages.
    """
    row_type, value = row_type.lower(), refang(value)
    if row_type != "url":
        return row_type, value.lower()
    parts = urlsplit(value)
    return row_type, urlunsplit((parts.scheme.lower(), parts.netloc.lower(), parts.path, parts.query, parts.fragment))


def ref_date(row: dict | None, incident_date: date | None) -> date | None:
    """A row's own first_seen_utc date wins over --incident-date."""
    if row and row.get("first_seen_utc"):
        try:
            return date.fromisoformat(row["first_seen_utc"][:10])
        except ValueError:
            pass
    return incident_date


def build_rows(plan: LookupPlan, results: dict[IOC, list[SourceResult]],
               existing: list[dict] | None, incident_date: date | None, today: date
               ) -> tuple[list[dict], list[str]]:
    """Merge this run into the existing rows. Returns (rows, notes for the screen)."""
    rows = [dict(row) for row in (existing or [])]
    index = {row_key(row["type"], row["value"]): row for row in rows}
    notes = []

    for item in plan.items:
        if item.skip == "private":
            continue                       # private IPs never go into the CSV
        ioc = item.ioc
        found = results.get(ioc, [])
        row = index.get(row_key(ioc.type, ioc.value))
        ref = ref_date(row, incident_date)
        if item.skip == "allowlisted":
            text, complete = "allowlisted - not checked", False
        else:
            text, complete = enrichment(ioc, found, ref), plan.is_complete(ioc, results)

        if row is None:
            new = dict.fromkeys(COLUMNS, "")
            new.update(type=ioc.type, value=defang(ioc), enrichment=text,
                       checked_on=checked_on(found, today).isoformat())
            if item.cdn:
                new["role"] = f"shared CDN ({item.cdn}) - do not block"
            rows.append(new)
            index[row_key(ioc.type, ioc.value)] = new
        elif complete or not row.get("enrichment"):
            row["enrichment"] = text
            row["checked_on"] = checked_on(found, today).isoformat()
        else:
            notes.append(f"kept old enrichment (incomplete run): {defang(ioc)}")
    return rows, notes


def rows_to_csv_text(rows: list[dict]) -> str:
    buffer = io.StringIO()
    writer = csv.DictWriter(buffer, fieldnames=COLUMNS, lineterminator="\n")
    writer.writeheader()
    writer.writerows(rows)
    return buffer.getvalue()


def write_rows(path: Path, rows: list[dict]) -> None:
    """Write a new CSV. Mode 'x' refuses to overwrite an existing file.

    The text is built first, so a failure never leaves an empty file behind.
    """
    text = rows_to_csv_text(rows)
    with path.open("x", newline="", encoding="utf-8") as handle:
        handle.write(text)


def default_output_name(now: datetime) -> str:
    return f"ioc-enrich-{now:%Y-%m-%d-%H%M}.csv"
