#!/usr/bin/env python3
# Run with: python3 -B scripts/export_queries.py
"""
export_queries.py
Walks hunts/*/​*queries.md files, extracts each detection/hunt query
(a `## heading` followed by a fenced code block), enriches it with the
parent hunt's ATT&CK / actor / status metadata (pulled from LOCK.md via
parse_metrics.parse_lock), and writes:

  exports/queries.json   — the Detection Query Library feed

This is the source the reports/queries.html dashboard reads so detection
engineers can browse hunt queries and pull them into detection rules.

No third-party deps (query files are plain markdown; hunt metadata comes
from parse_metrics which imports pyyaml lazily and is not exercised here).
"""

import json
import re
import sys
from pathlib import Path

sys.dont_write_bytecode = True

# Allow `python3 scripts/export_queries.py` from the repo root to import the
# sibling parser module regardless of the current working directory.
SCRIPT_DIR = Path(__file__).parent
if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))

from parse_metrics import parse_lock  # noqa: E402  (path set up above)

REPO_ROOT = SCRIPT_DIR.parent
HUNTS_DIR = REPO_ROOT / "hunts"
EXPORTS_DIR = REPO_ROOT / "exports"
OUTPUT_FILE = EXPORTS_DIR / "queries.json"

# Map a known query-file name to a human platform label + short key used for
# filtering/badging on the dashboard. Any other `*-queries.md` file still works
# via the fallback in platform_for_file().
PLATFORM_MAP = {
    "crowdstrike-queries.md": ("CrowdStrike Falcon", "crowdstrike"),
    "google-secops-queries.md": ("Google SecOps", "secops"),
    "splunk-queries.md": ("Splunk", "splunk"),
    "sentinel-queries.md": ("Microsoft Sentinel", "sentinel"),
    "elastic-queries.md": ("Elastic", "elastic"),
}

# Best-effort language hint per platform, for the code-block label / styling.
LANGUAGE_MAP = {
    "crowdstrike": "spl",
    "secops": "yara-l",
    "splunk": "spl",
    "sentinel": "kql",
    "elastic": "eql",
}


def platform_for_file(filename: str) -> tuple[str, str]:
    if filename in PLATFORM_MAP:
        return PLATFORM_MAP[filename]
    # Fallback: derive a label from "<name>-queries.md".
    stem = re.sub(r"[-_]?queries$", "", Path(filename).stem, flags=re.IGNORECASE)
    key = re.sub(r"[^a-z0-9]+", "-", stem.lower()).strip("-") or "other"
    label = stem.replace("-", " ").replace("_", " ").title() or "Other"
    return label, key


# Match a `## heading` and then the FIRST fenced code block that follows it,
# before the next `## `/`# ` heading. Captures the optional language token after
# the opening fence.
_SECTION_RE = re.compile(
    r"^\#\#\s+(?P<heading>.+?)\s*$"          # ## heading
    r"(?P<between>.*?)"                        # any prose between heading and fence
    r"^```(?P<lang>[\w.+-]*)[ \t]*\r?\n"      # opening fence (+ optional lang)
    r"(?P<code>.*?)"                           # the query body
    r"^```[ \t]*$",                            # closing fence
    re.DOTALL | re.MULTILINE,
)


def extract_queries(md_text: str) -> list[dict]:
    """Return [{title, body, note, lang}] for each `## heading` + code block."""
    out = []
    for m in _SECTION_RE.finditer(md_text):
        code = m.group("code").rstrip("\n")
        if not code.strip():
            continue
        note = m.group("between").strip()
        out.append({
            "title": m.group("heading").strip(),
            "body": code,
            "note": note,
            "lang": (m.group("lang") or "").strip(),
        })
    return out


def query_files(hunt_dir: Path) -> list[Path]:
    return sorted(p for p in hunt_dir.glob("*queries.md") if p.is_file())


def build_records(hunts_dir: Path) -> list[dict]:
    records = []
    if not hunts_dir.exists():
        return records

    for lock_file in sorted(hunts_dir.rglob("LOCK.md")):
        hunt_dir = lock_file.parent
        files = query_files(hunt_dir)
        if not files:
            continue

        try:
            hunt = parse_lock(lock_file)
        except Exception as e:  # metadata is best-effort; never drop the queries
            print(f"  WARN: could not parse {lock_file}: {e}")
            hunt = {
                "id": hunt_dir.name, "folder": hunt_dir.name, "title": hunt_dir.name,
                "status": "Unknown", "priority": "Unknown", "outcome": "Pending",
                "techniques": [], "tactics": [], "threat_actors": [],
                "converted_to_detection": False, "detection_detail": None,
            }

        for qf in files:
            label, key = platform_for_file(qf.name)
            default_lang = LANGUAGE_MAP.get(key, "")
            try:
                text = qf.read_text(encoding="utf-8")
            except Exception as e:
                print(f"  WARN: could not read {qf}: {e}")
                continue

            queries = extract_queries(text)
            if not queries:
                print(f"  note: no code-fenced queries in {qf.relative_to(REPO_ROOT)}")
            for idx, q in enumerate(queries, start=1):
                records.append({
                    "query_id": f"{hunt['id']}-{key}-{idx}",
                    "hunt_id": hunt["id"],
                    "hunt_folder": hunt["folder"],
                    "hunt_title": hunt["title"],
                    "hunt_status": hunt["status"],
                    "hunt_outcome": hunt["outcome"],
                    "priority": hunt["priority"],
                    "platform": label,
                    "platform_key": key,
                    "language": q["lang"] or default_lang,
                    "source_file": qf.name,
                    "title": q["title"],
                    "note": q["note"],
                    "query": q["body"],
                    "line_count": q["body"].count("\n") + 1,
                    "techniques": hunt["techniques"],
                    "tactics": hunt["tactics"],
                    "threat_actors": hunt["threat_actors"],
                    "converted_to_detection": hunt["converted_to_detection"],
                    "detection_detail": hunt["detection_detail"],
                })
            print(f"  Parsed: {hunt['id']} / {qf.name} ({len(queries)} queries)")

    return records


def compute_summary(records: list[dict]) -> dict:
    def facet(values):
        counts = {}
        for v in values:
            counts[v] = counts.get(v, 0) + 1
        return counts

    hunts_with_queries = sorted({r["hunt_id"] for r in records})
    platforms = facet(r["platform"] for r in records)
    statuses = facet(r["hunt_status"] for r in records)

    all_techniques = sorted({t for r in records for t in r["techniques"]})
    all_actors = sorted({a for r in records for a in r["threat_actors"]})

    # A query is "pullable" (ready to be turned into a detection) when its hunt
    # has not already been converted to a detection rule.
    converted = [r for r in records if r["converted_to_detection"]]
    pullable = [r for r in records if not r["converted_to_detection"]]

    return {
        "generated_at": _now_iso(),
        "totals": {
            "queries": len(records),
            "hunts_with_queries": len(hunts_with_queries),
            "platforms": len(platforms),
            "techniques_covered": len(all_techniques),
            "actors_covered": len(all_actors),
            "already_detections": len(converted),
            "pullable_queries": len(pullable),
        },
        "platform_distribution": platforms,
        "status_distribution": statuses,
        "techniques": all_techniques,
        "actors": all_actors,
        "hunts_with_queries": hunts_with_queries,
        "queries": records,
    }


def _now_iso() -> str:
    from datetime import datetime, timezone
    return datetime.now(timezone.utc).isoformat()


def main(hunts_dir: Path = HUNTS_DIR, output_file: Path = OUTPUT_FILE) -> dict:
    records = build_records(hunts_dir)
    summary = compute_summary(records)

    output_file.parent.mkdir(parents=True, exist_ok=True)
    output_file.write_text(json.dumps(summary, indent=2), encoding="utf-8")

    t = summary["totals"]
    print(
        f"\nWrote {output_file} "
        f"({t['queries']} queries across {t['hunts_with_queries']} hunts, "
        f"{t['platforms']} platforms)"
    )
    print(f"  Pullable (no detection yet): {t['pullable_queries']}")
    print(f"  Already a detection:         {t['already_detections']}")
    return summary


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="Export hunt queries to exports/queries.json")
    parser.add_argument("--hunts-dir", type=Path, default=HUNTS_DIR)
    parser.add_argument("--output", type=Path, default=OUTPUT_FILE)
    args = parser.parse_args()
    main(args.hunts_dir, args.output)
