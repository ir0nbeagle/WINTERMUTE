#!/usr/bin/env python3
# Run with: python3 -B parse_metrics.py
# The -B flag prevents Python from using stale .pyc cache files.
"""
parse_metrics.py
Walks hunts/LOCK.md files, extracts metadata and metrics,
and writes metrics/summary.json for use by the executive dashboard.
"""

import json
import re
import sys
from datetime import datetime, timezone
from pathlib import Path

sys.dont_write_bytecode = True

REPO_ROOT = Path(__file__).parent.parent
HUNTS_DIR = REPO_ROOT / "hunts"
OUTPUT_FILE = REPO_ROOT / "metrics" / "summary.json"
INTEL_DIR = REPO_ROOT / "threat-intel"

STANDARD_ACTORS = {"Scattered Spider", "Atlas Lion", "FIN7", "Magecart"}


def checked_boxes(section_text: str) -> list[str]:
    return re.findall(r"^- \[x\]\s*(.+)$", section_text, re.MULTILINE | re.IGNORECASE)


def field(text: str, key: str) -> str | None:
    m = re.search(rf"^\*\*{re.escape(key)}:\*\*\s*(.+)$", text, re.MULTILINE)
    return m.group(1).strip() if m else None


def clean_other_actor(raw: str) -> str:
    raw = raw.strip()
    bold = re.findall(r"\*\*([^*]+)\*\*", raw)
    if bold:
        return bold[0].strip()
    backtick = re.match(r"^`([^`]+)`", raw)
    if backtick:
        return backtick.group(1)
    return re.split(r"\s*[—–(]", raw)[0].strip()[:60]


def parse_lock(lock_path: Path) -> dict:
    text = lock_path.read_text(encoding="utf-8")

    # ATT&CK fields
    techniques = re.findall(r"T\d{4}(?:\.\d{3})?", field(text, "ATT&CK Techniques") or "")
    tactics_raw = field(text, "ATT&CK Tactics") or ""
    tactics = [t.strip() for t in tactics_raw.split(",") if t.strip()]

    # METRICS section
    metrics_match = re.search(r"## METRICS.*?(?=\n## |\Z)", text, re.DOTALL)
    metrics_text = metrics_match.group(0) if metrics_match else ""

    # Threat actors
    actor_m = re.search(r"\*\*Threat Actor:\*\*\n(.*?)(?=\n\*\*|\Z)", metrics_text, re.DOTALL)
    actor_section = actor_m.group(1) if actor_m else ""
    raw_checked = checked_boxes(actor_section)
    named = [a for a in raw_checked if not a.startswith("Other")]
    others_raw = re.findall(r"- \[x\]\s*Other:\s*(.+)", actor_section, re.IGNORECASE)
    cleaned_others = [clean_other_actor(r) for r in others_raw]

    # If all standard actors are checked alongside an Other, it's a template default
    if cleaned_others and STANDARD_ACTORS.issubset(set(named)):
        named = [a for a in named if a not in STANDARD_ACTORS]

    all_actors, seen, threat_actors = named + cleaned_others, set(), []
    for a in all_actors:
        if a.lower() not in seen:
            seen.add(a.lower())
            threat_actors.append(a)

    # Hunt outcome
    outcome_m = re.search(r"\*\*Hunt Outcome:\*\*\n(.*?)(?=\n\*\*|\Z)", metrics_text, re.DOTALL)
    outcomes = checked_boxes(outcome_m.group(1) if outcome_m else "")
    outcome = outcomes[0] if outcomes else "Pending"

    # Detection conversion
    det_m = re.search(r"\*\*Converted to Detection Rule:\*\*.*?\n(.*?)(?=\n\*\*|\Z)", metrics_text, re.DOTALL)
    det_checked = checked_boxes(det_m.group(1) if det_m else "")
    converted_to_detection = any(c.startswith("Yes") for c in det_checked)
    detection_detail = next((c for c in det_checked if c.startswith("Yes")), None)

    # Hunting rule
    hunt_m = re.search(r"\*\*Converted to Hunting Rule:\*\*.*?\n(.*?)(?=\n\*\*|\Z)", metrics_text, re.DOTALL)
    hunt_checked = checked_boxes(hunt_m.group(1) if hunt_m else "")
    converted_to_hunt_rule = any(c.startswith("Yes") for c in hunt_checked)

    # Visibility gap
    gap_m = re.search(r"\*\*Log/Visibility Gap Found:\*\*.*?\n(.*?)(?=\n\*\*|\Z)", metrics_text, re.DOTALL)
    gap_checked = checked_boxes(gap_m.group(1) if gap_m else "")
    visibility_gap = any(c.startswith("Yes") for c in gap_checked)
    gap_detail = next(
        (re.sub(r"^Yes\s*[—-]\s*Gap:\s*", "", c) for c in gap_checked if c.startswith("Yes")),
        None
    )

    title_line = text.splitlines()[0].lstrip("# ").strip() if text.splitlines() else lock_path.parent.name

    return {
        "id": field(text, "Hunt ID") or lock_path.parent.name,
        "folder": lock_path.parent.name,
        "title": title_line,
        "status": field(text, "Status") or "Unknown",
        "priority": field(text, "Priority") or "Unknown",
        "date_created": field(text, "Date Created"),
        "analyst": field(text, "Analyst"),
        "platform": field(text, "Platform"),
        "source": field(text, "Source"),
        "techniques": techniques,
        "tactics": tactics,
        "threat_actors": threat_actors,
        "outcome": outcome,
        "converted_to_detection": converted_to_detection,
        "detection_detail": detection_detail,
        "converted_to_hunt_rule": converted_to_hunt_rule,
        "visibility_gap": visibility_gap,
        "gap_detail": gap_detail,
        "has_crowdstrike_queries": (lock_path.parent / "crowdstrike-queries.md").exists(),
        "has_secops_queries": (lock_path.parent / "google-secops-queries.md").exists(),
    }


def compute_summary(hunts: list[dict]) -> dict:
    total = len(hunts)
    completed = [h for h in hunts if h["outcome"] not in ("Pending", "Unknown", "Inconclusive", "")]
    true_positives = [h for h in hunts if h["outcome"] == "True Positive"]
    converted = [h for h in hunts if h["converted_to_detection"]]

    all_techniques = set(t for h in hunts for t in h["techniques"])

    technique_coverage = {}
    for h in hunts:
        for t in h["techniques"]:
            if t not in technique_coverage:
                technique_coverage[t] = {"hunts": [], "has_detection": False}
            technique_coverage[t]["hunts"].append(h["id"])
            if h["converted_to_detection"]:
                technique_coverage[t]["has_detection"] = True

    actor_map = {}
    for h in hunts:
        for actor in h["threat_actors"]:
            if actor not in actor_map:
                actor_map[actor] = {"hunts": [], "techniques": set(), "detections": 0}
            actor_map[actor]["hunts"].append(h["id"])
            actor_map[actor]["techniques"].update(h["techniques"])
            if h["converted_to_detection"]:
                actor_map[actor]["detections"] += 1
    for actor in actor_map:
        actor_map[actor]["techniques"] = sorted(actor_map[actor]["techniques"])

    outcome_counts = {}
    for h in hunts:
        outcome_counts[h["outcome"]] = outcome_counts.get(h["outcome"], 0) + 1

    gaps = [{"hunt": h["id"], "detail": h["gap_detail"]} for h in hunts if h["visibility_gap"]]

    # Tactic distribution
    tactic_counts = {}
    for h in hunts:
        for tac in h["tactics"]:
            tactic_counts[tac] = tactic_counts.get(tac, 0) + 1

    # Priority breakdown
    priority_counts = {}
    for h in hunts:
        priority_counts[h["priority"]] = priority_counts.get(h["priority"], 0) + 1

    return {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "totals": {
            "hunts": total,
            "completed_hunts": len(completed),
            "true_positives": len(true_positives),
            "detections_created": len(converted),
            "hunt_to_detection_rate": round(len(converted) / total * 100, 1) if total else 0,
            "true_positive_rate": round(len(true_positives) / len(completed) * 100, 1) if completed else 0,
            "unique_techniques_covered": len(all_techniques),
            "threat_actors_tracked": len(actor_map),
            "visibility_gaps_found": len(gaps),
        },
        "outcome_distribution": outcome_counts,
        "priority_distribution": priority_counts,
        "tactic_distribution": tactic_counts,
        "technique_coverage": technique_coverage,
        "threat_actors": actor_map,
        "visibility_gaps": gaps,
        "hunts": hunts,
    }


def main():
    if not HUNTS_DIR.exists():
        print(f"No hunts/ directory found at {HUNTS_DIR}")
        return

    hunts = []
    for lock_file in sorted(HUNTS_DIR.rglob("LOCK.md")):
        try:
            hunt = parse_lock(lock_file)
            hunts.append(hunt)
            print(f"  Parsed: {hunt['id']} ({hunt['outcome']})")
        except Exception as e:
            print(f"  ERROR parsing {lock_file}: {e}")

    # Parse threat intel reports
    reports = []
    if INTEL_DIR.exists():
        for report_file in sorted(INTEL_DIR.rglob("report.md")):
            if "TEMPLATE" in str(report_file):
                continue
            try:
                r = parse_report(report_file)
                if r:
                    reports.append(r)
                    print(f"  Report: {r['id']} [{r['status']}]")
            except Exception as e:
                print(f"  ERROR parsing {report_file}: {e}")

    hunt_techniques = set(t for h in hunts for t in h["techniques"])
    summary = compute_summary(hunts)
    summary["intel"] = compute_report_summary(reports, hunt_techniques)

    OUTPUT_FILE.parent.mkdir(parents=True, exist_ok=True)
    OUTPUT_FILE.write_text(json.dumps(summary, indent=2), encoding="utf-8")
    print(f"\nWrote {OUTPUT_FILE} ({len(hunts)} hunts, {len(reports)} reports)")

    t = summary["totals"]
    print(f"\n--- Quick Stats ---")
    print(f"Total Hunts:            {t['hunts']}")
    print(f"Completed:              {t['completed_hunts']}")
    print(f"True Positives:         {t['true_positives']}")
    print(f"Detections Created:     {t['detections_created']}")
    print(f"Hunt->Detection Rate:   {t['hunt_to_detection_rate']}%")
    print(f"Techniques Covered:     {t['unique_techniques_covered']}")
    print(f"Threat Actors Tracked:  {t['threat_actors_tracked']}")
    print(f"Visibility Gaps:        {t['visibility_gaps_found']}")


# ---------------------------------------------------------------------------
# Threat Intel Report parsing
# ---------------------------------------------------------------------------
try:
    import yaml
    YAML_AVAILABLE = True
except ImportError:
    YAML_AVAILABLE = False

INTEL_DIR = REPO_ROOT / "threat-intel"


def parse_report(report_path: Path) -> dict | None:
    if not YAML_AVAILABLE:
        raise RuntimeError(
            "PyYAML is required to parse YAML frontmatter but is not installed. "
            "Install it with `pip install -r requirements.txt` before running this script."
        )
    text = report_path.read_text(encoding="utf-8")
    import re as _re
    m = _re.match(r"^---\n(.*?)\n---", text, _re.DOTALL)
    if not m:
        return None
    try:
        meta = yaml.safe_load(m.group(1))
    except Exception:
        return None

    actors = meta.get("threat_actors") or []
    actor_names = [a.get("name") if isinstance(a, dict) else str(a) for a in actors]
    iocs = meta.get("iocs") or []

    return {
        "id": meta.get("id", report_path.parent.name),
        "folder": report_path.parent.name,
        "title": meta.get("title", ""),
        "date": str(meta.get("date", "")),
        "analyst": meta.get("analyst", ""),
        "tlp": meta.get("tlp", "AMBER"),
        "priority": meta.get("priority", "High"),
        "status": meta.get("status", "new"),
        "linked_hunts": meta.get("linked_hunts") or [],
        "threat_actors": actor_names,
        "techniques": meta.get("techniques") or [],
        "tools": [t.get("name") if isinstance(t, dict) else str(t) for t in (meta.get("tools") or [])],
        "ioc_count": len(iocs),
        "ioc_types": list({i.get("type", "unknown") for i in iocs}),
    }


def compute_report_summary(reports: list[dict], hunt_techniques: set) -> dict:
    total = len(reports)
    status_counts = {}
    for r in reports:
        status_counts[r["status"]] = status_counts.get(r["status"], 0) + 1

    converted = [r for r in reports if r["status"] == "hunt-created"]
    queued = [r for r in reports if r["status"] in ("new", "in-review")]

    all_actors = set()
    all_techniques = set()
    all_tools = set()
    total_iocs = 0
    for r in reports:
        all_actors.update(r["threat_actors"])
        all_techniques.update(r["techniques"])
        all_tools.update(r["tools"])
        total_iocs += r["ioc_count"]

    # TTP gap: techniques in reports that have no hunt yet
    ttp_gap = sorted(all_techniques - hunt_techniques)

    return {
        "totals": {
            "reports": total,
            "queued": len(queued),
            "converted_to_hunt": len(converted),
            "no_hunt": status_counts.get("no-hunt", 0),
            "monitoring": status_counts.get("monitoring", 0),
            "report_to_hunt_rate": round(len(converted) / total * 100, 1) if total else 0,
            "actors_tracked": len(all_actors),
            "techniques_identified": len(all_techniques),
            "tools_identified": len(all_tools),
            "total_iocs": total_iocs,
            "ttp_gap_count": len(ttp_gap),
        },
        "status_distribution": status_counts,
        "actors_tracked": sorted(all_actors),
        "techniques_identified": sorted(all_techniques),
        "tools_identified": sorted(all_tools),
        "ttp_gap": ttp_gap,
        "reports": reports,
    }


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument("--hunts-dir", type=Path, default=HUNTS_DIR)
    parser.add_argument("--output", type=Path, default=OUTPUT_FILE)
    args = parser.parse_args()
    HUNTS_DIR = args.hunts_dir
    OUTPUT_FILE = args.output
    main()

