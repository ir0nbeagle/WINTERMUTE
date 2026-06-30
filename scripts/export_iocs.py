#!/usr/bin/env python3
# Run with: python3 -B scripts/export_iocs.py
"""
export_iocs.py
Reads all threat-intel/*/report.md YAML frontmatter, extracts IOCs,
and exports:
  exports/stix-bundle.json   — STIX 2.1 bundle
  exports/misp-export.json   — MISP event format
  exports/iocs.csv           — flat CSV for blocking/ticketing

Requires: pyyaml (pip install pyyaml)
"""

import csv
import json
import sys
import uuid
import yaml
import re
from datetime import datetime, timezone
from pathlib import Path

sys.dont_write_bytecode = True

REPO_ROOT = Path(__file__).parent.parent
INTEL_DIR = REPO_ROOT / "threat-intel"
EXPORTS_DIR = REPO_ROOT / "exports"

# TLP marking definition UUIDs (STIX 2.1 standard)
TLP_UUIDS = {
    "WHITE": "marking-definition--613f2e26-407d-48c7-9eca-b8e91df99dc9",
    "GREEN": "marking-definition--34098fce-860f-48ae-8e50-ebd3cc5e41da",
    "AMBER": "marking-definition--f88d31f6-486f-44da-b317-01333bde0b82",
    "RED":   "marking-definition--5e57c739-391a-4eb3-b6be-7d15ca92d5ed",
}

TLP_MARKING_DEFS = [
    {"type": "marking-definition", "spec_version": "2.1", "id": TLP_UUIDS["WHITE"],
     "created": "2017-01-20T00:00:00Z", "definition_type": "tlp",
     "definition": {"tlp": "white"}},
    {"type": "marking-definition", "spec_version": "2.1", "id": TLP_UUIDS["GREEN"],
     "created": "2017-01-20T00:00:00Z", "definition_type": "tlp",
     "definition": {"tlp": "green"}},
    {"type": "marking-definition", "spec_version": "2.1", "id": TLP_UUIDS["AMBER"],
     "created": "2017-01-20T00:00:00Z", "definition_type": "tlp",
     "definition": {"tlp": "amber"}},
    {"type": "marking-definition", "spec_version": "2.1", "id": TLP_UUIDS["RED"],
     "created": "2017-01-20T00:00:00Z", "definition_type": "tlp",
     "definition": {"tlp": "red"}},
]


def stix_id(obj_type: str) -> str:
    return f"{obj_type}--{uuid.uuid4()}"


def stix_timestamp(dt=None) -> str:
    if dt is None:
        dt = datetime.now(timezone.utc)
    if isinstance(dt, str):
        return dt if "T" in dt else dt + "T00:00:00Z"
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ")


def ioc_to_stix_pattern(ioc: dict) -> str | None:
    t = ioc.get("type", "").lower()
    v = ioc.get("value", "")
    patterns = {
        "domain":  f"[domain-name:value = '{v}']",
        "ip":      f"[ipv4-addr:value = '{v}']",
        "url":     f"[url:value = '{v}']",
        "md5":     f"[file:hashes.MD5 = '{v}']",
        "sha1":    f"[file:hashes.SHA-1 = '{v}']",
        "sha256":  f"[file:hashes.SHA-256 = '{v}']",
        "sha-256": f"[file:hashes.SHA-256 = '{v}']",
        "email":   f"[email-addr:value = '{v}']",
        "filename":f"[file:name = '{v}']",
        "package": f"[file:name = '{v}']",
        "regex":   f"[file:content_ref.payload_bin MATCHES '{v}']",
    }
    return patterns.get(t)


def ioc_to_misp_type(ioc: dict) -> str | None:
    t = ioc.get("type", "").lower()
    mapping = {
        "domain":   "domain",
        "ip":       "ip-dst",
        "url":      "url",
        "md5":      "md5",
        "sha1":     "sha1",
        "sha256":   "sha256",
        "sha-256":  "sha256",
        "email":    "email-src",
        "filename": "filename",
        "package":  "text",
        "regex":    "text",
        "unicode-range": "text",
    }
    return mapping.get(t)


def parse_frontmatter(report_path: Path) -> dict | None:
    text = report_path.read_text(encoding="utf-8")
    m = re.match(r"^---\n(.*?)\n---", text, re.DOTALL)
    if not m:
        return None
    try:
        return yaml.safe_load(m.group(1))
    except yaml.YAMLError as e:
        print(f"  YAML error in {report_path}: {e}")
        return None


def load_reports() -> list[dict]:
    reports = []
    for report_file in sorted(INTEL_DIR.rglob("report.md")):
        if "TEMPLATE" in str(report_file):
            continue
        meta = parse_frontmatter(report_file)
        if meta:
            meta["_path"] = str(report_file)
            reports.append(meta)
            print(f"  Loaded: {meta.get('id', report_file.parent.name)} ({len(meta.get('iocs', []))} IOCs)")
    return reports


def build_stix_bundle(reports: list[dict]) -> dict:
    now = stix_timestamp()
    objects = list(TLP_MARKING_DEFS)
    identity_id = stix_id("identity")
    objects.append({
        "type": "identity", "spec_version": "2.1",
        "id": identity_id, "created": now, "modified": now,
        "name": "WINTERMUTE Threat Hunting Platform",
        "identity_class": "organization",
    })

    for report in reports:
        report_tlp = (report.get("tlp") or "AMBER").upper()
        marking_refs = [TLP_UUIDS.get(report_tlp, TLP_UUIDS["AMBER"])]
        created = stix_timestamp(report.get("date"))

        # Threat actor objects
        actor_ids = {}
        for actor in report.get("threat_actors") or []:
            actor_name = actor.get("name") if isinstance(actor, dict) else str(actor)
            ta_id = stix_id("threat-actor")
            actor_ids[actor_name] = ta_id
            objects.append({
                "type": "threat-actor", "spec_version": "2.1",
                "id": ta_id, "created": created, "modified": created,
                "name": actor_name,
                "threat_actor_types": [actor.get("type", "unknown")] if isinstance(actor, dict) else ["unknown"],
                "aliases": [],
                "object_marking_refs": marking_refs,
                "created_by_ref": identity_id,
            })

        # Attack pattern objects (MITRE techniques)
        technique_ids = {}
        for tech in report.get("techniques") or []:
            ap_id = stix_id("attack-pattern")
            technique_ids[tech] = ap_id
            objects.append({
                "type": "attack-pattern", "spec_version": "2.1",
                "id": ap_id, "created": created, "modified": created,
                "name": tech,
                "external_references": [{
                    "source_name": "mitre-attack",
                    "external_id": tech,
                    "url": f"https://attack.mitre.org/techniques/{tech.replace('.', '/')}",
                }],
                "object_marking_refs": marking_refs,
                "created_by_ref": identity_id,
            })

        # Indicator objects (IOCs)
        for ioc in report.get("iocs") or []:
            pattern = ioc_to_stix_pattern(ioc)
            if not pattern:
                continue
            ioc_tlp = (ioc.get("tlp") or report_tlp).upper()
            ioc_marking = [TLP_UUIDS.get(ioc_tlp, TLP_UUIDS["AMBER"])]
            ind_id = stix_id("indicator")
            valid_until = ioc.get("expires")

            indicator = {
                "type": "indicator", "spec_version": "2.1",
                "id": ind_id, "created": created, "modified": created,
                "name": f"{ioc.get('type', 'unknown').upper()}: {ioc.get('value', '')}",
                "description": ioc.get("context", ""),
                "pattern": pattern,
                "pattern_type": "stix",
                "valid_from": created,
                "labels": ["malicious-activity"],
                "object_marking_refs": ioc_marking,
                "created_by_ref": identity_id,
                "external_references": [{"source_name": report.get("id", ""), "description": report.get("title", "")}],
            }
            if valid_until:
                indicator["valid_until"] = stix_timestamp(str(valid_until))
            objects.append(indicator)

            # Relationships: indicator → threat actors
            for actor_name, ta_id in actor_ids.items():
                objects.append({
                    "type": "relationship", "spec_version": "2.1",
                    "id": stix_id("relationship"), "created": created, "modified": created,
                    "relationship_type": "indicates",
                    "source_ref": ind_id,
                    "target_ref": ta_id,
                    "object_marking_refs": ioc_marking,
                    "created_by_ref": identity_id,
                })

    return {
        "type": "bundle",
        "id": stix_id("bundle"),
        "objects": objects,
    }


def build_misp_export(reports: list[dict]) -> dict:
    events = []
    for report in reports:
        report_tlp = (report.get("tlp") or "AMBER").upper()
        attributes = []

        for ioc in report.get("iocs") or []:
            misp_type = ioc_to_misp_type(ioc)
            if not misp_type:
                continue
            ioc_tlp = (ioc.get("tlp") or report_tlp).upper()
            attr = {
                "uuid": str(uuid.uuid4()),
                "type": misp_type,
                "category": "Network activity" if misp_type in ("domain", "ip-dst", "url") else "Payload delivery",
                "value": ioc.get("value", ""),
                "comment": ioc.get("context", ""),
                "to_ids": misp_type not in ("text",),
                "tags": [{"name": f"tlp:{ioc_tlp.lower()}"}],
            }
            if ioc.get("expires"):
                attr["first_seen"] = str(report.get("date", ""))
                attr["last_seen"] = str(ioc["expires"])
            attributes.append(attr)

        actors = report.get("threat_actors") or []
        actor_names = [a.get("name") if isinstance(a, dict) else str(a) for a in actors]

        tags = [
            {"name": f"tlp:{report_tlp.lower()}"},
            {"name": f"threat-intel:report={report.get('id', '')}"},
        ] + [{"name": f"threat-actor:{a}"} for a in actor_names] + \
            [{"name": f"mitre-attack:{t}"} for t in (report.get("techniques") or [])]

        events.append({
            "uuid": str(uuid.uuid4()),
            "info": f"{report.get('id', '')} — {report.get('title', '')}",
            "date": str(report.get("date", "")),
            "threat_level_id": {"Critical": "1", "High": "2", "Medium": "3", "Low": "4"}.get(report.get("priority", "High"), "2"),
            "analysis": "2",
            "distribution": {"WHITE": "3", "GREEN": "2", "AMBER": "1", "RED": "0"}.get(report_tlp, "1"),
            "Attribute": attributes,
            "Tag": tags,
            "Orgc": {"name": "WINTERMUTE"},
        })

    return {"response": [{"Event": e} for e in events]}


def build_csv(reports: list[dict]) -> list[dict]:
    rows = []
    for report in reports:
        for ioc in report.get("iocs") or []:
            rows.append({
                "report_id": report.get("id", ""),
                "report_title": report.get("title", ""),
                "analyst": report.get("analyst", ""),
                "date": str(report.get("date", "")),
                "tlp": (ioc.get("tlp") or report.get("tlp") or "AMBER").upper(),
                "ioc_type": ioc.get("type", ""),
                "ioc_value": ioc.get("value", ""),
                "context": ioc.get("context", ""),
                "expires": str(ioc.get("expires", "")),
                "threat_actors": "|".join(
                    a.get("name") if isinstance(a, dict) else str(a)
                    for a in (report.get("threat_actors") or [])
                ),
            })
    return rows


def main():
    reports = load_reports() if INTEL_DIR.exists() else []
    if not reports:
        print("No reports found; writing empty exports")

    EXPORTS_DIR.mkdir(parents=True, exist_ok=True)

    # STIX 2.1
    stix_path = EXPORTS_DIR / "stix-bundle.json"
    stix_bundle = build_stix_bundle(reports)
    stix_path.write_text(json.dumps(stix_bundle, indent=2), encoding="utf-8")
    stix_count = sum(1 for o in stix_bundle["objects"] if o["type"] == "indicator")
    print(f"\nSTIX bundle: {stix_path} ({stix_count} indicators, {len(stix_bundle['objects'])} total objects)")

    # MISP
    misp_path = EXPORTS_DIR / "misp-export.json"
    misp_export = build_misp_export(reports)
    misp_path.write_text(json.dumps(misp_export, indent=2), encoding="utf-8")
    print(f"MISP export: {misp_path}")

    # CSV
    csv_path = EXPORTS_DIR / "iocs.csv"
    rows = build_csv(reports)
    with open(csv_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=["report_id","report_title","analyst","date","tlp","ioc_type","ioc_value","context","expires","threat_actors"])
        writer.writeheader()
        writer.writerows(rows)
    print(f"CSV export:  {csv_path} ({len(rows)} IOCs)")

    print(f"\nDone. {len(reports)} reports processed.")


if __name__ == "__main__":
    main()
