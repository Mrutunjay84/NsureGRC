"""Fail unless every vulnerability in a pip-audit JSON report is listed in docs/accepted_risks.yaml (used by CI)."""
import json
import sys

import yaml

report, register = sys.argv[1], sys.argv[2]
with open(register, encoding="utf-8") as fh:
    accepted = {r["id"] for r in (yaml.safe_load(fh) or {}).get("accepted", [])}
with open(report, encoding="utf-8") as fh:
    deps = json.load(fh)["dependencies"]
bad = [(d["name"], d["version"], v["id"]) for d in deps for v in d.get("vulns", []) if v["id"] not in accepted]
print("unaccepted vulnerabilities:", bad)
sys.exit(1 if bad else 0)
