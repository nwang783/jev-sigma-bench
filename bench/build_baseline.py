"""Make data/baseline/benign.jsonl: de-duplicated benign events from Nextron's evtx-baseline.

Same method and limits as sigma-llm-bench (15,000 unique events at most for each category, seed 0),
written here so that this repo does not run a downloaded script.
Run: uv run python -m bench.build_baseline
"""
import json
import random
from collections import defaultdict

from evtx import PyEvtxParser

from .common import BENIGN, DATA, flatten_event

CAP = 15000
SYSMON = {1: "process_creation", 11: "file_event", 13: "registry_set"}
DEDUP_KEYS = {
    "process_creation": ("Image", "CommandLine", "ParentImage", "ParentCommandLine"),
    "file_event": ("Image", "TargetFilename"),
    "registry_set": ("Image", "TargetObject", "Details"),
    "ps_script": ("ScriptBlockText",),
}


def main():
    root = DATA / "baseline"
    seen = defaultdict(dict)
    files = sorted(root.rglob("*Sysmon*Operational.evtx")) + sorted(root.rglob("*PowerShell*Operational.evtx"))
    for f in files:
        print("parsing", f.name, flush=True)
        sysmon = "Sysmon" in f.name
        for rec in PyEvtxParser(str(f)).records_json():
            ev = flatten_event(json.loads(rec["data"]))
            code = int(ev.get("EventID") or 0)
            cat = SYSMON.get(code) if sysmon else ("ps_script" if code == 4104 else None)
            if cat:
                seen[cat].setdefault(tuple(str(ev.get(k, "")) for k in DEDUP_KEYS[cat]), ev)
    random.seed(0)
    with BENIGN.open("w") as out:
        for cat, events in seen.items():
            vals = list(events.values())
            sample = random.sample(vals, min(CAP, len(vals)))
            print(cat, "unique:", len(vals), "kept:", len(sample))
            for ev in sample:
                out.write(json.dumps({"category": cat, **ev}) + "\n")


if __name__ == "__main__":
    main()
