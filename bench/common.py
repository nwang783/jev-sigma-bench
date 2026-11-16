"""Shared data loading: attack events, benign events, and the compiled SigmaHQ rule set.

Attack events: SigmaHQ regression data (events recorded when the attack was run).
Benign events: Nextron evtx-baseline (clean Windows 10/11 installs), de-duplicated.
The Sigma evaluator and loaders are imported from sigma-llm-bench (see setup.sh).
"""
import functools
import json
import sys
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parent.parent
DATA = ROOT / "data"
RESULTS = ROOT / "results"
sys.path.insert(0, str(DATA / "sigma-llm-bench"))

from sigbench import matcher  # noqa: E402
from sigbench.data import CATEGORIES, flatten_event, load_cases  # noqa: E402,F401

# The evaluator compiles a regex on every comparison. Cache them: the full rule set runs millions of comparisons.
matcher._wildcard_regex = functools.lru_cache(maxsize=None)(matcher._wildcard_regex)

BENIGN = DATA / "baseline" / "benign.jsonl"


def attack_cases():
    """One case per SigmaHQ rule with regression data.

    A case keeps only the events that its own rule fires on: those are the labeled attack events.
    """
    out = []
    for c in load_cases():
        try:
            pred = matcher.compile_rule(c["rule"])
        except matcher.SigmaError:
            continue
        events = [e for e in c["events"] if pred(e)]
        if events:
            out.append({**c, "events": events, "pred": pred})
    return out


def benign_events():
    with BENIGN.open() as f:
        return [json.loads(line) for line in f]


def rule_set(folder="rules"):
    """SigmaHQ Windows rules in the four categories: {category: [(id, title, pred)]}.

    folder "rules" is the standard set. "rules-threat-hunting" is the noisy set made for hunting, not alerting.
    """
    rules = {c: [] for c in CATEGORIES}
    skipped = 0
    for p in sorted((DATA / "sigma" / folder / "windows").rglob("*.yml")):
        try:
            r = yaml.safe_load(p.read_text())
        except yaml.YAMLError:
            continue
        cat = (r or {}).get("logsource", {}).get("category") if isinstance(r, dict) else None
        if cat not in rules:
            continue
        try:
            rules[cat].append((r["id"], r.get("title", ""), matcher.compile_rule(r)))
        except matcher.SigmaError:
            skipped += 1
    return rules, skipped


def fired(rules, event, skip_id=None):
    """Ids of the rules that fire on the event."""
    hits = []
    for rid, _title, pred in rules:
        if rid == skip_id:
            continue
        try:
            if pred(event):
                hits.append(rid)
        except Exception:  # a rule that fails on one odd event must not stop the run
            continue
    return hits
