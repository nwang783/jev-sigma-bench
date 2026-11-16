"""Sigma arm: how the full SigmaHQ rule set does on the attack events, the benign events, and the changed attack events.

Run: uv run python -m bench.sigma_arm
Writes results/sigma.json and results/events.jsonl (the event list that the Jev arm scores).
"""
import hashlib
import json
from collections import Counter

from .common import RESULTS, attack_cases, benign_events, fired, rule_set
from .mutate import MUTATIONS, mutate


def eid(obj):
    return hashlib.sha256(json.dumps(obj, sort_keys=True).encode()).hexdigest()[:16]


def main():
    RESULTS.mkdir(exist_ok=True)
    cases = attack_cases()
    rules, skipped = rule_set()
    hunt, _ = rule_set("rules-threat-hunting")
    titles = {rid: t for rs in list(rules.values()) + list(hunt.values()) for rid, t, _ in rs}

    def alert(category, event, own=None):
        """Title of one rule (standard set first, then hunting set) that fires, for the Sigma-then-Jev arm."""
        hits = fired(rules[category], event) or fired(hunt[category], event)
        if own in hits:
            return titles[own]
        return titles[hits[0]] if hits else None
    benign = benign_events()
    out = {"rules": {c: len(r) for c, r in rules.items()}, "rules_unsupported": skipped,
           "cases": dict(Counter(c["category"] for c in cases)),
           "benign": dict(Counter(b["category"] for b in benign))}
    events = []  # one row per event that the Jev arm will score

    # 1. Attack events: own rule (true by construction), any rule, any rule except the own rule.
    n = any_hit = loo_hit = 0
    by_cat = Counter()
    by_cat_loo = Counter()
    for c in cases:
        for i, e in enumerate(c["events"]):
            hits = fired(rules[c["category"]], e)
            others = [h for h in hits if h != c["id"]]
            n += 1
            any_hit += bool(hits)
            loo_hit += bool(others)
            by_cat[c["category"]] += 1
            by_cat_loo[c["category"]] += bool(others)
            events.append({"eid": eid(e), "kind": "attack", "case": c["id"], "category": c["category"], "event": e,
                           "sigma_any": bool(hits), "sigma_other": bool(others),
                           "hunt": bool(fired(hunt[c["category"]], e)), "alert": alert(c["category"], e, c["id"])})
    out["attack"] = {"events": n, "any_rule_recall": any_hit / n, "leave_own_rule_out_recall": loo_hit / n,
                     "leave_own_rule_out_by_category": {k: by_cat_loo[k] / by_cat[k] for k in by_cat}}

    # 2. Benign events: share that any rule fires on.
    fp = Counter()
    noisy = Counter()
    for b in benign:
        ev = {k: v for k, v in b.items() if k != "category"}
        hits = fired(rules[b["category"]], ev)
        fp[b["category"]] += bool(hits)
        noisy.update(hits)
        events.append({"eid": eid(ev), "kind": "benign", "case": None, "category": b["category"], "event": ev,
                       "sigma_any": bool(hits), "sigma_other": bool(hits),
                       "hunt": bool(fired(hunt[b["category"]], ev)), "alert": alert(b["category"], ev)})
    out["benign_result"] = {
        "events": len(benign), "any_rule_false_positive_rate": sum(fp.values()) / len(benign),
        "by_category": {k: fp[k] / v for k, v in out["benign"].items()},
        "rules_that_fired": len(noisy),
        "top_noisy_rules": [{"title": titles[r], "hits": h} for r, h in noisy.most_common(8)]}

    # 3. Changed attack events (process creation only): does the own rule still fire? Does any rule?
    out["mutations"] = {}
    for kind in MUTATIONS:
        tot = own = anyr = 0
        for c in cases:
            if c["category"] != "process_creation":
                continue
            for e in c["events"]:
                m = mutate(e, kind)
                if m is None:
                    continue
                hits = fired(rules[c["category"]], m)
                tot += 1
                own += c["id"] in hits
                anyr += bool(hits)
                events.append({"eid": eid(m), "kind": "attack_" + kind, "case": c["id"], "category": c["category"],
                               "event": m, "sigma_any": bool(hits), "sigma_other": c["id"] in hits,
                               "hunt": False, "alert": None})
        out["mutations"][kind] = {"events": tot, "own_rule_recall": own / tot, "any_rule_recall": anyr / tot}

    b = [r for r in events if r["kind"] == "benign"]
    a = [r for r in events if r["kind"] == "attack"]
    out["hunting_rules"] = {"rules": {c: len(r) for c, r in hunt.items()},
                            "benign_events_hit": sum(r["hunt"] for r in b), "attack_events_hit": sum(r["hunt"] for r in a),
                            "benign_events_with_any_alert": sum(r["alert"] is not None for r in b)}
    (RESULTS / "sigma.json").write_text(json.dumps(out, indent=2))
    with (RESULTS / "events.jsonl").open("w") as f:
        for row in events:
            f.write(json.dumps(row) + "\n")
    print(json.dumps(out, indent=2))


if __name__ == "__main__":
    main()
