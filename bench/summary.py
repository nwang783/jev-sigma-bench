"""Write results/summary.json: the headline numbers, with benign rates weighted back to the full benign set.

The generic question ran on every benign event that has a Sigma alert and on a sample of the others, so
each sampled event counts for the events it stands for. Run: uv run python -m bench.summary
"""
import json
from collections import Counter

from .common import RESULTS


def main():
    rows = [json.loads(line) for line in (RESULTS / "jev.jsonl").open()]
    sigma = json.loads((RESULTS / "sigma.json").read_text())
    pop, pop_alert = Counter(), Counter()
    for line in (RESULTS / "events.jsonl").open():
        r = json.loads(line)
        if r["kind"] == "benign":
            pop[r["category"]] += 1
            pop_alert[r["category"]] += r["alert"] is not None
    g = [r for r in rows if r.get("generic") is not None and r["role"] == "main"]
    att = [r for r in g if r["kind"] == "attack"]
    ben = [r for r in g if r["kind"] == "benign"]
    sampled = Counter(r["category"] for r in ben if r["alert"] is None)

    def w(r):
        return 1.0 if r["alert"] is not None else (pop[r["category"]] - pop_alert[r["category"]]) / sampled[r["category"]]

    total = sum(w(r) for r in ben)

    def fp(t):
        return sum(w(r) for r in ben if r["generic"] >= t) / total

    sigma_fp = sigma["benign_result"]["any_rule_false_positive_rate"]
    t = next(x for x in sorted({r["generic"] for r in ben}) + [1.01] if fp(x) <= sigma_fp)
    described = {}
    for kind in sigma["mutations"]:
        xs = [r["described"] for r in rows if r["kind"] == "attack_" + kind and r.get("described") is not None]
        described[kind] = sum(x >= .5 for x in xs) / len(xs)
    out = {
        "attack_events": len(att), "benign_events": int(total),
        "no_rule": {"sigma_fp": sigma_fp, "sigma_recall": sigma["attack"]["leave_own_rule_out_recall"],
                    "jev_threshold": t, "jev_fp": fp(t), "jev_recall": sum(r["generic"] >= t for r in att) / len(att),
                    "both_recall": sum(r["sigma_other"] or r["generic"] >= t for r in att) / len(att),
                    "jev_recall_at_half": sum(r["generic"] >= .5 for r in att) / len(att), "jev_fp_at_half": fp(.5)},
        "changed_text": {k: {"n": m["events"], "sigma_own_rule": m["own_rule_recall"], "jev_described": described[k]}
                         for k, m in sigma["mutations"].items()},
    }
    (RESULTS / "summary.json").write_text(json.dumps(out, indent=2))
    print(json.dumps(out, indent=2))


if __name__ == "__main__":
    main()
