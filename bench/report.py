"""Compare the Jev answers with the Sigma results. Run: uv run python -m bench.report"""
import json
from collections import defaultdict

from .common import RESULTS


def rate(xs):
    xs = list(xs)
    return sum(xs) / len(xs) if xs else float("nan")


def threshold_for_fpr(benign_scores, fpr):
    """Smallest threshold with a benign false positive rate at or below fpr."""
    s = sorted(benign_scores, reverse=True)
    k = int(fpr * len(s))
    return s[k] + 1e-9 if k < len(s) else 0.0


def main():
    rows = [json.loads(line) for line in (RESULTS / "jev.jsonl").open()]
    sigma = json.loads((RESULTS / "sigma.json").read_text())
    g = [r for r in rows if r.get("generic") is not None and r.get("role") == "main"]
    att = [r for r in g if r["kind"] == "attack"]
    ben = [r for r in g if r["kind"] == "benign"]
    print(f"GENERIC QUESTION: {len(att)} attack events, {len(ben)} benign events")
    print(f"  Sigma, full rule set:        recall {rate(r['sigma_any'] for r in att):.1%}  "
          f"benign FP {rate(r['sigma_any'] for r in ben):.2%}   (own rule included: true by construction)")
    print(f"  Sigma, own rule removed:     recall {rate(r['sigma_other'] for r in att):.1%}")
    bs = [r["generic"] for r in ben]
    for label, t in [("threshold 0.5", 0.5), ("FP at most 1%", threshold_for_fpr(bs, 0.01)),
                     ("FP at most 0.1%", threshold_for_fpr(bs, 0.001)),
                     ("FP equal to Sigma", threshold_for_fpr(bs, rate(r["sigma_any"] for r in ben)))]:
        missed = [r for r in att if not r["sigma_other"]]
        print(f"  Jev, {label:<18} (t={t:.3f}): recall {rate(r['generic'] >= t for r in att):.1%}  "
              f"benign FP {rate(b >= t for b in bs):.2%}  "
              f"recall on the {len(missed)} events that Sigma misses with the own rule removed: "
              f"{rate(r['generic'] >= t for r in missed):.1%}")
    # Area under the ROC curve: probability that an attack event scores above a benign event.
    order = sorted([(r["generic"], 1) for r in att] + [(b, 0) for b in bs])
    rank_sum, i = 0.0, 0
    while i < len(order):
        j = i
        while j < len(order) and order[j][0] == order[i][0]:
            j += 1
        rank_sum += sum(lab for _, lab in order[i:j]) * (i + j + 1) / 2
        i = j
    auc = (rank_sum - len(att) * (len(att) + 1) / 2) / (len(att) * len(bs)) if att and bs else float("nan")
    print(f"  Jev AUROC {auc:.3f}")
    print("  By log source at threshold 0.5 (recall / benign FP):")
    for cat in sorted({r["category"] for r in g}):
        print(f"    {cat:<18} {rate(r['generic'] >= .5 for r in att if r['category'] == cat):.1%} / "
              f"{rate(r['generic'] >= .5 for r in ben if r['category'] == cat):.2%}")

    print("\nCHANGED COMMAND LINES (process creation; share still detected)")
    for kind, m in sigma["mutations"].items():
        mm = [r for r in g if r["kind"] == "attack_" + kind]
        print(f"  {kind:<7} n={m['events']:<4} Sigma own rule {m['own_rule_recall']:.1%}  Sigma any rule {m['any_rule_recall']:.1%}  "
              f"Jev generic {rate(r['generic'] >= .5 for r in mm):.1%}  "
              f"Jev described {rate(r['described'] >= .5 for r in mm if r.get('described') is not None):.1%}")

    print("\nDESCRIBED QUESTION (Jev gets the rule title and description)")
    cases = defaultdict(lambda: {"att": [], "ben": [], "cross": []})
    for r in rows:
        if r.get("described") is None:
            continue
        if r["kind"] == "attack" and r["role"] == "main":
            cases[r["asked_case"]]["att"].append(r["described"])
        elif r["role"] == "benign_negative":
            cases[r["asked_case"]]["ben"].append(r["described"])
        elif r["role"] == "cross_negative":
            cases[r["asked_case"]]["cross"].append(r["described"])
    cs = [c for c in cases.values() if c["att"] and c["ben"]]
    detects = [max(c["att"]) >= .5 for c in cs]
    noisy = [rate(b >= .5 for b in c["ben"]) > .01 for c in cs]
    print(f"  {len(cs)} cases: detects its attack {rate(detects):.1%}, fires on more than 1% of the benign sample {rate(noisy):.1%}, "
          f"both good {rate(d and not n for d, n in zip(detects, noisy)):.1%}")
    print(f"  Fires on a benign event: {rate(b >= .5 for c in cs for b in c['ben']):.2%}")
    print(f"  Fires on an attack event of a DIFFERENT rule (hard negatives): {rate(x >= .5 for c in cs for x in c['cross']):.1%}"
          "   (some different rules describe overlapping behavior, so this is an upper bound on the error)")

    print("\nSIGMA THEN JEV (Jev sees only events where a standard or hunting rule fired)")
    f = [r for r in rows if r.get("filter") is not None]
    tp = [r["filter"] for r in f if r["kind"] == "attack"]
    fp = [r["filter"] for r in f if r["kind"] == "benign"]
    print(f"  {len(tp)} true alerts, {len(fp)} false alerts from {len({r['alert'] for r in f if r['kind'] == 'benign'})} rules")
    for t in (0.5, 0.2, 0.1, 0.05):
        print(f"  pass to an analyst if p >= {t}: true alerts kept {rate(x >= t for x in tp):.1%}, "
              f"false alerts removed {rate(x < t for x in fp):.1%}")
    by_rule = defaultdict(list)
    for r in f:
        if r["kind"] == "benign":
            by_rule[r["alert"]].append(r["filter"])
    for title, xs in sorted(by_rule.items(), key=lambda kv: -len(kv[1]))[:8]:
        print(f"    {len(xs):>4} false alerts from '{title}': removed at 0.5 {rate(x < .5 for x in xs):.0%}")

if __name__ == "__main__":
    main()
