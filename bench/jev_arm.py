"""Jev arm: ask Jev about the same events that the Sigma arm scored. Jev sees scrubbed events (see scrub.py).

Three questions:
  generic   - "is this event malicious?" with no knowledge of any rule. Compare with Sigma when the
              attack's own rule is removed (an attack that no one wrote a rule for).
  described - "does this event show <rule title and description>?" Negatives are benign events and
              attack events of OTHER rules from the same log source (hard negatives: similar tools,
              different behavior).
  filter    - asked only where a Sigma rule fired: "rule X fired; is this a real attack?" This is the
              Sigma-then-Jev cascade. Positives are attack events, negatives are benign events that fire a
              standard or hunting rule.

Run: uv run python -m bench.jev_arm --pilot      (300 requests, to check the API and the cost)
     uv run python -m bench.jev_arm              (full run)
Writes results/jev.jsonl.
"""
import argparse
import asyncio
import json
import random

from .common import RESULTS, attack_cases
from .jev import MODEL, PRICE_PER_MTOK, CostLimit, Jev
from .scrub import scrub

INTRO = "This is one Windows event from a security log. "
GENERIC = (INTRO + "Is this event evidence of malicious activity: an attack technique, attacker tooling, or abuse of "
           "a system tool by an intruder? Answer false for normal operating system, software, user, or "
           "administrator activity.")
FIELD_LIMIT = 4000  # characters; long PowerShell script blocks are cut


def noul(text):
    return {"type": "noul", "instructions": text}


def state_of(row):
    ev = {k: (v[:FIELD_LIMIT] if isinstance(v, str) else v) for k, v in scrub(row["event"]).items()}
    return json.dumps({"log_source": row["category"], "event": ev}, ensure_ascii=False)


def described(case):
    r = case["rule"]
    return (INTRO + "Does this event show the following behavior? "
            f"{r.get('title', '')}. {' '.join(str(r.get('description', '')).split())}")


def filter_q(title):
    return (INTRO + f'A detection rule named "{title}" fired on this event. Is this event part of a real attack or '
            "of attack preparation? Answer false if it is normal system, software, or administrator activity that "
            "only happens to match the rule.")


def plan(args):
    """Return jobs: (event row, questions, case id that the described question is about, role of the row)."""
    rows = [json.loads(line) for line in (RESULTS / "events.jsonl").open()]
    rnd = random.Random(0)
    cases = {c["id"]: c for c in attack_cases()}
    attack = [r for r in rows if r["kind"] == "attack"]
    changed = [r for r in rows if r["kind"].startswith("attack_")]
    benign = [r for r in rows if r["kind"] == "benign"]
    by_cat, attack_by_cat = {}, {}
    for b in benign:
        by_cat.setdefault(b["category"], []).append(b)
    for a in attack:
        attack_by_cat.setdefault(a["category"], []).append(a)
    jobs = []
    # Generic on benign: a sample for each log source, plus every benign event with a Sigma alert (with the filter question).
    sample = {b["eid"] for bs in by_cat.values() for b in rnd.sample(bs, min(args.benign_per_category, len(bs)))}
    for b in benign:
        if b["alert"]:
            jobs.append((b, {"generic": noul(GENERIC), "filter": noul(filter_q(b["alert"]))}, None, "main"))
        elif b["eid"] in sample:
            jobs.append((b, {"generic": noul(GENERIC)}, None, "main"))
    # Attack events: all three questions. Changed attack events: generic and described.
    for r in attack:
        qs = {"generic": noul(GENERIC), "described": noul(described(cases[r["case"]])), "filter": noul(filter_q(r["alert"]))}
        jobs.append((r, qs, r["case"], "main"))
    for r in changed:
        jobs.append((r, {"generic": noul(GENERIC), "described": noul(described(cases[r["case"]]))}, r["case"], "main"))
    # Described question negatives for each case: benign events, and attack events of other cases.
    for cid, c in cases.items():
        cat = c["category"]
        for b in rnd.sample(by_cat[cat], min(args.benign_per_case, len(by_cat[cat]))):
            jobs.append((b, {"described": noul(described(c))}, cid, "benign_negative"))
        others = [a for a in attack_by_cat[cat] if a["case"] != cid]
        for a in rnd.sample(others, min(args.cross_per_case, len(others))):
            jobs.append((a, {"described": noul(described(c))}, cid, "cross_negative"))
    if args.pilot:
        jobs = rnd.sample(jobs, 300)
    return jobs


async def run(args):
    jobs = plan(args)
    chars = sum(len(state_of(r)) + sum(len(q["instructions"]) for q in qs.values()) for r, qs, _, _ in jobs)
    est = chars / 3.5 * PRICE_PER_MTOK / 1e6
    print(f"{len(jobs)} requests, model {MODEL}, estimated cost ${est:.2f} (limit ${args.max_cost})")
    if args.dry_run:
        return
    if est > args.max_cost:
        raise SystemExit("The estimate is above the limit. Decrease the samples or increase --max-cost.")
    jev = Jev(args.max_cost)
    out = (RESULTS / "jev.jsonl").open("w")
    done = 0

    async def one(row, qs, cid, role):
        nonlocal done
        try:
            ans = await jev.ask(state_of(row), qs)
        except CostLimit:
            return
        out.write(json.dumps({"eid": row["eid"], "kind": row["kind"], "category": row["category"], "case": row["case"],
                              "asked_case": cid, "role": role, "sigma_any": row["sigma_any"],
                              "sigma_other": row["sigma_other"], "hunt": row["hunt"], "alert": row["alert"], **ans}) + "\n")
        done += 1
        if done % 2000 == 0:
            print(f"  {done}/{len(jobs)}  ${jev.cost:.3f}", flush=True)

    try:
        await asyncio.gather(*(one(*j) for j in jobs))
    finally:
        out.close()
        await jev.close()
    print(f"done: {done} answers, {jev.calls} new calls, {jev.tokens} input tokens, ${jev.cost:.3f}")


if __name__ == "__main__":
    p = argparse.ArgumentParser()
    p.add_argument("--pilot", action="store_true")
    p.add_argument("--dry-run", action="store_true", help="print the request count and cost estimate, call nothing")
    p.add_argument("--benign-per-category", type=int, default=4000)
    p.add_argument("--benign-per-case", type=int, default=30)
    p.add_argument("--cross-per-case", type=int, default=30)
    p.add_argument("--max-cost", type=float, default=5.0)
    asyncio.run(run(p.parse_args()))
