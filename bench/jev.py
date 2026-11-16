"""Small async client for the Jev decision model through OpenRouter, with a disk cache and a cost limit.

API contract (OpenRouter docs, read 2026-11-16): POST /api/alpha/decisions with model, state, questions.
A `noul` question returns {"type": "noul", "noul": <probability that the statement is true>}.
The key comes from the environment variable OPENROUTER_API_KEY. This code never prints it.
"""
import asyncio
import hashlib
import json
import os

import httpx

from .common import RESULTS

URL = "https://openrouter.ai/api/alpha/decisions"
MODEL = os.environ.get("JEV_MODEL", "typesafe/jev-1.14")
PRICE_PER_MTOK = 0.042  # USD for each million input tokens; output is free
CACHE = RESULTS / "cache" / "jev.jsonl"


class CostLimit(Exception):
    pass


class Jev:
    def __init__(self, max_cost, concurrency=12):
        key = os.environ.get("OPENROUTER_API_KEY")
        if not key:
            raise SystemExit("Set OPENROUTER_API_KEY in the environment first.")
        self.http = httpx.AsyncClient(headers={"Authorization": f"Bearer {key}"}, timeout=60)
        self.sem = asyncio.Semaphore(concurrency)
        self.max_cost, self.cost, self.tokens, self.calls = max_cost, 0.0, 0, 0
        CACHE.parent.mkdir(parents=True, exist_ok=True)
        self.cache = {}
        if CACHE.exists():
            for line in CACHE.open():
                row = json.loads(line)
                self.cache[row["k"]] = row["answers"]
        self.out = CACHE.open("a")

    async def close(self):
        self.out.close()
        await self.http.aclose()

    async def ask(self, state, questions):
        """Return {question name: probability or None}. None means refused or not answered."""
        body = {"model": MODEL, "state": state, "questions": questions}
        k = hashlib.sha256(json.dumps(body, sort_keys=True).encode()).hexdigest()
        if k in self.cache:
            return self.cache[k]
        async with self.sem:
            if self.cost >= self.max_cost:
                raise CostLimit(f"cost limit of ${self.max_cost} reached")
            for attempt in range(6):
                r = await self.http.post(URL, json=body)
                if r.status_code in (429, 500, 502, 503, 504):
                    await asyncio.sleep(2 ** attempt)
                    continue
                break
            if r.status_code != 200:
                # Keep the status only: an error body can repeat request details.
                raise RuntimeError(f"Jev request failed with HTTP {r.status_code}")
            data = r.json()
        usage = data.get("usage", {})
        self.tokens += usage.get("input_tokens", 0)
        self.cost += usage.get("cost") or usage.get("input_tokens", 0) * PRICE_PER_MTOK / 1e6
        self.calls += 1
        answers = {}
        for name in questions:
            a = data.get("answers", {}).get(name) or {}
            answers[name] = a.get("noul") if a.get("type") == "noul" else None
        self.cache[k] = answers
        self.out.write(json.dumps({"k": k, "answers": answers}) + "\n")
        self.out.flush()
        return answers
