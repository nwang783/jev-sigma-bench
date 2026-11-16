#!/bin/bash
# Get the public data. Run once from the repo root. About 400 MB on disk.
set -euo pipefail
mkdir -p data && cd data
# SigmaHQ rules with regression (true-positive) events.
[ -d sigma ] || git clone -q --depth 1 https://github.com/SigmaHQ/sigma sigma
# The Sigma evaluator and data loaders come from sigma-llm-bench (no license file: used here, not copied).
if [ ! -d sigma-llm-bench ]; then
  git clone -q https://github.com/Ayush-M99/sigma-llm-bench sigma-llm-bench
  git -C sigma-llm-bench checkout -q "${SIGBENCH_COMMIT:-HEAD}"
fi
# Their loaders look for data/sigma and data/baseline inside their own tree.
mkdir -p sigma-llm-bench/data baseline
ln -sfn "$PWD/sigma" sigma-llm-bench/data/sigma
ln -sfn "$PWD/baseline" sigma-llm-bench/data/baseline
cd baseline
for f in win10-client win11-client; do
  if [ ! -d "$f" ]; then
    curl -sSfLO "https://github.com/NextronSystems/evtx-baseline/releases/latest/download/$f.tgz"
    mkdir "$f" && tar -xzf "$f.tgz" -C "$f" && rm "$f.tgz"
  fi
done
echo "data ready"
