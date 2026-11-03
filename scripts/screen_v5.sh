#!/usr/bin/env bash
# v5 base-model screening (PASS_MARKS.md): same 30k-row sample, 1 epoch, each base; winner by tune-set catch at 2% false alarms.
# Skips a base whose folder already exists, so it can be re-run after an interruption.
cd "$(dirname "$0")/.."
PY=.venv/Scripts/python.exe
until [ -s data/v5_web_train.jsonl ] && [ -s data/browsesafe_test.jsonl ]; do sleep 30; done
for b in jhu-clsp/mmBERT-base jhu-clsp/ettin-encoder-400m answerdotai/ModernBERT-large; do
  n=screen-$(basename "$b")
  [ -f "models/$n/guardian.json" ] && continue
  $PY -I scripts/train.py --base "$b" --extra v5_web --sample 30000 --epochs 1 --out "models/$n" > "runs/$n.log" 2>&1
done
grep -h "catch_at_2pct\|threshold\|saved" runs/screen-*.log
