"""Builds blue-guardian-v6 from v5's weights (plan in PASS_MARKS.md, written before this ran):
  1. threshold from a wider tune set (tune.jsonl + 2,000 unused OR-Bench + 2,000 unused oasst2 prompts), 2% false alarms;
  2. page rule: logistic regression on window-score features, fitted on unused BrowseSafe train pages, threshold at 2%
     false alarms on other unused train pages.
    .venv\\Scripts\\python.exe -I scripts\\fit_v6.py
"""
import json
import shutil
import sys
from pathlib import Path

import numpy as np
import pandas as pd
from sklearn.linear_model import LogisticRegression

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
from blue_guardian.detect import ModelDetector, page_features, windows  # noqa: E402

RAW, DATA, V5, V6 = ROOT / "data" / "raw", ROOT / "data", ROOT / "models" / "blue-guardian-v5", ROOT / "models" / "blue-guardian-v6"


def clean(t):
    return " ".join(str(t).split())[:4000]


def thr_at_2pct(normal_scores):
    s = np.sort(np.asarray(normal_scores))[::-1]
    return float(max(0.5, s[int(0.02 * len(s))] + 1e-6))


def main():
    if not V6.exists():
        shutil.copytree(V5, V6)
    det = ModelDetector(str(V5), device=0)
    det.page = None
    attack = lambda outs: [o["score"] if o["label"].lower() in ("injection", "attack", "1", "label_1") else 1 - o["score"] for o in outs]

    # 1. threshold on a wider tune set (rows after the training caps in prepare_data.py's own shuffle, never trained on)
    seen = {json.loads(l)["text"] for f in ("train", "test", "fresh_test") for l in open(DATA / f"{f}.jsonl", encoding="utf-8")}
    oa = pd.concat([pd.read_parquet(RAW / f) for f in ("oasst2_train.parquet", "oasst2_val.parquet")])
    oa = oa[(oa.role == "prompter") & ~oa.deleted & (oa.review_result == True)]  # noqa: E712
    extra = [clean(t) for t in oa.text.sample(frac=1, random_state=7)[15000:17000]]
    extra += [clean(t) for t in pd.read_csv(RAW / "orbench_80k.csv").sample(frac=1, random_state=7)[15000:17000].prompt]
    extra = [t for t in dict.fromkeys(extra) if len(t) >= 3 and t not in seen]
    tune = [json.loads(l) for l in open(DATA / "tune.jsonl", encoding="utf-8")]
    normal = [r["text"] for r in tune if r["label"] == 0] + extra
    attacks = [r["text"] for r in tune if r["label"] == 1]
    ns, ats = np.array(attack(det._clf(normal, batch_size=64))), np.array(attack(det._clf(attacks, batch_size=64)))
    thr = thr_at_2pct(ns)
    (V6 / "guardian.json").write_text(json.dumps({"threshold": round(thr, 6)}), encoding="utf-8")
    print(f"threshold {thr:.4f} (v5 had 0.577): {len(normal)} tune normal texts ({len(extra)} new), "
          f"false alarms {(ns >= thr).mean():.1%}, tune attacks caught {(ats >= thr).mean():.1%}")

    # 2. page rule on BrowseSafe train pages that v5's window picking never used
    tr = pd.read_parquet(RAW / "browsesafe" / "train.parquet")
    used = set(tr[tr.label == "yes"].sample(2000, random_state=7).index) | set(tr[tr.label == "no"].sample(2000, random_state=7).index)
    free = tr.drop(index=list(used))
    pick = pd.concat([free[free.label == "yes"].sample(400, random_state=11), free[free.label == "no"].sample(400, random_state=11)])
    X, y = [], []
    for i, (page, label) in enumerate(zip(pick.content, pick.label)):
        X.append(page_features(attack(det._clf(windows(page), batch_size=64))))
        y.append(int(label == "yes"))
        if i % 100 == 0:
            print(i, "pages", flush=True)
    X, y = np.array(X), np.array(y)
    fit = np.r_[np.arange(0, 300), np.arange(400, 700)]          # 300 attack + 300 normal pages to fit
    hold = np.r_[np.arange(300, 400), np.arange(700, 800)]       # 100 + 100 pages to set the page threshold
    lr = LogisticRegression(max_iter=1000).fit(X[fit], y[fit])
    p = lr.predict_proba(X[hold])[:, 1]
    pthr = thr_at_2pct(p[y[hold] == 0])
    (V6 / "page.json").write_text(json.dumps({"w": [round(float(w), 6) for w in lr.coef_[0]], "b": round(float(lr.intercept_[0]), 6),
                                              "threshold": round(pthr, 6)}), encoding="utf-8")
    print(f"page rule: threshold {pthr:.4f}, held-out pages caught {(p[y[hold] == 1] >= pthr).mean():.1%}, "
          f"false alarms {(p[y[hold] == 0] >= pthr).mean():.1%}")
    print("saved", V6)


if __name__ == "__main__":
    main()
