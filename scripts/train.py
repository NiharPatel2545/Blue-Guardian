"""Fine-tunes a small open model (ModernBERT-base) to tell injections from normal text, on the train set only.
The tune set picks the best epoch; the test set is not touched here (scripts/score.py does that once).
    .venv\\Scripts\\python.exe -I scripts\\train.py [--epochs 3] [--max-len 256] [--out models/blue-guardian-v1]
"""
import argparse
import json
import random
from pathlib import Path

import numpy as np
import torch
from datasets import Dataset
from transformers import (AutoModelForSequenceClassification, AutoTokenizer, DataCollatorWithPadding, Trainer,
                          TrainingArguments)

ROOT = Path(__file__).resolve().parent.parent


def load(*names, sample=0):
    rows = [json.loads(line) for n in names for line in open(ROOT / "data" / f"{n}.jsonl", encoding="utf-8")]
    if sample and sample < len(rows):
        rows = random.Random(7).sample(rows, sample)          # the same sample for every base
    return Dataset.from_dict({"text": [r["text"] for r in rows], "label": [r["label"] for r in rows]})


def catch_at_fpr(scores, labels, fpr=0.02):
    """Share of attacks caught at the threshold that keeps false alarms on normal text at or below fpr."""
    ben = np.sort(scores[labels == 0])[::-1]
    thr = ben[int(fpr * len(ben))] if len(ben) else 0.5
    return float((scores[labels == 1] > thr).mean()) if (labels == 1).any() else 0.0


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--base", default="answerdotai/ModernBERT-base")
    ap.add_argument("--epochs", type=float, default=3)
    ap.add_argument("--max-len", type=int, default=256)
    ap.add_argument("--batch", type=int, default=16)
    ap.add_argument("--lr", type=float, default=3e-5)
    ap.add_argument("--out", default=str(ROOT / "models" / "blue-guardian-v1"))
    ap.add_argument("--extra", help="extra data prefix: adds data/<prefix>_train.jsonl and data/<prefix>_tune.jsonl")
    ap.add_argument("--sample", type=int, default=0, help="train on a fixed random sample of this many rows (screening)")
    a = ap.parse_args()

    tok = AutoTokenizer.from_pretrained(a.base)
    extra = [a.extra] if a.extra else []
    train = load("train", *[f"{e}_train" for e in extra], sample=a.sample)
    tune = load("tune", *[f"{e}_tune" for e in extra])
    enc = lambda b: tok(b["text"], truncation=True, max_length=a.max_len)
    train, tune = train.map(enc, batched=True, remove_columns=["text"]), tune.map(enc, batched=True, remove_columns=["text"])
    model = AutoModelForSequenceClassification.from_pretrained(a.base, num_labels=2, id2label={0: "normal", 1: "injection"},
                                                               label2id={"normal": 0, "injection": 1})

    def metrics(p):
        logits, labels = p
        probs = torch.softmax(torch.tensor(logits, dtype=torch.float32), -1)[:, 1].numpy()
        pred = probs >= 0.5
        return {"accuracy": float((pred == labels).mean()), "catch": float(pred[labels == 1].mean()),
                "false_alarms": float(pred[labels == 0].mean()), "catch_at_2pct": catch_at_fpr(probs, labels)}

    args = TrainingArguments(
        output_dir=str(ROOT / "runs" / Path(a.out).name), num_train_epochs=a.epochs, learning_rate=a.lr, per_device_train_batch_size=a.batch,
        per_device_eval_batch_size=64, eval_strategy="epoch", save_strategy="epoch", save_total_limit=1, load_best_model_at_end=True,
        metric_for_best_model="catch_at_2pct", greater_is_better=True, weight_decay=0.01,
        warmup_steps=int(0.06 * len(train) / a.batch * a.epochs),          # warm up over the first 6% of steps
        bf16=torch.cuda.is_available(), logging_steps=50, report_to=[], seed=7)
    trainer = Trainer(model=model, args=args, train_dataset=train, eval_dataset=tune, data_collator=DataCollatorWithPadding(tok),
                      compute_metrics=metrics)
    trainer.train()
    print("tune set:", json.dumps(trainer.evaluate(), indent=1))
    trainer.save_model(a.out)
    tok.save_pretrained(a.out)
    # threshold that keeps false alarms on the tune set's normal text at 2% or less; ModelDetector reads it
    p = trainer.predict(tune)
    probs = torch.softmax(torch.tensor(p.predictions, dtype=torch.float32), -1)[:, 1].numpy()
    ben = np.sort(probs[p.label_ids == 0])[::-1]
    thr = float(max(0.5, ben[int(0.02 * len(ben))] + 1e-6))
    (Path(a.out) / "guardian.json").write_text(json.dumps({"threshold": round(thr, 6)}), encoding="utf-8")
    print("threshold", thr)
    print("saved", a.out)


if __name__ == "__main__":
    main()
