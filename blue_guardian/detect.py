"""The detector half of Blue Guardian: reads untrusted text (web pages, emails, documents, tool output) before an agent does,
and scores how likely it is to be a prompt injection.

HeuristicDetector is the starting point: readable rules, no download, microseconds per message. It is the baseline the
trained model (ModelDetector, see PASS_MARKS.md) must beat on held-out data before it ships.
"""
from __future__ import annotations

import json
import math
import re
import unicodedata
from dataclasses import dataclass, field
from pathlib import Path


@dataclass
class Detection:
    score: float                               # 0 = looks normal, 1 = almost certainly an attack
    flagged: bool
    reasons: list[str] = field(default_factory=list)


# (name, weight, pattern). Weights combine as independent signals: score = 1 - prod(1 - w).
RULES = [
    ("override", 0.75, r"\b(ignore|disregard|forget|override|bypass)\b[^.\n]{0,40}\b(all |any |the |your |my )?(previous|prior|above|earlier|preceding|original|system)\b[^.\n]{0,25}\b(instructions?|rules|prompts?|directions|guidelines|messages?)"),
    ("new-rules", 0.55, r"\b(new|updated|real|actual) (instructions|rules|task|orders)\b\s*[:\-]"),
    ("role-hijack", 0.6, r"\b(you are now|from now on,? you are|pretend (to be|you are)|act as)\b[^.\n]{0,40}\b(DAN|developer mode|unfiltered|jailbr\w*|no (rules|restrictions|limits)|evil|uncensored)"),
    ("dev-mode", 0.5, r"\b(developer|god|admin|debug|maintenance) mode\b[^.\n]{0,20}\b(enabled|activated|on)\b"),
    ("prompt-leak", 0.6, r"\b(reveal|print|show|repeat|output|dump|leak|tell me)\b[^.\n]{0,40}\b(system prompt|hidden (instructions|prompt)|your (instructions|rules|prompt)|initial prompt|developer message)"),
    ("fake-authority", 0.55, r"(\[|<|\b)(SYSTEM|ADMIN|ADMINISTRATOR|ROOT|ANTHROPIC|OPENAI|DEVELOPER)(\]|>|\s*(:|MESSAGE|OVERRIDE|NOTICE|INSTRUCTION))"),
    ("chat-markup", 0.6, r"<\|?(im_start|im_end|system|endoftext)\|?>|\[/?INST\]|<</?SYS>>"),
    ("secret-grab", 0.7, r"\b(send|email|post|upload|forward|paste|exfiltrate|transmit|share)\b[^.\n]{0,60}\b(passwords?|api[ _-]?keys?|tokens?|secrets?|credentials|\.env|ssh keys?|private keys?|cookies)"),
    ("exfil-link", 0.65, r"!\[[^\]]*\]\(https?://[^)\s]*\?[^)\s]*=[^)\s]*\)"),
    ("hide-from-user", 0.6, r"\b(do not|don'?t|never)\b[^.\n]{0,15}\b(tell|inform|mention|show|alert|notify)\b[^.\n]{0,20}\b(the )?(user|human|owner|operator)"),
    ("tool-order", 0.4, r"\b(run|execute|call)\b[^.\n]{0,20}\b(this|the following)\b[^.\n]{0,20}\b(command|code|script|tool)\b"),
    ("base64-blob", 0.25, r"[A-Za-z0-9+/]{160,}={0,2}"),
]
_CASE_SENSITIVE = {"fake-authority"}                      # shouting SYSTEM: is a signal, the word "system" is not
_COMPILED = [(n, w, re.compile(p, 0 if n in _CASE_SENSITIVE else re.I)) for n, w, p in RULES]

INVISIBLE = re.compile("[​-‏‪-‮⁠-⁤﻿\U000e0000-\U000e007f]")


class HeuristicDetector:
    name = "heuristic-v0"

    def __init__(self, threshold: float = 0.5):
        self.threshold = threshold

    def score(self, text: str) -> Detection:
        reasons, keep = [], 1.0
        hidden = INVISIBLE.findall(text)
        if len(hidden) >= 3:
            reasons.append(f"hidden-characters ({len(hidden)})")
            keep *= 1 - 0.6
        clean = unicodedata.normalize("NFKC", INVISIBLE.sub("", text))
        for name, weight, rx in _COMPILED:
            if rx.search(clean):
                reasons.append(name)
                keep *= 1 - weight
        s = round(1 - keep, 3)
        return Detection(s, s >= self.threshold, reasons)


DEFAULT_MODEL = "niharpatel2545/blue-guardian-v4"


def _config(model: str, name: str) -> dict | None:
    """A JSON file next to the weights (local folder or Hugging Face), or None."""
    cfg = Path(model) / name
    if not cfg.exists():
        try:
            from huggingface_hub import hf_hub_download
            cfg = Path(hf_hub_download(model, name))
        except Exception:
            return None
    return json.loads(cfg.read_text("utf-8"))


def _threshold(model: str) -> float:
    """The threshold train.py chose on the tune set (guardian.json next to the weights), else 0.5."""
    return float((_config(model, "guardian.json") or {}).get("threshold", 0.5))


def page_features(scores: list[float]) -> list[float]:
    """What the page rule reads from a long text's window scores (see PASS_MARKS.md, v6)."""
    s = sorted(scores, reverse=True)
    return [s[0], s[1] if len(s) > 1 else s[0], sum(s) / len(s), sum(x > 0.5 for x in s) / len(s), math.log(len(s))]


class ModelDetector:
    """A fine-tuned classifier (see PASS_MARKS.md). Needs `pip install blue-guardian[model]`. `model` is a local folder or a
    Hugging Face model id; the default downloads blue-guardian-v4 (about 600 MB) on first use."""
    name = "model"

    def __init__(self, model: str = DEFAULT_MODEL, threshold: float | None = None, device: str | int | None = None):
        try:
            import torch
            from transformers import pipeline
        except ImportError as e:
            raise RuntimeError("ModelDetector needs torch and transformers: pip install blue-guardian[model]") from e
        self.threshold = _threshold(model) if threshold is None else threshold
        self.page = _config(model, "page.json")       # v6+: one decision for a long text from all its window scores
        if device is None:
            device = 0 if torch.cuda.is_available() else "cpu"
        # half precision on the GPU: about 2x faster, same answers to 2 decimals; full precision on the CPU
        dtype = torch.float32 if device in ("cpu", -1) else torch.bfloat16
        self._clf = pipeline("text-classification", model=model, device=device, truncation=True, max_length=512, dtype=dtype)

    def score(self, text: str) -> Detection:
        """Long text (a web page, a file) is cut into overlapping windows and the most suspicious window decides, so an
        attack buried deep in a page is read too, not only the first few hundred words."""
        parts = windows(text)
        outs = self._clf(parts, batch_size=32)
        scores = [o["score"] if o["label"].lower() in ("injection", "attack", "1", "label_1") else 1 - o["score"] for o in outs]
        i = max(range(len(scores)), key=scores.__getitem__)
        if len(parts) > 1 and self.page:
            z = self.page["b"] + sum(w * f for w, f in zip(self.page["w"], page_features(scores)))
            p = 1 / (1 + math.exp(-z))
            return Detection(round(p, 3), p >= self.page["threshold"], [f"page rule over {len(parts)} windows",
                                                                         f"most suspicious: window {i + 1} ({scores[i]:.2f})"])
        reasons = [f"model:{outs[i]['label']}"] + ([f"window {i + 1} of {len(parts)}"] if len(parts) > 1 else [])
        return Detection(round(scores[i], 3), scores[i] >= self.threshold, reasons)


WINDOW, STEP = 1000, 800          # characters; 200 overlap so an attack cut at a boundary is whole in the next window


def windows(text: str) -> list[str]:
    if len(text) <= WINDOW:
        return [text]
    return [text[i:i + WINDOW] for i in range(0, len(text) - (WINDOW - STEP), STEP)]
