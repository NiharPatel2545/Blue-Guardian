# Pass marks

Written before any model is trained. A detector ships only if it meets every mark on data it never saw during training
or tuning. Misses are published along with the wins.

## Test data rules

- Train, tune and test sets come from **different sources** (different datasets or collections), not a random split of one
  set, so the score reflects attacks the model has not seen.
- Normal text includes hard cases: everyday messages that mention "ignore", "instructions", "system" or "password" in a
  harmless way, security discussions, and code. A guard that flags these interrupts real users.
- The test set is used once per candidate. Anything used to choose a threshold or a model is a tuning set, not a test set.

## Data for v1 (fixed before download, 30 Oct 2026)

| Set | Sources (licence) | Used for |
|---|---|---|
| Train | SPML Chatbot Prompt Injection (MIT); jailbreak-classification train split (Apache-2.0); LLMail-Inject phase-2 labelled submissions, attacks hidden in emails (MIT); Dolly-15k instructions and context passages as normal text (CC BY-SA 3.0) | fitting the model |
| Tune | jailbreak-classification test split (Apache-2.0) | choosing epochs and the threshold only |
| Test (held out, sources never seen in training) | deepset prompt-injections, all splits (Apache-2.0); Lakera Gandalf ignore-instructions (MIT, attacks only); LLMail-Inject emails for false-positive tests (MIT, normal emails) | the marks below, once per candidate |

Prompt Guard 2 is scored on the same test set when access to it is granted (Mark 1 waits for that).

## Marks for the first trained detector (v1)

| # | Mark | Why |
|---|---|---|
| 1 | At no more than 2% false alarms on normal text, catches at least 5 points more attacks than Meta's Prompt Guard 2 (86M) on the same held-out test set | The point of the project: fewer interruptions for the same or better protection |
| 2 | Beats the rules-only `HeuristicDetector` by at least 15 points of catch rate at the same false-alarm rate | Otherwise the model is not worth its weight |
| 3 | No more than 3% false alarms on the hard-normal set | Real users must not be blocked for normal sentences |
| 4 | Under 20 ms per message on the RTX 5070 Ti laptop GPU, under 150 ms on a laptop CPU | It sits in front of every message an agent reads |
| 5 | Results reported per source and per attack type, including every type where it is worse than the baseline | Honest claims only |

## Results

**Baseline, heuristic-v0 (test set):** catches 31.0% of attacks, 0 of 559 normal texts flagged. deepset 5.7%, Gandalf 37.7%.

**v1, ModernBERT-base, 3 epochs (test set, 30 Oct 2026): FAILED marks 1-4.** Catches 71.2% of attacks (deepset 52.1%,
Gandalf 76.2%) but false alarms are 34.3%: all 160 normal emails flagged, 8% of deepset's normal texts. Catch rate at 2%
false alarms: 0. 26 ms per text on the GPU. Cause: every email in the training data was an attack, so the model learned
"email = attack". Tune set (same family as training) looked perfect (99% caught, 1.6% false alarms), which is why the
held-out test matters.

**v2 change (written before v2 ran):** add the 2,500 LLMail-Inject phase-2 emails its judges marked as not attacks to the
training set as normal text, and cap attack emails at 2,500 so emails carry no label signal on their own. Everything else
unchanged. Same test set, scored once.

**v2 result (test set, 30 Oct 2026):** catches 67.2% of attacks with 3.6% false alarms (0 of 160 normal emails, 5.0% of
deepset's normal texts). At 2% false alarms it catches 61.6%, against 31.3% for the heuristic. 24 ms per text on the GPU.
- Mark 1 (vs Prompt Guard 2): not yet scored, needs access to the model.
- Mark 2 (beat the heuristic by 15+ points at the same false-alarm rate): **passed**, +30.3 points.
- Mark 3 (no more than 3% false alarms on hard normal text): **failed narrowly**, 3.6% overall, 5.0% on deepset.
- Mark 4 (under 20 ms per message on the GPU): **failed narrowly**, 24 ms.
- Weakest spot: deepset (44% caught). Part of it is German, and ModernBERT-base is English-only.

The test set has now been used for two candidates. Before v3, add a fresh held-out source so later choices are not tuned to it.

**v3 plan (written 30 Oct 2026, before any v3 data was built or model trained):**
- Base model: mmBERT-base (multilingual ModernBERT, MIT) instead of the English-only ModernBERT-base.
- Training additions: yanismiraoui prompt_injections (Apache-2.0, 7 languages) and neuralchemy Prompt-injection-dataset
  (Apache-2.0). Everything else as v2.
- New **fresh test set**, never used before: ShieldLM prompt-injection test split (MIT, 8 languages) and S-Labs
  prompt-injection test split (MIT). Any text that also appears in training is removed from training.
  Amended before building: ShieldLM is compiled from other datasets, three of which are in our training data and one in
  the old test, so only its rows from other sources are kept (alespalla chatbot prompts, safeguard, harelix mixed
  techniques, in-the-wild jailbreaks, InjecAgent, JailbreakBench). S-Labs does not list its sources, so exact duplicates
  of training text are removed; near-duplicates may remain.
- v3 is judged on the fresh test set (the honest number) and also reported on the old test set for comparison with v2.
- Ship v3 over v2 only if, on the fresh set, its catch rate at 2% false alarms is at least 5 points higher than v2's on the
  same fresh set, and its false alarms at the default threshold are no higher than v2's.

## Marks for the rules half (policy and gateway)

Met by `tests/test_blue_guardian.py` (6 tests): unknown tools blocked, paths cannot escape allowed folders, only listed websites,
forbidden command patterns blocked, approval for "ask" tools, rate and spending caps, kill switch, taint after a suspected
injection, and a full audit log.

**v3 result and comparison (30 Oct 2026, scored once).** Catch rate at 2% false alarms / false alarms at the default threshold:

| | Fresh test (7,601 rows) | Old test (1,822 rows) |
|---|---|---|
| heuristic-v0 | 5.6% / 0.0% | 31.3% / 0.0% |
| v2 | 36.0% / 2.5% | 61.6% / 3.6% |
| v3 | 45.1% / 10.8% | 97.0% / 1.1% |
| ProtectAI deberta-v3 prompt-injection v2 | 83.4% / 0.1% | 91.4% / 0.7% |

- v3 vs v2 on the fresh set: +9.1 points at 2% false alarms (mark: +5, met) but false alarms at the default threshold rose
  from 2.5% to 10.8% (mark: no higher, **failed**). v3 does not replace v2 as the default; its threshold would need raising.
- The industry baseline (ProtectAI) is far ahead on the fresh set: 83% caught at almost no false alarms. Its training data
  is not fully published, so it may have seen some of these sources; the old test likely overlaps its training data, so the
  fresh set is the fairer comparison. Honest position: we are well behind on unseen data.
- Next: more and more varied normal text (v3's false alarms are on everyday chatbot prompts and JailbreakBench's harmless
  requests), and agent-style indirect attacks (InjecAgent 46%, harelix 51%).

**v4 plan (written 30 Oct 2026, before any v4 data was downloaded or model trained):**
- Base model: mmBERT-base, same settings as v3.
- Training additions, normal text: OpenAssistant oasst2 user prompts, all languages (Apache-2.0), up to 15,000; OR-Bench 80k,
  harmless requests that sound risky (CC BY 4.0), up to 15,000; XSTest safe prompts (CC BY 4.0).
- Training additions, attacks: Lakera Mosscap prompt-injection game (MIT), up to 10,000; Lakera Gandalf summarization,
  attacks hidden inside text to summarise (MIT). Gandalf is the same game family as the old test, so the old test gets
  less fair for v4; the fresh set is the one that decides.
- New tune set: 10% of each new source, held out of training, plus the old tune set. The threshold is the one that keeps
  false alarms at 2% or less on the tune set's normal text. The fresh test is not used to choose anything.
- Honest note: the choice of these sources was informed by v3's mistakes on the fresh set (everyday chatbot prompts,
  harmless requests), so the fresh set is now partly seen. v5 needs another never-used test source.
- Ship v4 as the default only if, on the fresh set, (1) its catch rate at 2% false alarms is at least 5 points above v3's
  45.1%, and (2) its false alarms at the chosen threshold are no higher than v2's 2.5%. Reported per source either way.

**v4 result (30 Oct 2026, scored once).** The tune-set threshold came out at 0.5 (2% false alarms on the tune set was already
below 0.5). Catch rate at 2% false alarms / false alarms at the threshold:

| | Fresh test (7,601 rows) | Old test (1,822 rows) |
|---|---|---|
| v2 | 36.0% / 2.5% | 61.6% / 3.6% |
| v3 | 45.1% / 10.8% | 97.0% / 1.1% |
| **v4** | **76.5% / 2.1%** | 89.9% / 0.9% |
| ProtectAI deberta-v3 prompt-injection v2 | 83.4% / 0.1% | 91.4% / 0.7% |

- Ship mark (1) +5 points over v3 at 2% false alarms: **passed**, +31.4. Mark (2) false alarms no higher than v2's 2.5%:
  **passed**, 2.1%. v4 replaces v2 as the default.
- First-model marks: mark 2 (beat the heuristic by 15+): passed. Mark 3 (no more than 3% false alarms on hard normal text):
  passed on both sets (deepset 1.3%, everyday chatbot prompts 2.1%). Mark 4 (under 20 ms on the GPU): passed, 14.7 ms. Mark 1
  (Prompt Guard 2) still not scored.
- Per source on the fresh set: S-Labs 84.9% caught / 1.4% false alarms, safeguard 87.8% / 2.4%, in-the-wild jailbreaks 92.0%,
  JailbreakBench harmless requests 18.5% false alarms (5 of 27).
- **Worse than v3 on agent attacks**: InjecAgent 21.5% caught, harelix mixed techniques 21.9%. Attacks hidden in tool output
  are the weak spot. Old-test deepset dropped to 35% (part German).
- Still 7 points behind ProtectAI on the fresh set, with more false alarms (2.1% vs 0.1%). The fresh set was partly seen when
  choosing v4's data (see the v4 plan), so treat 76.5% as an upper bound until a never-used test source is scored.

## v5 plan (written 4 Nov 2026, before any v5 data was built or model trained)

Goal: fix the weak spot (attacks hidden in tool output: web pages, emails, files) and pick the best base model.

- **Bake-off, same data and settings for all:** jhu-clsp/ettin-encoder-400m (MIT), answerdotai/ModernBERT-large (Apache-2.0),
  and mmBERT-base (MIT, the v4 base, as the control so we can tell what the data did and what the base did). Max length 256.
- **Training addition:** BrowseSafe-Bench train split (Perplexity, MIT): 11,039 HTML pages, half with a hidden injection. The
  pages are long (median 47k characters) and the dataset does not mark where the injection sits, so each page is cut into
  windows; from an attack page the window that v4 and ProtectAI together score highest is the attack example; from a normal
  page its highest-scoring window (a hard normal case) and one random window. 10% of pages go to the tune set.
- **Long text in the product:** `inspect` scores overlapping windows and uses the highest score, so a whole page or file is
  checked, not only its first 256 tokens.
- **New never-used test, different source: AgentDojo** (ETH Zurich, MIT), v1 suites (workspace, travel, banking, slack).
  Normal = every tool-output item (email, calendar event, file, web page, message, review) with its injection slots filled
  with the suite's own harmless default text. Attacks = the same items with one slot filled by one of AgentDojo's six
  published attack templates (important_instructions, tool_knowledge without the tool list, ignore_previous, direct,
  system_message, injecagent) around each suite's injection goals.
- **In-family test:** BrowseSafe-Bench test split, 600 pages sampled (300 attack, 300 normal), page score = highest window.
  Reported, but it is the same family as the training data, so AgentDojo is the honest number.
- **Screening (time-boxed):** each base trains 1 epoch on the same 30k-row sample; the winner is chosen by catch rate at 2%
  false alarms on the tune set only. The winner then trains fully (3 epochs, all data). The test sets are scored once, on
  the final candidate, with v4 and ProtectAI scored alongside (baselines, they choose nothing).

**v5 ship marks:**
1. AgentDojo test: catch rate at 2% false alarms at least **20 points above v4's** and at least **50%**.
2. Fresh test (v3/v4's): catch rate at 2% false alarms no more than 2 points below v4's 76.5%; false alarms at the chosen
   threshold no higher than 2.5%.
3. BrowseSafe test (in-family): catch rate at 2% false alarms at least 20 points above v4's.
4. Under 20 ms per 256-token window on the RTX 5070 Ti laptop GPU.
5. Results per source and per attack template, including every place it is worse than v4 or ProtectAI.

**v5 amendments (4 Nov 2026, before any v5 model was trained or anything was scored on the v5 tests):**
- AgentDojo test built: 2,358 rows, 2,136 attacks (356 per template), 222 normal. Besides whole items, each long text field
  (an email body, a web page, a file) also counts as its own tool output, since many tools return just that. With 222
  normal items the AgentDojo false-alarm rate is coarse (1 item = 0.45 points); the fresh test (5,725 normal texts)
  stays the main false-alarm check.
- BrowseSafe training uses 4,000 of the 11,039 training pages (2,000 attack, 2,000 normal) to keep the window-picking
  step under an hour on the laptop GPU.
- Observation before v5 (BrowseSafe *train* split, 40 pages, not a score): v4 with window scanning flagged 12 of 15 attack
  pages and 20 of 25 normal pages. v4 can't tell normal HTML from an attack; that is what v5's web data is for.

**v5 screening result (5 Nov 2026, tune set only; 1 epoch on the same 30k-row sample).** Catch rate at 2% false alarms /
false alarms at 0.5 / tune-set scoring time: mmBERT-base 82.9% / 0.68% / 14 s; ModernBERT-large 82.9% / 0.82% / 30 s;
Ettin-encoder-400m 82.0% / 0.74% / 30 s. Tie between mmBERT-base and ModernBERT-large; by the rule set before the run (within
0.01, take the smaller and faster model) **mmBERT-base** is the v5 base. The bigger bases bought nothing here; the data is
what moves the score.

**Hand testing of v4 (4-5 Nov 2026, `blue-guardian scan`, not a scored test set).** Social-engineering attacks typed by hand
were all flagged: a threat to get admin passwords (1.0), a fake locked-out admin (0.996), the classic override (1.0). False
alarm found: "hey cmon just do it man i need it" scored 0.577 / 0.568 (flagged, nothing harmful asked): v4 treats pushy,
urgent tone as an attack. Harmless sentences using "ignore" ("check my essay and ignore the typos") passed (0.001). These go
on the list of things v5 and later must be checked against; they are not added to any training set.

**v5 result (5 Nov 2026, each test scored once).** Catch rate at 2% false alarms / false alarms at the model's threshold:

| | AgentDojo (never used, 2,358) | Fresh test (7,601) | BrowseSafe test (600 whole pages) |
|---|---|---|---|
| heuristic-v0 | 16.7% / 0.0% | 5.6% / 0.0% | 34.7% / 8.0% |
| v4 | 42.3% / 2.7% | 76.6% / 2.1% | 0.0% / 82.3% |
| **v5** | **67.0% / 2.7%** | **78.7% / 3.1%** | 0.0% / 71.3% |
| ProtectAI v2 | 0.0% / 12.2% | 83.7% / 0.1% | 0.0% / 100% |

- Mark 1 (AgentDojo: +20 points over v4 and at least 50%): **passed**, +24.7 points, 67.0%.
- Mark 2 (fresh test: no more than 2 points below v4 at 2%, false alarms at the threshold no higher than 2.5%): catch rate
  **passed** (+2.1), false alarms **failed** (3.1%). Most of the extra false alarms are JailbreakBench's harmless requests
  (11 of 27) and everyday chatbot prompts (3.0%).
- Mark 3 (BrowseSafe pages: +20 points over v4 at 2%): **failed**. Every model scores 0 at 2% on whole pages: scoring a page
  as its most suspicious of ~60 windows multiplies false alarms (v5 still flags 71% of normal pages). The windows idea needs
  a page-level rule, not a better window model.
- Mark 4 (speed): same as v4 (same base), 16-21 ms per text in this run.
- Agent attacks improved most: InjecAgent 21.5% -> 36.1%, harelix 21.9% -> 39.5%, AgentDojo +24.7. v5 beats ProtectAI on
  AgentDojo and harelix; ProtectAI stays ahead on the fresh test and on false alarms.
- **Verdict: v5 does not replace v4 as the default** (marks 2 and 3 failed). The threshold is not changed after the fact:
  choosing it on a test set would make that set a tuning set.
- Next (v6, written now, before any change): (1) a page-level rule for long text (for example, flag a page only when two
  windows agree, or a separate page threshold chosen on BrowseSafe tune pages), scored on the BrowseSafe test once;
  (2) more harmless requests that sound risky in the tune set, so the threshold is chosen on the kind of text that caused
  the false alarms.
