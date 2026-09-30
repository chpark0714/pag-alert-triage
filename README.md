# Provenance Marking and Information Exclusion in LLM-Augmented Alert Triage — Artifact

Code, payload corpus, harness, per-item model outputs, and paper build for:

> A. L. Edwin Jose Jebaslin Vijila and C. H. Park, "Provenance Marking and Information Exclusion in LLM-Augmented Alert Triage: Security Effects and Operational Costs."

Release: `[TAG]` · commit `[HASH]` · models and run dates in `MANIFEST.json`.

## What is here

| Path | Contents |
|---|---|
| `src/generator.py`, `src/schema.py`, `src/synth.py` | Three-stratum alert generator (A trusted-sufficient, B-syn parse-required, B-ref record-required) |
| `src/payloads.py` | 60 injection payloads, S1–S4 (15 each), authored for this study; taxonomy follows Pandey & Bhujang |
| `src/delivery.py` | Delivery-path annotation: which payload can reach which field through which protocol/application convention (Table II) |
| `src/conditions.py` | All prompt conditions: B0, B1, B1N, B2, B3, P0, P1, P2 (pre-specified); X1, X2, X3, G (post hoc); rules R0/R1 |
| `src/defenses.py` | Trust-tier classification (D1), provenance-aware rendering (D2), downgrade gate (D3) |
| `src/client.py` | OpenAI client with content-hash cache (`sha256(model, temperature, seed, system, user)[:40]`), RPM/RPD handling, parameter-mode fallback |
| `src/stats.py`, `test_stats.py` | Paired McNemar, Holm, Wilson/Newcombe intervals; regression tests for seed-collision indexing |
| `run_v2.py` | Main harness (`--conditions`, `--seeds`, `--n`, `--outdir`) |
| `run_batch.py` | OpenAI Batch API submit / status / fetch into the same cache |
| `make_results.py` | Single source of truth: reads every `records.json`, writes `paper/results.json`, `paper/prompts.json`, `MANIFEST.json`, `paper/fig1_safety_cost.png` |
| `analyze_wording.py`, `inspect_results.py` | Post hoc wording ladder; parse/label diagnostics |
| `results_v2/`, `results_frontier/`, `results_wording/`, `results_followup/` | Per-item records (`records.json`) for gpt-4o-mini and gpt-6-astra, every condition |
| `.cache/<model>/` | Raw model responses keyed by content hash (API-call and cache-reuse counts per model in `MANIFEST.json`) |
| `paper/content_v12.js`, `paper/build12.js` | Extended version (16 pp.) source; `paper/PAG_paper_IEEE_v12.pdf` is the extended version |
| `paper/content_v13_short.js`, `paper/build13.js` | Conference version (ICCA 2026, 6 pp.) source; every number in both versions is read from `paper/results.json` |
| `PROTOCOL.md` | Pre-specified comparisons, post hoc additions, execution record |
| `pilot/`, `control/`, `blind/` | Pilot studies (Section VI) |

## Reproduce the tables and figure (no API calls)

```bash
python3 make_results.py            # -> paper/results.json, results_preview.md, fig1
python3 test_stats.py
cd paper && npm install docx && node build12.js   # -> PAG_paper_IEEE_v12.docx
```

## Re-run the model (API calls; cache makes it idempotent)

```bash
export OPENAI_API_KEY=...
python3 run_batch.py submit --client openai:gpt-4o-mini --n 60 --seeds 3 --conditions B0_naive B1_structured B1N_norm B2_delim B3_constrained P0_pag_inline P1_pag_render P2_pag_full
python3 run_batch.py fetch
python3 run_v2.py --client openai:gpt-4o-mini --n 60 --seeds 3 --outdir results_v2
```

Seeds, decoding settings, and the `--params` mode used for gpt-6-astra are recorded in `MANIFEST.json`. Cached responses are reused; a cache hit is bit-identical to the original run.

## Not included

API keys; OpenAI batch bookkeeping (`batch_state.json`); superseded drafts.
