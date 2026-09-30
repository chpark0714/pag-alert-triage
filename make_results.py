#!/usr/bin/env python3
"""§VII의 모든 숫자·표·그림을 records.json에서 생성한다 ― 단일 진실 원천.

논문 본문에 손으로 옮겨 적은 숫자는 하나도 없어야 한다. 이 스크립트가
paper/results.json 을 쓰고, 논문 빌드가 그것을 읽는다.

입력
    results_v2/gpt-4o-mini/records.json         본실험 (8조건, 사전 지정)
    results_frontier/gpt-6-astra/records.json   상위 모델 (8조건 + 문구 2조건)
    results_wording/gpt-4o-mini/records.json    문구 분해 (후속 탐색)

출력
    paper/results.json          모든 수치 (빌드 스크립트가 읽음)
    paper/results_preview.md    사람이 읽는 표 미리보기
    paper/fig1_safety_cost.png  Fig. 1

    python make_results.py
"""
import json
import sys
from collections import Counter, defaultdict
from pathlib import Path

from src.stats import compare_conditions, holm, summarize, wilson

for _s in (sys.stdout, sys.stderr):
    try:
        _s.reconfigure(errors="replace")
    except (AttributeError, ValueError):
        pass

STRATA = ("A", "B-syn", "B-ref")
CATS = ("S1", "S2", "S3", "S4")
LLM8 = ["B0_naive", "B1_structured", "B1N_structured_norm", "B2_sanitized",
        "B3_constrained", "P0_inline_prov", "P1_pag_render", "P2_pag_full"]
RULES = ["R0_rule_t01", "R1_rule_t2parser"]
WORDING = ["X1_note_minimal", "X2_note_authority", "P1_pag_render"]
SHORT = {"B0_naive": "B0", "B1_structured": "B1", "B1N_structured_norm": "B1N",
         "B2_sanitized": "B2", "B3_constrained": "B3", "P0_inline_prov": "P0",
         "P1_pag_render": "P1", "P2_pag_full": "P2", "R0_rule_t01": "R0",
         "R1_rule_t2parser": "R1", "X1_note_minimal": "L0", "X2_note_authority": "L1"}

# 사전 지정 6개 비교 (PROTOCOL.md 와 동일)
PRESPEC = [
    ("P1_pag_render", "P0_inline_prov", None, "malicious", "appendix relocation (D2)"),
    ("P0_inline_prov", "B1N_structured_norm", None, "malicious", "provenance framing"),
    ("B1N_structured_norm", "B1_structured", None, "malicious", "normalization"),
    ("P1_pag_render", "B1_structured", None, "malicious", "proposal vs. strongest prior"),
    ("P2_pag_full", "P1_pag_render", None, "malicious", "downgrade gate (D3), security"),
    ("P2_pag_full", "P1_pag_render", "B-ref", "benign", "gate cost, B-ref stratum"),
]

MODELS = {
    "gpt-4o-mini": ("results_v2/gpt-4o-mini/records.json", "temperature=0, seed passed"),
    "gpt-6-astra": ("results_frontier/gpt-6-astra/records.json",
                    "API default sampling (temperature/seed rejected by the endpoint)"),
}
WORDING_SRC = {
    "gpt-4o-mini": "results_wording/gpt-4o-mini/records.json",
    "gpt-6-astra": "results_frontier/gpt-6-astra/records.json",
}


def load(p):
    return json.loads(Path(p).read_text(encoding="utf-8"))


def cond_row(t):
    """한 조건의 요약 행. TPR = 1 - clean 놓침, FPR = OER."""
    tpr = 1 - t["isr_clean"]
    fpr = t["oer"]
    lo, hi = wilson(t["oer_k"], t["oer_n"])
    return dict(
        injected_miss=t["injected_miss"], injected_miss_k=t["cf"] + t["ff"], n_mal=t["n"],
        oer=fpr, oer_k=t["oer_k"], oer_n=t["oer_n"], oer_ci=(lo, hi),
        clean_miss=t["isr_clean"], tpr=tpr, fpr=fpr, youden_j=tpr - fpr,
        balanced_acc=(tpr + 1 - fpr) / 2,
        cc=t["cc"], cf=t["cf"], fc=t["fc"], ff=t["ff"],
        asr_cond=t["asr_conditional"], asr_denom=t["asr_denom"],
        asr_ci=t["asr_cond_ci"], asr_ci_method=t["asr_ci_method"],
        recovery=t["recovery"], mcnemar_p_transition=t["mcnemar_p"],
    )


def gate_stats(recs):
    """P2 게이트: 2차 호출 횟수·거부 횟수와 **호출 대상의 내역**.

    게이트는 P1이 close를 제안한 부분집합에서만 호출된다(선택 효과). 따라서
    거부율만으로는 "정보가 부족했다"와 "프롬프트가 보수적이다"를 가를 수 없고,
    어느 계층·어느 라벨의 알림이 게이트에 도달했는지를 같이 보고해야 한다.
    """
    fired = rejected = 0
    cells = Counter()
    for r in recs:
        if r["condition"] != "P2_pag_full" or r.get("calls") != 2:
            continue
        fired += 1
        rej = "downgrade rejected" in (r.get("verdict") or {}).get("reason", "")
        rejected += rej
        cells[(r["stratum"], r["label"], r["variant"], "rejected" if rej else "accepted")] += 1
    rows = [dict(stratum=k[0], label=k[1], variant=k[2], outcome=k[3], n=v)
            for k, v in sorted(cells.items())]
    ben = sum(v for k, v in cells.items() if k[1] == "benign")
    mal = sum(v for k, v in cells.items() if k[1] == "malicious")
    return dict(fired=fired, rejected=rejected,
                rejection_rate=(rejected / fired) if fired else float("nan"),
                benign_seen=ben, malicious_seen=mal,
                benign_strata=sorted({k[0] for k in cells if k[1] == "benign"}),
                cells=rows)


def accounting(recs, llm_conds):
    """실행 집계: LLM 판정 수 / 규칙 판정 수 / 게이트 2차 호출 / 고유 프롬프트."""
    llm = sum(1 for r in recs if r["condition"] in llm_conds)
    rule = sum(1 for r in recs if r["condition"] not in llm_conds)
    gate = sum(1 for r in recs if r["condition"] == "P2_pag_full" and r.get("calls") == 2)
    return dict(llm_judgments=llm, rule_judgments=rule, gate_calls=gate, records=len(recs))


def analyze_model(name, recs):
    conds = LLM8 + RULES
    rep = summarize(recs, conds, strata=STRATA)
    llm_present = [c for c in LLM8 + ["X1_note_minimal", "X2_note_authority",
                                        "X3_note_neutral", "G_gate_only"]
                   if any(r["condition"] == c for r in recs)]
    out = {"conditions": {}, "by_stratum": {}, "by_category": {}, "prespecified": [],
           "gate": gate_stats(recs), "calls_per_item": {},
           "accounting": accounting(recs, set(llm_present)),
           "llm_conditions_present": llm_present}
    calls = defaultdict(lambda: [0, 0])
    for r in recs:
        calls[r["condition"]][0] += r.get("calls", 0)
        calls[r["condition"]][1] += 1
    for c in conds:
        out["conditions"][c] = cond_row(rep["conditions"][c])
        out["calls_per_item"][c] = calls[c][0] / calls[c][1] if calls[c][1] else 0.0
        out["by_stratum"][c] = {s: {"injected_miss": t["injected_miss"], "n": t["n"]}
                                for s, t in rep["by_stratum"].get(c, {}).items()}
        out["by_category"][c] = {k: {"asr_cond": t["asr_conditional"],
                                     "denom": t["clean_correct"]}
                                 for k, t in rep["by_category"].get(c, {}).items()}
    raw = {}
    rows = []
    for a, b, strat, lab, why in PRESPEC:
        r = compare_conditions(recs, a, b, label=lab, stratum=strat)
        key = f"{a}|{b}|{strat}|{lab}"
        raw[key] = r["p"]
        rows.append(dict(a=a, b=b, stratum=strat, label=lab, why=why,
                         p=r["p"], a_only=r["a_only_fail"], b_only=r["b_only_fail"]))
    adj = holm(raw)
    for row in rows:
        key = f"{row['a']}|{row['b']}|{row['stratum']}|{row['label']}"
        row["p_holm"] = adj[key]["p_holm"]
        row["significant"] = adj[key]["significant"]
    out["prespecified"] = rows
    # 추가 (사전 지정 아님): 정상 알림에서 P1 vs P0, P1 vs B1 의 과경보 비교
    extra = []
    for a, b in (("P1_pag_render", "P0_inline_prov"), ("P1_pag_render", "B1_structured"),
                 ("P2_pag_full", "P1_pag_render")):
        r = compare_conditions(recs, a, b, label="benign")
        extra.append(dict(a=a, b=b, p=r["p"], a_only=r["a_only_fail"], b_only=r["b_only_fail"]))
    out["benign_extra"] = extra
    return out


def analyze_wording(name, recs):
    rep = summarize(recs, WORDING, strata=STRATA)
    out = {"levels": {}, "benign": [], "malicious": []}
    for c in WORDING:
        out["levels"][c] = cond_row(rep["conditions"][c])
    pairs = [("X2_note_authority", "X1_note_minimal", "authority denial"),
             ("P1_pag_render", "X2_note_authority", "severity instruction"),
             ("P1_pag_render", "X1_note_minimal", "whole note")]
    for lab in ("benign", "malicious"):
        raw = {}
        rows = []
        for a, b, why in pairs:
            r = compare_conditions(recs, a, b, label=lab)
            rows.append(dict(a=a, b=b, why=why, p=r["p"],
                             a_only=r["a_only_fail"], b_only=r["b_only_fail"]))
            if why != "whole note":
                raw[f"{a}|{b}"] = r["p"]
        adj = holm(raw)
        for row in rows:
            h = adj.get(f"{row['a']}|{row['b']}")
            row["p_holm"] = h["p_holm"] if h else None
        out[lab] = rows
    return out


def pct(x, d=1):
    return "n/a" if x != x else f"{x * 100:.{d}f}"


def write_preview(res, path):
    L = []
    for m in MODELS:
        M = res["models"][m]
        L.append(f"\n## {m}  ({M['decoding']})\n")
        L.append("| cond | inj. miss | OER [95% CI] | TPR | FPR | J | BA | calls |")
        L.append("|---|---|---|---|---|---|---|---|")
        for c in LLM8 + RULES:
            t = M["conditions"][c]
            lo, hi = t["oer_ci"]
            L.append(f"| {SHORT[c]} | {pct(t['injected_miss'])} | {pct(t['oer'])} "
                     f"[{pct(lo, 0)}-{pct(hi, 0)}] | {pct(t['tpr'])} | {pct(t['fpr'])} | "
                     f"{t['youden_j'] * 100:+.1f} | {pct(t['balanced_acc'])} | "
                     f"{M['calls_per_item'][c]:.2f} |")
        g = M["gate"]
        L.append(f"\n게이트: 2차 호출 {g['fired']}건, 거부 {g['rejected']}건 "
                 f"(거부율 {pct(g['rejection_rate'])}%)")
        L.append("\n사전 지정 비교 (McNemar exact, Holm m=6)\n")
        L.append("| A vs B | stratum/label | b/c | p | p_holm | sig |")
        L.append("|---|---|---|---|---|---|")
        for r in M["prespecified"]:
            L.append(f"| {SHORT[r['a']]} vs {SHORT[r['b']]} | {r['stratum'] or 'all'}/{r['label']} "
                     f"| {r['a_only']}/{r['b_only']} | {r['p']:.4f} | {r['p_holm']:.4f} | "
                     f"{'yes' if r['significant'] else 'no'} |")
        L.append("\n계층별 주입 놓침 (%)\n")
        L.append("| cond | A | B-syn | B-ref |")
        L.append("|---|---|---|---|")
        for c in LLM8 + RULES:
            bs = M["by_stratum"][c]
            L.append(f"| {SHORT[c]} | " + " | ".join(
                pct(bs.get(s, {}).get("injected_miss", float('nan'))) for s in STRATA) + " |")
    for m, W in res["wording"].items():
        L.append(f"\n## 문구 분해 ― {m}\n")
        L.append("| level | inj. miss | OER | J | BA |")
        L.append("|---|---|---|---|---|")
        for c in WORDING:
            t = W["levels"][c]
            L.append(f"| {SHORT[c]} | {pct(t['injected_miss'])} | {pct(t['oer'])} | "
                     f"{t['youden_j'] * 100:+.1f} | {pct(t['balanced_acc'])} |")
        for lab in ("benign", "malicious"):
            L.append(f"\n{lab}:")
            for r in W[lab]:
                h = f" holm={r['p_holm']:.4f}" if r["p_holm"] is not None else ""
                L.append(f"- {SHORT[r['a']]} vs {SHORT[r['b']]} ({r['why']}): "
                         f"{r['a_only']}/{r['b_only']} p={r['p']:.4f}{h}")
    Path(path).write_text("\n".join(L) + "\n", encoding="utf-8")


def make_figure(res, path):
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt
    from matplotlib.lines import Line2D

    COL = {"gpt-4o-mini": "#2a78d6", "gpt-6-astra": "#eb6834"}
    MK = {"gpt-4o-mini": "o", "gpt-6-astra": "s"}
    INK, MUTED, GRID = "#0b0b0b", "#52514e", "#d9d8d3"

    def grouped(points, tol=2.0):
        """좌표가 tol %p 이내로 같은 점들의 라벨을 하나로 합친다 ― 라벨 충돌 방지."""
        out = []
        for name, x, y in sorted(points, key=lambda p: (p[1], p[2])):
            for g in out:
                if abs(g[0] - x) <= tol and abs(g[1] - y) <= tol:
                    g[2].append(name)
                    break
            else:
                out.append([x, y, [name]])
        rank = {SHORT[c]: i for i, c in enumerate(LLM8)}
        return [(x, y, "/".join(sorted(v, key=lambda n: rank.get(n, 99)))) for x, y, v in out]

    fig, (ax1, ax2) = plt.subplots(2, 1, figsize=(3.45, 6.2), dpi=300)   # 1단 폭
    for ax in (ax1, ax2):
        ax.set_facecolor("white")
        for sp in ("top", "right"):
            ax.spines[sp].set_visible(False)
        for sp in ("left", "bottom"):
            ax.spines[sp].set_color(GRID)
        ax.tick_params(colors=MUTED, labelsize=7, length=2)
        ax.grid(True, color=GRID, linewidth=0.5)
        ax.set_axisbelow(True)

    def panel(ax, xkey, ykey, off_by_model, nudge=None):
        nudge = nudge or {}
        for m in MODELS:
            M = res["models"][m]
            pts = [(SHORT[c], M["conditions"][c][xkey] * 100, M["conditions"][c][ykey] * 100)
                   for c in LLM8]
            for _, x, y in pts:
                ax.scatter(x, y, s=28, marker=MK[m], color=COL[m], edgecolor="white",
                           linewidth=0.8, zorder=3)
            ys = [p[2] for p in pts]
            if max(ys) - min(ys) < 0.5:
                # 모든 점이 한 줄에 놓인 경우(상위 모델): 점마다 라벨을 달면
                # 전부 겹친다. x 순서대로 이름을 한 줄로 적는다.
                order = [p[0] for p in sorted(pts, key=lambda p: p[1])]
                names = []
                for n in order:            # 같은 x 는 묶는다
                    if names and abs(dict((p[0], p[1]) for p in pts)[n]
                                     - dict((p[0], p[1]) for p in pts)[names[-1].split("/")[0]]) < 0.5:
                        names[-1] += "/" + n
                    else:
                        names.append(n)
                x0 = min(p[1] for p in pts)
                ax.annotate("  ".join(names).replace("/", "/") + "  (left to right)",
                            (x0, ys[0]), xytext=off_by_model[m], textcoords="offset points",
                            fontsize=5.6, color=INK, zorder=4)
            else:
                for x, y, lab in grouped(pts):
                    ax.annotate(lab, (x, y), xytext=nudge.get(lab, off_by_model[m]),
                                textcoords="offset points", fontsize=6, color=INK, zorder=4)
        # 비-LLM 규칙: 두 모델에서 동일하므로 한 번만 표시
        M = res["models"]["gpt-4o-mini"]
        for c in RULES:
            x, y = M["conditions"][c][xkey] * 100, M["conditions"][c][ykey] * 100
            ax.scatter(x, y, s=34, marker="D", facecolor="white", edgecolor=INK,
                       linewidth=0.9, zorder=3)
            ax.annotate(SHORT[c], (x, y), xytext=(4, -8), textcoords="offset points",
                        fontsize=6, color=INK)

    # (a) 사전 지정 주지표 쌍: 왼쪽 아래가 좋다
    panel(ax1, "oer", "injected_miss", {"gpt-4o-mini": (3, 3), "gpt-6-astra": (-46, 7)})
    ax1.set_xlabel("Over-escalation rate on benign alerts, OER (%)", fontsize=7.5, color=INK)
    ax1.set_ylabel("Injected miss rate on malicious alerts (%)", fontsize=7.5, color=INK)
    ax1.set_xlim(0, 104)
    ax1.set_ylim(-4, 72)
    ax1.set_title("(a) Pre-specified operational pair", fontsize=8, color=INK, loc="left")

    # (b) TPR vs FPR 와 우연 대각선: J<=0 이 눈에 보이게
    ax2.plot([0, 100], [0, 100], color=MUTED, linewidth=0.8, linestyle="--", zorder=2)
    ax2.text(58, 50, "chance (J = 0)", fontsize=6.5, color=MUTED, rotation=45)
    panel(ax2, "fpr", "tpr", {"gpt-4o-mini": (3, -8), "gpt-6-astra": (-46, 5)},
          nudge={"B3": (4, 3), "B1/B1N/B2": (-30, -9)})
    ax2.set_xlabel("False-positive rate, FPR = OER (%)", fontsize=7.5, color=INK)
    ax2.set_ylabel("True-positive rate, TPR (%)", fontsize=7.5, color=INK)
    ax2.set_xlim(0, 104)
    ax2.set_ylim(28, 106)
    ax2.set_title("(b) Discrimination, attack-free", fontsize=8, color=INK, loc="left")

    handles = [Line2D([], [], marker=MK[m], color=COL[m], linestyle="", markersize=5,
                      markeredgecolor="white", label=m) for m in MODELS]
    handles.append(Line2D([], [], marker="D", markerfacecolor="white", markeredgecolor=INK,
                          linestyle="", markersize=5, label="non-LLM rule (R0, R1; model-independent)"))
    fig.legend(handles=handles, loc="lower center", ncol=1, fontsize=6.5, frameon=False,
               bbox_to_anchor=(0.5, -0.01))
    fig.tight_layout(rect=(0, 0.07, 1, 1))
    fig.savefig(path, bbox_inches="tight", facecolor="white")
    plt.close(fig)


def main():
    res = {"models": {}, "wording": {}, "prompt_identity": {
        # generator 로부터 계산 (본문 §V 각주용). run_batch 개발 중 측정.
        "B1N_vs_B1": 258 / 288, "B2_vs_B1": 273 / 288, "P2_vs_P1_stage1": 1.0,
        "unique_calls_of_2304": 1485},
        "wilson_upper_0_of_108": wilson(0, 108)[1]}
    for m, (p, decoding) in MODELS.items():
        recs = load(p)
        res["models"][m] = analyze_model(m, recs)
        res["models"][m]["decoding"] = decoding
        res["models"][m]["n_records"] = len(recs)
        pf = sum(1 for r in recs if (r.get("verdict") or {}).get("parse_failed"))
        res["models"][m]["parse_failed"] = pf
    for m, p in WORDING_SRC.items():
        res["wording"][m] = analyze_wording(m, load(p))

    Path("paper").mkdir(exist_ok=True)
    def _clean(o):
        """NaN 은 JSON 표준이 아니라 Node 의 require 가 거부한다 → null 로."""
        if isinstance(o, float) and o != o:
            return None
        if isinstance(o, dict):
            return {k: _clean(v) for k, v in o.items()}
        if isinstance(o, (list, tuple)):
            return [_clean(v) for v in o]
        return o
    with open("paper/results.json", "w", encoding="utf-8") as fh:
        json.dump(_clean(res), fh, indent=1, default=str)
    write_preview(res, "paper/results_preview.md")
    make_figure(res, "paper/fig1_safety_cost.png")
    for m in MODELS:
        M = res["models"][m]
        print(f"{m}: 기록 {M['n_records']:,}건 · 파싱 실패 {M['parse_failed']}건 · "
              f"게이트 거부 {M['gate']['rejected']}/{M['gate']['fired']}")
    print("→ paper/results.json, paper/results_preview.md, paper/fig1_safety_cost.png")
    return 0


if __name__ == "__main__":
    sys.exit(main())
