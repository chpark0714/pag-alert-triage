#!/usr/bin/env python3
"""Figure 1 — ISR–OER 트레이드오프 산점도.

본 연구의 핵심 그림. 기존 문헌은 ISR만 보고하므로 이 평면 자체가 비어 있다.
좌하단(공격도 막고 오탐도 안 늘림)에 가까울수록 우수.
"""
import json

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt


matplotlib.rcParams["font.family"] = ["Noto Sans CJK JP", "DejaVu Sans"]
matplotlib.rcParams["axes.unicode_minus"] = False

BASELINE = "#2a78d6"   # categorical slot 1
PROPOSED = "#eb6834"   # categorical slot 2
INK, INK2, GRID = "#0b0b0b", "#52514e", "#d8d7d2"
SURFACE = "#fcfcfb"

LABELS = {
    "B0_naive": ("B0 무방어", BASELINE),
    "B3_constrained": ("B3 constrained\n(기존 최고 베이스라인)", BASELINE),
    "P1_pag_render": ("P1 PAG-render\n(제안)", PROPOSED),
    "P2_pag_full": ("P2 PAG+게이트\n(제안)", PROPOSED),
}
OFFSETS = {"B0_naive": (10, 10), "B3_constrained": (10, -30),
           "P1_pag_render": (12, 6), "P2_pag_full": (-8, 14)}


def main():
    data = json.load(open("pilot/final_summary.json"))

    fig, ax = plt.subplots(figsize=(7.4, 5.4), dpi=200)
    fig.patch.set_facecolor(SURFACE)
    ax.set_facecolor(SURFACE)

    for cond, v in data.items():
        if cond not in LABELS:
            continue
        label, color = LABELS[cond]
        x, y = v["oer"] * 100, v["isr"] * 100
        ax.scatter(x, y, s=150, color=color, zorder=3,
                   edgecolors=SURFACE, linewidths=2)
        dx, dy = OFFSETS[cond]
        ax.annotate(label, (x, y), textcoords="offset points", xytext=(dx, dy),
                    fontsize=9.5, color=INK, linespacing=1.35, zorder=4)

    ax.set_xlabel("OER — 정상 알림 과잉 경보율 (%)", fontsize=10.5, color=INK2, labelpad=9)
    ax.set_ylabel("ISR — 악성 알림 오판율 (%)", fontsize=10.5, color=INK2, labelpad=9)
    ax.text(0, 1.115, "방어 조건별 안전–효용 트레이드오프",
            transform=ax.transAxes, fontsize=13, color=INK, va="bottom")
    ax.text(0, 1.035, "소형 모델 · 48건 큐 · 파일럿 · 좌하단일수록 우수",
            transform=ax.transAxes, fontsize=9, color=INK2, va="bottom")

    ax.set_xlim(-3, 31)
    ax.set_ylim(-3, 36)
    ax.grid(True, color=GRID, lw=0.7, alpha=0.65)
    ax.set_axisbelow(True)
    for s in ("top", "right"):
        ax.spines[s].set_visible(False)
    for s in ("left", "bottom"):
        ax.spines[s].set_color(GRID)
    ax.tick_params(colors=INK2, labelsize=9.5)

    fig.tight_layout()
    fig.savefig("figure1_isr_oer.png", facecolor=SURFACE, bbox_inches="tight")
    print("저장: figure1_isr_oer.png")


if __name__ == "__main__":
    main()
