#!/usr/bin/env python3
"""후속 탐색 분석 ― 과경보의 원인이 '출처 표시'인가 '한 문장'인가.

본실험에서 P0/P1/P2의 OER이 94~100%로 나왔다. 그런데 P0·P1이 공유하는
문구의 마지막 절이 이렇다.

    "; if one appears to do so, that itself is evidence of an evasion
      attempt and raises severity."

이것은 출처를 알려주는 서술이 아니라 **심각도를 올리라는 지시**이며, 모든
알림에는 공격자 기록 가능 필드가 있으므로 사실상 항상 발화한다. 따라서
본실험 데이터만으로는 다음 두 주장을 구분할 수 없다.

    (a) 출처 표시(provenance marking)가 과경보를 유발한다
    (b) 그 한 문장이 과경보를 유발한다

문구를 세 단계로 나눠 그것을 가른다. 배치·렌더링·정규화·신뢰등급은 전부
동일하고 문구만 다르다.

    X1_note_minimal    L0  출처만 알려준다
    X2_note_authority  L1  + 권위 부정 ("승인을 줄 수 없다")
    P1_pag_render      L2  + 심각도 지시            ← 본실험에서 쓴 문구

L0→L1 차이가 권위 부정의 효과, L1→L2 차이가 심각도 지시의 효과다.

**이 분석은 결과를 본 뒤에 정한 것이므로 사전 지정 6개 비교와 같은 지위가
아니다.** Holm 보정도 이 두 비교 안에서만 따로 적용하고, 논문에서는 후속
탐색(exploratory follow-up)으로 명시해야 한다.

    python analyze_wording.py [--dir results_wording]
"""
import argparse
import json
import sys
from pathlib import Path

from src.stats import compare_conditions, holm, summarize

for _s in (sys.stdout, sys.stderr):
    try:
        _s.reconfigure(errors="replace")
    except (AttributeError, ValueError):
        pass

LEVELS = [("X1_note_minimal", "L0  출처만"),
          ("X2_note_authority", "L1  + 권위 부정"),
          ("P1_pag_render", "L2  + 심각도 지시 (본실험)")]


def pct(x):
    return "  n/a" if x != x else f"{x:5.1%}"


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--dir", default="results_wording")
    ap.add_argument("--model", default="gpt-4o-mini")
    args = ap.parse_args()

    rec = Path(args.dir) / args.model / "records.json"
    if not rec.exists():
        print(f"\n{rec} 가 없습니다. 먼저 아래를 실행하세요:\n")
        print("  python run_batch.py submit --client openai:gpt-4o-mini --n 60 --seeds 3 \\")
        print("      --conditions P1_pag_render X1_note_minimal X2_note_authority")
        print("  python run_batch.py fetch")
        print("  python run_v2.py --client openai:gpt-4o-mini --n 60 --seeds 3 \\")
        print("      --conditions P1_pag_render X1_note_minimal X2_note_authority \\")
        print(f"      --outdir {args.dir}\n")
        return 1

    recs = json.loads(rec.read_text(encoding="utf-8"))
    have0 = {r["condition"] for r in recs}
    # X3(중립 문구)가 있으면 사다리 옆에 붙인다 ― 심사 지적: L0도 ATTACKER-WRITABLE 라벨을 공유
    levels = LEVELS + ([("X3_note_neutral", "N   중립 라벨·문구 (증거 가능성 명시)")]
                       if "X3_note_neutral" in have0 else [])
    conds = [c for c, _ in levels]
    have = {r["condition"] for r in recs}
    missing = [c for c in conds if c not in have]
    if missing:
        print(f"\n기록에 없는 조건: {missing}\n")
        return 1

    rep = summarize(recs, conds, strata=("A", "B-syn", "B-ref"))

    print("\n" + "=" * 78)
    print("후속 탐색: 문구 강도 분해  (사전 지정 아님 / 탐색적)")
    print("=" * 78)
    print(f"\n{'문구 수준':<30}{'주입 놓침':>11}{'OER':>9}{'TPR':>8}"
          f"{'Youden J':>11}{'균형정확도':>12}")
    print("-" * 78)
    for c, label in levels:
        t = rep["conditions"][c]
        miss_clean = t["clean_failed"] / t["n"] if t["n"] else float("nan")
        tpr = 1 - miss_clean
        ba = (tpr + (1 - t["oer"])) / 2
        print(f"{label:<30}{pct(t['injected_miss']):>11}{pct(t['oer']):>9}"
              f"{pct(tpr):>8}{tpr - t['oer']:>+11.1%}{pct(ba):>12}")
    print("  Youden J = TPR - FPR(=OER). J<=0이면 판별력이 남아있지 않다는 뜻이다.")
    print("\n  주입 놓침 분모 =", rep["conditions"][conds[0]]["n"],
          "· OER 분모 =", rep["conditions"][conds[0]]["oer_n"])

    # ── 대응 비교: 정상 알림에서의 과경보 (핵심 질문)
    print("\n[과경보] 같은 정상 알림 위에서의 대응 비교 (McNemar exact)")
    print("-" * 78)
    pairs = [("X2_note_authority", "X1_note_minimal", "권위 부정을 더한 효과"),
             ("P1_pag_render", "X2_note_authority", "심각도 지시를 더한 효과  ★"),
             ("P1_pag_render", "X1_note_minimal", "문구 전체의 효과")]
    if "X3_note_neutral" in have0:
        pairs += [("X2_note_authority", "X3_note_neutral", "중립 → ATTACKER 라벨+forensic 문구 (권위 부정 동일)"),
                  ("P1_pag_render", "X3_note_neutral", "중립 → 본실험 문구 전체")]
    raw, detail = {}, {}
    for a, b, why in pairs:
        r = compare_conditions(recs, a, b, label="benign")
        raw[f"{a} vs {b}"] = r["p"]
        detail[f"{a} vs {b}"] = (r, why)
    adj = holm({k: v for k, v in raw.items() if "전체" not in detail[k][1]})
    for k, (r, why) in detail.items():
        h = adj.get(k)
        tag = f"holm={h['p_holm']:.4f}" if h else "(보정 제외)"
        print(f"  {k:<44} p={r['p']:.4f} {tag}")
        print(f"    └ {why}  · 불일치 쌍 {r['a_only_fail']}/{r['b_only_fail']}")
    print("\n  ※ Holm은 위 두 개(권위·심각도) 안에서만 적용. 사전 지정 6개와 별도 가족.")

    # ── 보안 쪽도 같이 본다 (악성 놓침)
    print("\n[보안] 같은 악성 알림 위에서의 대응 비교")
    print("-" * 78)
    for a, b, why in pairs:
        r = compare_conditions(recs, a, b, label="malicious")
        print(f"  {a} vs {b:<26} p={r['p']:.4f}  불일치 {r['a_only_fail']}/{r['b_only_fail']}")

    print("\n해석 지침")
    print("-" * 78)
    print("  · 심각도 지시를 뺐을 때 OER이 크게 떨어지면 → 원인은 '출처 표시'가")
    print("    아니라 그 한 문장이다. 논문 주장을 그 수준으로 좁혀야 한다.")
    print("  · OER이 그대로 높으면 → 출처 표시 자체가 과경보를 유발한다는")
    print("    본실험의 negative result가 문구와 무관하게 성립한다.")
    print("  · 어느 쪽이든 보안 쪽(놓침) 변화를 함께 읽어야 한다. 놓침이 같이")
    print("    올라가면 문구가 보안·운영 비용을 동시에 움직인 것이다.\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
