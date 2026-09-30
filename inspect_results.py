#!/usr/bin/env python3
"""결과 진단 ― OER 100%가 '모델의 판단'인지 '파싱 실패'인지 가른다.

왜 이걸 먼저 보는가
-------------------
P0/P1/P2의 OER이 정확히 100%로 나왔다. 두 가지 해석이 가능하다.

  (A) 모델이 실제로 모든 정상 알림을 "악성"으로 판정했다 (과경보 = 진짜 결과)
  (B) 모델이 JSON이 아닌 산문으로 답해서 parse_verdict가 실패했고,
      fail-closed 규칙("파싱 실패 → escalate")이 전부 escalate로 만들었다

(B)라면 이건 결과가 아니라 버그이고, 프롬프트를 고쳐 다시 돌려야 한다.
둘은 records.json의 parse_failed 플래그로 바로 구분된다.

    python inspect_results.py
"""
import hashlib
import json
import sys
from collections import Counter, defaultdict
from pathlib import Path

for _s in (sys.stdout, sys.stderr):
    try:
        _s.reconfigure(errors="replace")
    except (AttributeError, ValueError):
        pass

MODEL = "gpt-4o-mini"
REC = Path("results_v2") / MODEL / "records.json"
CACHE = Path(".cache") / MODEL


def cache_key(system, user, seed, model=MODEL, temperature=0.0):
    """src.client.Client._key 와 동일한 해시 (openai 패키지 없이 계산)."""
    h = hashlib.sha256()
    for part in (model, str(temperature), str(seed), system, user):
        h.update(part.encode())
        h.update(b"\x00")
    return CACHE / f"{h.hexdigest()[:40]}.json"


def main():
    if not REC.exists():
        print(f"{REC} 가 없습니다. run_v2.py를 먼저 실행하세요.")
        return 1
    recs = json.loads(REC.read_text(encoding="utf-8"))
    print(f"\n기록 {len(recs):,}건 읽음\n")

    # ── 1. 조건별 파싱 실패율 ─────────────────────────────────────────
    pf, tot = Counter(), Counter()
    for r in recs:
        v = r.get("verdict") or {}
        tot[r["condition"]] += 1
        if v.get("parse_failed"):
            pf[r["condition"]] += 1
    print("[1] 조건별 JSON 파싱 실패율  ← 여기가 높으면 OER 100%는 버그다")
    print(f"{'condition':<24}{'파싱실패':>10}{'전체':>8}{'비율':>9}")
    print("-" * 55)
    for c in sorted(tot):
        print(f"{c:<24}{pf[c]:>10}{tot[c]:>8}{pf[c]/tot[c]:>9.1%}")

    # ── 2. 정상 알림에 대한 판정 분포 ────────────────────────────────
    print("\n[2] 정상(benign) 알림에 대한 판정 분포  ← OER의 정체")
    print(f"{'condition':<24}{'escalate':>10}{'close':>8}{'그중 파싱실패':>14}")
    print("-" * 60)
    ben = defaultdict(lambda: [0, 0, 0])
    for r in recs:
        if r["label"] != "benign":
            continue
        v = r.get("verdict") or {}
        a = ben[r["condition"]]
        if v.get("action") == "escalate" or v.get("verdict") == "malicious":
            a[0] += 1
            if v.get("parse_failed"):
                a[2] += 1
        else:
            a[1] += 1
    for c in sorted(ben):
        e, cl, f = ben[c]
        print(f"{c:<24}{e:>10}{cl:>8}{f:>14}")

    # ── 3. 모델이 정상 알림에 실제로 뭐라고 답했는지 원문 ────────────
    print("\n[3] 정상 알림에 대한 모델 응답 원문 (P1/P2 조건, 최대 3건)")
    print("-" * 60)
    try:
        sys.path.insert(0, ".")
        import types
        import run_v2
        from src.conditions import SYSTEM
        args = types.SimpleNamespace(n=60, seeds=3, conditions=run_v2.CONDS,
                                     stratum_weights=[0.34, 0.33, 0.33],
                                     pipeline="parse")
        shown = 0
        for s in range(3):
            seed = 20260911 + s * 1000
            _, jobs = run_v2.build_jobs(args, seed)
            for j in jobs:
                if shown >= 3 or j["label"] != "benign" or j["condition"] != "P1_pag_render":
                    continue
                kf = cache_key(SYSTEM, j["prompt"], seed)
                if not kf.exists():
                    continue
                raw = json.loads(kf.read_text(encoding="utf-8"))["text"]
                print(f"\n  [{j['alert_id']} / {j['stratum']}] 모델 응답:")
                print("   ", raw.replace("\n", "\n    ")[:600])
                shown += 1
        if not shown:
            print("  (캐시에서 해당 응답을 찾지 못했습니다)")
    except Exception as e:
        print(f"  원문 조회 실패: {type(e).__name__}: {e}")

    # ── 4. 정규화·필터가 실제로 프롬프트를 바꾼 항목 수 ──────────────
    print("\n[4] 참고: 사전 지정 비교 중 프롬프트가 애초에 동일한 비율은")
    print("    B1N vs B1 = 90%, B2 vs B1 = 95% (구성상 효과가 존재할 수 없는 구간)")
    print()
    return 0


if __name__ == "__main__":
    sys.exit(main())
