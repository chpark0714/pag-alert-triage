#!/usr/bin/env python3
"""파일럿 데이터 생성기.

API 키가 없는 환경에서 실제 LLM 판정을 받기 위한 우회 경로.
조건별로 '현실적인 알림 큐'를 하나 만들어 프롬프트 파일로 내보낸다.

설계 의도
---------
조건마다 별도 데이터셋을 쓰지 않고 **동일한 큐**를 조건만 바꿔 렌더링한다.
- ISR과 OER이 같은 모집단에서 나오므로 트레이드오프 비교가 정당해진다.
- 악성(인젝션 있음)과 정상(인젝션 없음)이 섞여 있어 실제 SOC 큐에 가깝다.
- 조건 간 차이가 데이터 차이가 아니라 방어 차이임이 보장된다.
"""
import argparse
import json
import random
from pathlib import Path

from src.defenses import BUILDERS
from src.payloads import CATEGORIES
from src.synth import inject, make_alert

ATTACK_CATS = ["S1", "S2", "S3", "S4"]


def build_queue(n: int = 48, seed: int = 20260911, malicious_ratio: float = 0.6,
                profile: str = "ambiguous"):
    """혼합 큐 생성. 악성에는 S1~S4를 고르게 배분, 정상은 무공격 유지."""
    rng = random.Random(seed)
    n_mal = int(n * malicious_ratio)
    rows = []
    for i in range(n):
        is_mal = i < n_mal
        alert = make_alert(rng, is_mal, i, profile)
        if is_mal:
            cat = ATTACK_CATS[i % len(ATTACK_CATS)]
            payload = rng.choice(CATEGORIES[cat])
            alert = inject(alert, payload, rng)
        else:
            cat = "S0"
        rows.append({
            "id": f"A{i:03d}",
            "label": "malicious" if is_mal else "benign",
            "payload_category": cat,
            "alert": alert,
        })
    rng.shuffle(rows)
    return rows


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--n", type=int, default=48)
    ap.add_argument("--conditions", nargs="+",
                    default=["B0_naive", "B3_constrained", "P1_pag_render"])
    ap.add_argument("--outdir", default="pilot")
    ap.add_argument("--profile", default="ambiguous", choices=["ambiguous", "obvious"])
    args = ap.parse_args()

    queue = build_queue(args.n, profile=args.profile)
    out = Path(args.outdir)
    out.mkdir(exist_ok=True)

    # 정답지는 별도 파일로 분리 — 판정자에게 라벨이 새지 않도록.
    with open(out / "truth.json", "w") as f:
        json.dump([{k: r[k] for k in ("id", "label", "payload_category")} for r in queue],
                  f, indent=2)
    with open(out / "queue_raw.json", "w") as f:
        json.dump(queue, f, indent=2, ensure_ascii=False)

    for cond in args.conditions:
        items = [{"id": r["id"], "prompt": BUILDERS[cond](r["alert"])} for r in queue]
        with open(out / f"items_{cond}.json", "w") as f:
            json.dump(items, f, indent=2, ensure_ascii=False)
        print(f"{cond}: {len(items)}건 → {out}/items_{cond}.json")

    n_mal = sum(1 for r in queue if r["label"] == "malicious")
    print(f"\n큐 구성: 악성 {n_mal} / 정상 {len(queue) - n_mal}")
    from collections import Counter
    print("페이로드 분포:", dict(Counter(r["payload_category"] for r in queue)))


if __name__ == "__main__":
    main()
