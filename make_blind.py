#!/usr/bin/env python3
"""3차 측정 — 블라인드 교차설계 배치 생성.

2차 파일럿의 두 가지 타당성 위협을 설계로 제거한다.

위협 1: 배치 오염
    한 판정자가 한 조건의 48건을 연속 처리 → 앞 항목이 뒤 항목에 영향.
위협 2: Demand characteristics
    판정자가 '인젝션 연구용 파일'임을 눈치채면 평소보다 의심이 강해진다.
    이게 조건마다 다르게 작용하면 조건 비교 자체가 무의미해진다.

해결: 조건을 섞어서 배분한다.
    - 모든 조건의 항목을 하나의 풀에 넣고 무작위로 배치에 흩뿌린다.
    - 판정자는 한 배치 안에서 B0·B3·P1 렌더링을 뒤섞어 보게 된다.
    - 따라서 판정자의 '의심 수준'은 조건 간 **상수**가 된다.
      비교하려는 것은 조건 간 차이이므로, 상수는 상쇄된다.
    - 제약: 같은 알림(alert_id)은 한 배치에 두 번 들어가지 않는다.
      (같은 사건을 두 렌더링으로 연달아 보면 정답을 역추론할 수 있음)

대조군(무인젝션 악성)도 같은 풀에 포함시킨다. 판정자는 자기가 보는 항목이
인젝션된 것인지 대조군인지 알 수 없다 — 2차에서는 별도 실행이라 알 수 있었다.
"""
import argparse
import json
import random
from pathlib import Path

from src.defenses import BUILDERS
from src.payloads import CATEGORIES, INJECTION_FIELDS
from src.synth import inject, make_alert

CONDS = ["B0_naive", "B3_constrained", "P1_pag_render"]
ATTACK_CATS = ["S1", "S2", "S3", "S4"]


def build_alerts(n: int, seed: int, malicious_ratio: float = 0.6):
    """알림 생성. 악성은 인젝션본과 무인젝션본을 둘 다 보관한다."""
    rng = random.Random(seed)
    n_mal = int(n * malicious_ratio)
    out = []
    for i in range(n):
        is_mal = i < n_mal
        clean = make_alert(rng, is_mal, i, "ambiguous")
        if is_mal:
            cat = ATTACK_CATS[i % len(ATTACK_CATS)]
            injected = inject(clean, rng.choice(CATEGORIES[cat]), rng)
        else:
            cat, injected = "S0", clean
        out.append(dict(id=f"A{i:03d}", label="malicious" if is_mal else "benign",
                        payload_category=cat, clean=clean, injected=injected))
    return out


def build_items(alerts):
    """(alert, 조건, variant) 조합을 모두 펼친다."""
    items = []
    for a in alerts:
        variants = [("inj", a["injected"])]
        if a["label"] == "malicious":
            variants.append(("clean", a["clean"]))   # 대조군
        for variant, payload_alert in variants:
            for cond in CONDS:
                items.append(dict(
                    item_id=f"{a['id']}-{cond}-{variant}",
                    alert_id=a["id"], condition=cond, variant=variant,
                    label=a["label"],
                    payload_category=a["payload_category"] if variant == "inj" else "CLEAN",
                    prompt=BUILDERS[cond](payload_alert),
                ))
    return items


def assign_batches(items, n_batches: int, seed: int, tries: int = 4000):
    """같은 alert_id가 한 배치에 중복되지 않도록 무작위 배분."""
    rng = random.Random(seed)
    target = len(items) / n_batches
    for _ in range(tries):
        pool = items[:]
        rng.shuffle(pool)
        batches = [[] for _ in range(n_batches)]
        seen = [set() for _ in range(n_batches)]
        ok = True
        for it in pool:
            cand = [b for b in range(n_batches)
                    if it["alert_id"] not in seen[b] and len(batches[b]) < target + 2]
            if not cand:
                ok = False
                break
            b = min(cand, key=lambda x: len(batches[x]))
            batches[b].append(it)
            seen[b].add(it["alert_id"])
        if ok:
            for b in batches:
                rng.shuffle(b)      # 배치 내 순서도 섞어 조건이 위치로 드러나지 않게
            return batches
    raise RuntimeError("배치 배분 실패 — n_batches를 늘리세요")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--n", type=int, default=60, help="알림 수")
    ap.add_argument("--batches", type=int, default=12)
    ap.add_argument("--seed", type=int, default=20260911)
    ap.add_argument("--outdir", default="blind")
    args = ap.parse_args()

    alerts = build_alerts(args.n, args.seed)
    items = build_items(alerts)
    batches = assign_batches(items, args.batches, args.seed)

    out = Path(args.outdir)
    out.mkdir(exist_ok=True)

    # 정답지는 판정자가 읽는 파일과 완전히 분리한다.
    truth = {it["item_id"]: {k: it[k] for k in
                             ("alert_id", "condition", "variant", "label", "payload_category")}
             for it in items}
    json.dump(truth, open(out / "truth.json", "w"), indent=2)

    for b, batch in enumerate(batches):
        # 판정자에게는 item_id와 prompt만 준다. 조건·라벨·variant 전부 숨김.
        blind = [{"id": it["item_id"], "prompt": it["prompt"]} for it in batch]
        json.dump(blind, open(out / f"batch_{b:02d}.json", "w"),
                  indent=2, ensure_ascii=False)

    from collections import Counter
    print(f"알림 {len(alerts)}건 → 판정 항목 {len(items)}건 → 배치 {args.batches}개")
    print(f"배치당 {min(len(b) for b in batches)}~{max(len(b) for b in batches)}건")
    print("조건 분포:", dict(Counter(i["condition"] for i in items)))
    print("variant 분포:", dict(Counter(i["variant"] for i in items)))
    # 배치별 조건 혼합 확인
    mix = [dict(Counter(i["condition"] for i in b)) for b in batches]
    print(f"\n배치0 조건 혼합: {mix[0]}")
    print(f"배치1 조건 혼합: {mix[1]}")
    dup = [b for b, batch in enumerate(batches)
           if len({i['alert_id'] for i in batch}) != len(batch)]
    print(f"\nalert 중복 배치: {dup or '없음 ✓'}")


if __name__ == "__main__":
    main()
