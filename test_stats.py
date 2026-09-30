#!/usr/bin/env python3
"""집계 회귀 테스트 ― 시드 간 alert_id 충돌 버그를 다시 만들지 않기 위한 것.

생성기는 시드마다 알림 id를 A000부터 다시 매긴다. 따라서 집계에서 기록을
alert_id 하나로만 인덱싱하면, 시드가 다른 **서로 다른 알림**이 같은 키로
덮어써진다. 단순한 표본 손실로 끝나지 않는다 ― 앞 시드의 라벨·계층에 뒤
시드의 판정을 맞붙이게 되므로 정답 자체가 어긋난다.

    python test_stats.py
"""
import sys

from src.stats import compare_conditions, summarize


def rec(seed, aid, cond, variant, label, stratum, closed):
    return dict(seed=seed, alert_id=aid, condition=cond, variant=variant,
                label=label, stratum=stratum, payload_category="S2", calls=1,
                verdict=dict(verdict="benign" if closed else "malicious",
                             severity="low", action="close" if closed else "escalate",
                             reason="t", parse_failed=False))


def test_same_id_different_seed_do_not_collide():
    """시드1의 A000(정상)과 시드2의 A000(악성)은 서로 다른 알림이다."""
    recs = [rec(1, "A000", "C", "inj", "benign", "A", False),
            rec(2, "A000", "C", "inj", "malicious", "A", True),
            rec(2, "A000", "C", "clean", "malicious", "A", False)]
    t = summarize(recs, ["C"], strata=("A",))["conditions"]["C"]
    assert t["oer_n"] == 1, f"정상 표본이 사라졌다: oer_n={t['oer_n']}"
    assert t["n"] == 1, f"악성 쌍이 사라졌다: n={t['n']}"


def test_denominator_scales_with_seeds():
    """시드를 늘리면 분모도 그만큼 늘어야 한다."""
    recs = [rec(s, f"A{i:03d}", "C", "inj", "benign", "A", i % 2 == 0)
            for s in (1, 2, 3) for i in range(4)]
    t = summarize(recs, ["C"], strata=("A",))["conditions"]["C"]
    assert t["oer_n"] == 12, f"기대 12, 실제 {t['oer_n']} ― 시드가 덮어써지고 있다"


def test_compare_conditions_uses_seed():
    """대응 비교도 같은 키를 써야 한다. 시드마다 A·B가 갈리면 쌍이 3개다."""
    recs = []
    for s in (1, 2, 3):
        recs.append(rec(s, "A000", "A_cond", "inj", "malicious", "A", True))
        recs.append(rec(s, "A000", "B_cond", "inj", "malicious", "A", False))
    r = compare_conditions(recs, "A_cond", "B_cond")
    assert r["a_only_fail"] == 3, f"기대 3쌍, 실제 {r['a_only_fail']}"


def main():
    fails = 0
    for name, fn in sorted(globals().items()):
        if not name.startswith("test_"):
            continue
        try:
            fn()
            print(f"  PASS  {name}")
        except AssertionError as e:
            fails += 1
            print(f"  FAIL  {name}: {e}")
    print(f"\n{'모두 통과' if not fails else str(fails) + '건 실패'}")
    return 1 if fails else 0


if __name__ == "__main__":
    sys.exit(main())
