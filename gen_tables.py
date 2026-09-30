#!/usr/bin/env python3
"""표·본문 수치를 **하나의 집계 결과에서** 생성한다.

버전마다 손으로 입력한 수치가 어긋나는 것을 막기 위해, 논문에 들어가는
전달 가능성 표와 분모는 전부 이 스크립트가 출력한 값을 쓴다.
"""
import json
from src.delivery import FIELDS, UNAUTH, deliverable
from src.payloads import CATEGORIES

CATS = ["S1", "S2", "S3", "S4"]


def main():
    payloads = [p for c, ps in CATEGORIES.items() if c != "S0" for p in ps]
    rows, per = [], {}
    for f, spec in FIELDS.items():
        counts = [sum(1 for p in CATEGORIES[c] if deliverable(p, f)[0]) for c in CATS]
        per[f] = counts
        rows.append([f, "P" if spec.basis == "protocol" else "A", *map(str, counts)])

    n_f, n_p = len(FIELDS), len(payloads)
    total = n_f * n_p
    ok = sum(sum(v) for v in per.values())

    unauth = [f for f, s in FIELDS.items() if s.threat_level == UNAUTH]
    p_total = len(unauth) * n_p
    p_ok = sum(sum(per[f]) for f in unauth)

    print("TABLE II (paper) — 필드별 전달 가능 payload 수 (각 유형 15개 중)")
    print(f"{'Field':<14}{'Basis':>6}" + "".join(f"{c:>6}" for c in CATS) + f"{'Sum':>6}")
    for r in rows:
        print(f"{r[0]:<14}{r[1]:>6}" + "".join(f"{x:>6}" for x in r[2:]) +
              f"{sum(per[r[0]]):>6}")
    print()
    print(f"전체 감사 분모   : {n_p} payload × {n_f} field = {total}")
    print(f"  전달 가능      : {ok} ({ok/total:.1%})")
    print(f"  제외           : {total-ok} ({1-ok/total:.1%})")
    print(f"주 실험 분모     : {n_p} × {len(unauth)} field (cmdline 제외) = {p_total}")
    print(f"  전달 가능      : {p_ok} ({p_ok/p_total:.1%})")
    print(f"  제외           : {p_total-p_ok} ({1-p_ok/p_total:.1%})")

    json.dump(dict(per_field=per, n_payloads=n_p, n_fields=n_f,
                   audit_total=total, audit_deliverable=ok,
                   primary_fields=unauth, primary_total=p_total,
                   primary_deliverable=p_ok),
              open("deliverability.json", "w"), indent=2)
    print("\n저장: deliverability.json  (원고 표는 이 파일에서 생성)")


if __name__ == "__main__":
    main()
