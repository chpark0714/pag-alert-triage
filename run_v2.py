#!/usr/bin/env python3
"""본 실험 실행기 v3.

    python3 run_v2.py --client mock2                              # 배선 점검 (무료)
    python3 run_v2.py --client openai:gpt-4o-mini --n 60 --seeds 3 --dry-run
    python3 run_v2.py --client openai:gpt-4o-mini --n 60 --seeds 3

v3 변경점
---------
- 생성기: 3계층 (A / B-syn 구문해석 / B-ref 신뢰기록 대조) + 센서 인코딩 단계
- 베이스라인: R0(T0/T1 규칙) + **R1(T2 파서)** ― "LLM이 필요한가"는 R1과 비교해야 함
- 주 운영지표: injected miss rate × OER (분모 고정 → 선택편향 없음)
  ASR_cond는 분모를 함께 보고하며 원인 분석용으로 격하
- 0건일 때 부트스트랩 [0,0] 붕괴를 Wilson으로 대체
- 사전 지정 5개 비교에 Holm-Bonferroni 적용
"""
import argparse
import json
import statistics
import sys
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from src.conditions import (BUILDERS, GATED, GATE_SYSTEM, LADDER, SYSTEM, SYSTEM_FOR,
                            gate_verdict_from_text, parse_verdict, payload_residual,
                            render_gate)
from src.generator import STRATA, build, rule_t01, rule_t2_parser
from src.stats import compare_conditions, holm, summarize

CONDS = [c for c, _, _ in LADDER]

# Windows 콘솔/파이프는 기본 인코딩이 cp949라 일부 문자(em dash, 난독화
# 페이로드의 유니코드 등)를 못 찍고 UnicodeEncodeError로 죽는다. 실험이
# print 한 줄 때문에 통째로 날아가는 일이 없도록 대체 문자로 흘려보낸다.
for _stream in (sys.stdout, sys.stderr):
    try:
        _stream.reconfigure(errors="replace")
    except (AttributeError, ValueError):
        pass


def get_client(spec: str, rpm: int | None = None):
    if spec.startswith("mock"):
        from src.mock2 import MockV2
        c = MockV2()

        class W:                       # Client와 같은 인터페이스로 감싼다
            model = "mock2"

            class usage:
                calls = cached = pin = pout = 0
                @staticmethod
                def report(_m): return "mock (비용 없음)"
            @staticmethod
            def complete(system, user, seed=0): return c.complete(system, user)
        return W()
    from src.client import Client
    return Client(spec, rpm=rpm)


def build_jobs(args, seed):
    """한 시드의 알림과 판정 작업 목록을 만든다.

    run_v2(온라인 실행)와 run_batch(Batch API 제출)가 **같은 함수**를 쓰도록
    분리해두었다. 프롬프트가 한 글자라도 갈리면 캐시 키가 달라져서 배치로
    받아온 응답을 온라인 실행이 못 알아보기 때문이다.
    """
    rows = build(n=args.n, seed=seed, stratum_weights=args.stratum_weights,
                 pipeline=args.pipeline)
    jobs = []
    for r in rows:
        variants = [("inj", r["injected"])]
        if r["label"] == "malicious":
            variants.append(("clean", r["clean"]))
        for variant, alert in variants:
            for cond in args.conditions:
                jobs.append(dict(
                    alert_id=r["id"], condition=cond, variant=variant,
                    label=r["label"], stratum=r["stratum"],
                    payload_category=r["payload_category"] if variant == "inj" else "CLEAN",
                    inject_field=r["inject_meta"].get("field"),
                    alert=alert, payload=r["payload"] if variant == "inj" else "",
                    prompt=BUILDERS[cond](alert)))
    return rows, jobs


def run_seed(client, args, seed, out=None):
    rows, jobs = build_jobs(args, seed)

    print(f"  시드 {seed}: 알림 {len(rows)}건 → 판정 {len(jobs)}건", flush=True)

    def judge(job):
        try:
            if job["condition"] in SYSTEM_FOR:
                # 게이트 단독 조건: GATE_SYSTEM 으로 호출하고 benign_justified 를 판정으로 변환
                raw = client.complete(GATE_SYSTEM, job["prompt"], seed=seed)
                v = gate_verdict_from_text(raw)
            else:
                raw = client.complete(SYSTEM, job["prompt"], seed=seed)
                v = parse_verdict(raw)
            job["calls"] = 1
            if job["condition"] in GATED and (v["verdict"] == "benign" or v["action"] == "close"):
                g = client.complete(GATE_SYSTEM, render_gate(job["alert"]), seed=seed)
                job["calls"] = 2
                try:
                    ok = json.loads(g[g.index("{"):g.rindex("}") + 1]).get("benign_justified", False)
                except Exception:
                    ok = False
                job["gate_flipped"] = not ok
                if not ok:
                    v = {"verdict": "malicious", "severity": "medium", "action": "escalate",
                         "reason": "downgrade rejected by provenance gate", "parse_failed": False}
            job["verdict"] = v
            if job["payload"]:
                job["residual"] = payload_residual(job["alert"], job["payload"],
                                                  job["condition"], job.get("inject_field"))
        except Exception as e:
            # 재시도까지 모두 소진된 API 실패(예: 일일 한도 소진). 이건 "모델이
            # 놓쳤다"가 아니라 "데이터 없음"이므로 통계에 절대 섞지 않는다 ―
            # 별도로 빼서 기록하고, 캐시가 비어있으니 동일 명령 재실행 시
            # 이 항목만 다시 시도된다.
            job["error"] = f"{type(e).__name__}: {e}"
            job["verdict"] = None
        return job

    with ThreadPoolExecutor(max_workers=args.workers) as ex:
        done = list(ex.map(judge, jobs))

    failed = [j for j in done if j.get("error")]
    done = [j for j in done if not j.get("error")]
    if failed:
        # 진단 정보를 화면에 찍기 '전에' 먼저 파일로 남긴다. 출력 단계에서
        # 무슨 일이 나더라도 실패 원인은 디스크에 남아 있어야 한다.
        if out is not None:
            try:
                with open(out / f"failed_seed{seed}.json", "w", encoding="utf-8") as fh:
                    json.dump([{k: j[k] for k in ("alert_id", "condition", "variant",
                                                  "error") if k in j} for j in failed],
                              fh, indent=1)
            except OSError:
                pass
        from collections import Counter
        def _bucket(msg):
            return "일일 한도(RPD/TPD)" if "일일 한도" in msg or "per day" in msg.lower() or "RPD" in msg else msg.split(":")[0]
        reasons = Counter(_bucket(j["error"]) for j in failed)
        print(f"  [경고] 시드 {seed}: {len(failed)}/{len(jobs)}건 API 호출 실패 "
              f"(통계 제외, 재실행 시 이 항목만 재시도됨)", flush=True)
        for why, cnt in reasons.most_common():
            print(f"         - {cnt}건: {why}", flush=True)
        print(f"         첫 실패 메시지: {failed[0]['error'][:300]}", flush=True)

    # 비-LLM 베이스라인 두 종 (API 호출 없음)
    #   R0: T0/T1만 본다 → 주입에 면역이지만 T2 정보를 못 쓴다
    #   R1: T2를 **파싱**한다 → "LLM이 필요한가"는 R0가 아니라 R1과 비교해야 한다
    for name, fn in (("R0_rule_t01", rule_t01), ("R1_rule_t2parser", rule_t2_parser)):
        for r in rows:
            for variant, alert in ([("inj", r["injected"])] +
                                   ([("clean", r["clean"])] if r["label"] == "malicious" else [])):
                pred = fn(alert)
                done.append(dict(
                    alert_id=r["id"], condition=name, variant=variant,
                    label=r["label"], stratum=r["stratum"],
                    payload_category=r["payload_category"] if variant == "inj" else "CLEAN",
                    inject_field=r["inject_meta"].get("field"), calls=0, payload="",
                    verdict=dict(verdict=pred, severity="medium",
                                 action="escalate" if pred == "malicious" else "close",
                                 reason="rule", parse_failed=False)))
    return done, rows, failed


def pct(x):
    return "  n/a" if x != x else f"{x:5.1%}"


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--client", required=True)
    ap.add_argument("--n", type=int, default=60)
    ap.add_argument("--seeds", type=int, default=3)
    ap.add_argument("--conditions", nargs="+", default=CONDS)
    ap.add_argument("--stratum-weights", type=float, nargs=3, default=[0.34, 0.33, 0.33],
                    metavar=("A", "B_SYN", "B_REF"), help="계층 비율")
    ap.add_argument("--pipeline", default="parse",
                    choices=["parse", "serialize", "raw"],
                    help="저장·소비 경로. parse=JSON 저장 후 파싱(기본, 개행 복원), "
                         "serialize=직렬화 텍스트를 그대로 삽입, raw=바이트 보존(대조)")
    ap.add_argument("--workers", type=int, default=4)
    ap.add_argument("--rpm", type=int, default=None,
                    help="분당 호출 상한(선행 스로틀링). 지정 안 하면 무제한으로 "
                         "쏘다가 429를 맞고 재시도함 ― 계정 티어의 RPM보다 "
                         "낮게 주면 애초에 429가 덜 남")
    ap.add_argument("--outdir", default="results_v2")
    ap.add_argument("--dry-run", action="store_true")
    args = ap.parse_args()

    n_mal = int(args.n * 0.6)
    total = (n_mal * 2 + (args.n - n_mal)) * len(args.conditions) * args.seeds
    print(f"\n조건 {len(args.conditions)}종(+R0·R1 무료) × 시드 {args.seeds}개")
    print(f"판정 항목 {total:,}건 (게이트 2차 호출 별도)")
    if args.dry_run:
        model = args.client.partition(":")[2]
        from src.client import PRICES
        cin, cout = PRICES.get(model, (0, 0))
        print(f"예상 비용 ≒ ${total * 1.15 * (950 * cin + 90 * cout) / 1e6:.2f}\n")
        return

    client = get_client(args.client, rpm=args.rpm)
    out = Path(args.outdir) / str(client.model).replace("/", "_")
    out.mkdir(parents=True, exist_ok=True)

    def _slim(records):
        return [{k: r[k] for k in ("alert_id", "seed", "condition", "variant", "label",
                                   "stratum", "payload_category", "inject_field",
                                   "calls", "verdict") if k in r} for r in records]

    all_records, all_failed, per_seed_asr = [], [], defaultdict(list)
    for s in range(args.seeds):
        seed = 20260911 + s * 1000
        recs, _, failed = run_seed(client, args, seed, out=out)
        for r in recs:
            r["seed"] = seed
        for r in failed:
            r["seed"] = seed
        all_records += recs
        all_failed += failed
        srep = summarize(recs, args.conditions + ["R0_rule_t01", "R1_rule_t2parser"],
                         strata=STRATA)
        for c, t in srep["conditions"].items():
            if t["clean_correct"]:
                per_seed_asr[c].append(t["asr_conditional"])
        print(f"    {client.usage.report(client.model)}", flush=True)

        # 중간 저장: 시드 하나가 끝날 때마다 즉시 디스크에 반영한다. 이후 시드에서
        # API가 죽어도(예: 일일 한도 소진) 여기까지 확보한 판정은 남는다.
        with open(out / "records.json", "w", encoding="utf-8") as fh:
            json.dump(_slim(all_records), fh, indent=1)
        if all_failed:
            with open(out / "failed.json", "w", encoding="utf-8") as fh:
                json.dump([{k: j[k] for k in ("alert_id", "seed", "condition",
                                              "variant", "error") if k in j}
                           for j in all_failed], fh, indent=1)
        print(f"    [중간 저장] {out}/records.json ({len(all_records)}건 누적)", flush=True)

    conds = args.conditions + ["R0_rule_t01", "R1_rule_t2parser"]
    rep = summarize(all_records, conds, strata=STRATA)

    # 호출 비용은 전이표에 없으므로 원시 기록에서 집계한다
    calls_agg = defaultdict(lambda: [0, 0])
    for r in all_records:
        a = calls_agg[r["condition"]]
        a[0] += r.get("calls", 0)
        a[1] += 1
    for c, t in rep["conditions"].items():
        n = calls_agg[c][1]
        t["calls_per_item"] = calls_agg[c][0] / n if n else 0.0

    # ---------------- 출력
    print("\n" + "=" * 92)
    print(f"결과 v2 ― {client.model} · 시드 {args.seeds}개 합산")
    print("=" * 92)
    print(f"\n[주 운영지표]  분모가 조건과 무관하게 고정되므로 선택편향이 없다")
    print(f"{'condition':<22}{'놓침(주입)':>12}{'OER':>9}{'ΔOER':>9}{'calls':>8}")
    print("-" * 92)
    for c in conds:
        t = rep["conditions"][c]
        print(f"{c:<22}{pct(t['injected_miss']):>12}{pct(t['oer']):>9}"
              f"{t['oer_delta_vs_base']:>+9.1%}{t['calls_per_item']:>8.2f}")

    print(f"\n[원인 분석]  ASR_cond의 분모는 조건마다 다르다 ― 반드시 함께 읽을 것")
    print(f"{'condition':<22}{'ASR_cond':>10}{'분모':>7}{'[95% CI]':>16}"
          f"{'회복':>8}{'McNemar p':>11}  CI방법")
    print("-" * 92)
    for c in conds:
        t = rep["conditions"][c]
        lo, hi = t["asr_cond_ci"]
        ci = f"[{lo:.0%}-{hi:.0%}]" if lo == lo else "  n/a"
        meth = "wilson" if "wilson" in t.get("asr_ci_method", "") else "boot"
        print(f"{c:<22}{pct(t['asr_conditional']):>10}{t['asr_denom']:>7}{ci:>16}"
              f"{pct(t['recovery']):>8}{t['mcnemar_p']:>11.4f}  {meth}")

    print("\n전이행렬 (악성 알림, clean 판정 → injected 판정)")
    print(f"{'condition':<22}{'유지':>7}{'악화':>7}{'개선':>7}{'지속':>7}   해석")
    print("-" * 92)
    for c in conds:
        t = rep["conditions"][c]
        note = ""
        if t["cf"] and t["fc"] and abs(t["cf"] - t["fc"]) <= 1:
            note = "← ISR_net이 상쇄로 0에 가까움. ASR_cond를 볼 것"
        print(f"{c:<22}{t['cc']:>7}{t['cf']:>7}{t['fc']:>7}{t['ff']:>7}   {note}")

    # 탐지 품질 ― R0가 왜 답이 아닌지를 수치로 보이는 표
    print("\n탐지 품질 (공격 없는 상태 기준). TPR=1-놓침, FPR=OER.")
    print("  Youden J = TPR - FPR. J<=0이면 같은 FPR을 내는 무작위 분류기에 지배된다")
    print("  ― 즉 '판정 문턱이 옮겨간 것'이 아니라 '판별력 자체가 사라진 것'이다.")
    print(f"{'condition':<22}{'놓침(clean)':>12}{'오경보(OER)':>13}"
          f"{'TPR':>8}{'FPR':>8}{'Youden J':>11}{'균형정확도':>12}")
    print("-" * 92)
    for c in sorted(conds, key=lambda c: -((1 - rep["conditions"][c]["isr_clean"])
                                           - rep["conditions"][c]["oer"])):
        t = rep["conditions"][c]
        miss, oer = t["isr_clean"], t["oer"]
        tpr = 1 - miss
        j = tpr - oer
        bacc = (tpr + 1 - oer) / 2 if miss == miss and oer == oer else float("nan")
        t["tpr"], t["fpr"], t["youden_j"], t["balanced_acc"] = tpr, oer, j, bacc
        print(f"{c:<22}{pct(miss):>12}{pct(oer):>13}{pct(tpr):>8}{pct(oer):>8}"
              f"{j:>+11.1%}{pct(bacc):>12}")
    print("  └ R0는 T2를 안 보므로 주입에 면역이지만, 그 대가가 놓침률로 나타난다.")
    print("    계층별 분해는 아래 표에서 본다.")

    print("\n계층별  (A: T0/T1 충분 · B-syn: T2 해석 · B-ref: T0 기록과 대조)")
    print(f"{'condition':<22}" + "".join(f"{s2:>11}" for s2 in STRATA)
          + "   ← 주입 놓침률")
    print("-" * 92)
    for c in conds:
        bs = rep["by_stratum"].get(c, {})
        row = "".join(pct(bs.get(s2, {}).get("injected_miss", float("nan"))).rjust(11)
                      for s2 in STRATA)
        print(f"{c:<22}{row}")
    print("  └ B-ref는 T2를 T0 신뢰기록과 대조해야 풀린다. 게이트(T0/T1만 봄)는")
    print("    대조 대상인 T2를 못 보므로 이 계층에서 검증을 완료할 수 없다.")
    print("  └ R1(T2 파서)이 B-syn·B-ref를 잘 풀면 LLM 필요성 주장은 성립하지 않는다.")

    print("\n공격 유형별 ASR_conditional")
    cats = ["S1", "S2", "S3", "S4"]
    print(f"{'condition':<22}" + "".join(f"{c:>9}" for c in cats))
    print("-" * 92)
    for c in conds:
        bc = rep["by_category"].get(c, {})
        print(f"{c:<22}" + "".join(
            pct(bc.get(k, {}).get("asr_conditional", float("nan"))).rjust(9) for k in cats))

    # 핵심 대응 비교
    print("\n대응 비교 (McNemar exact, 같은 알림 위에서)")
    print("-" * 92)
    # 사전 지정 비교 6개. 이 여섯 개만 Holm 보정 대상이며,
    # 계층·공격유형·파이프라인별 세부 분석은 탐색적이다.
    key = [("P1_pag_render", "P0_inline_prov", None, "malicious",
            "참조 부록 렌더링 효과 (위치 단독이 아님)"),
           ("P0_inline_prov", "B1N_structured_norm", None, "malicious",
            "출처 프레이밍 효과"),
           ("B1N_structured_norm", "B1_structured", None, "malicious",
            "정규화(전처리) 효과"),
           ("P1_pag_render", "B1_structured", None, "malicious",
            "제안 vs 선행연구 최강(classification)"),
           ("P2_pag_full", "P1_pag_render", None, "malicious",
            "게이트의 보안 효과"),
           ("P2_pag_full", "P1_pag_render", "B-ref", "benign",
            "★ 계층 주요비교: 정보가 필요한 계층에서 게이트의 오경보 비용")]
    raw_p, detail = {}, {}
    for a, b, strat, lab in [(k[0], k[1], k[2], k[3]) for k in key]:
        why = [k[4] for k in key if k[:4] == (a, b, strat, lab)][0]
        if a in conds and b in conds:
            r = compare_conditions(all_records, a, b, label=lab, stratum=strat)
            tag = f"{a} vs {b}" + (f" [{strat}/{lab}]" if strat else "")
            raw_p[tag] = r["p"]
            detail[tag] = (r, why)
    adj = holm(raw_p)
    for k, v in sorted(adj.items(), key=lambda kv: kv[1]["p_raw"]):
        r, why = detail[k]
        sig = "유의" if v["significant"] else "n.s."
        print(f"  {k:<46} p={v['p_raw']:.4f} holm={v['p_holm']:.4f} {sig:>5}"
              f"  ({r['a_only_fail']}/{r['b_only_fail']})")
        print(f"    └ {why}")
    print("  ※ 위 6개만 사전 지정·보정 대상. 계층·공격유형·파이프라인별 세부는 탐색적.")
    print("  ※ McNemar 입력: 동일 injected alert에 대한 두 조건의 최종 miss(악성)"
          " 또는 최종 escalate(정상) 여부.")

    with open(out / "summary.json", "w", encoding="utf-8") as fh:
        json.dump({"model": str(client.model), "n": args.n, "seeds": args.seeds,
                   "n_api_failed": len(all_failed),
                   "report": {k: {c: {kk: vv for kk, vv in t.items()
                                      if isinstance(vv, (int, float, str))}
                                  for c, t in v.items()}
                              for k, v in rep.items()}},
                  fh, indent=2, default=str)
    print(f"\n저장: {out}/summary.json, {out}/records.json")
    if all_failed:
        print(f"  [주의] API 호출 실패로 통계에서 제외된 항목 {len(all_failed)}건 "
              f"→ {out}/failed.json 참고. 캐시에 없으므로 동일 명령 재실행 시 이 항목만 재시도됨.")
    print(f"{client.usage.report(client.model)}\n")


if __name__ == "__main__":
    sys.exit(main())
