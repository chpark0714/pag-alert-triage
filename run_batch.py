#!/usr/bin/env python3
"""Batch API 실행기 ― 일일 한도(RPD)를 우회해서 본실험을 완주하기 위한 경로.

왜 배치인가
-----------
이 실험은 (1) 프롬프트가 전부 사전에 결정돼 있고, (2) temperature=0이며,
(3) 항목 간 상태 공유가 없다. 즉 동기 호출이 줄 수 있는 이점이 하나도 없다.
반면 Batch API는 일반 RPM/RPD와 **별도의 한도**를 쓰고 비용이 절반이다.

설계 원칙
---------
프롬프트 생성은 run_v2.build_jobs()를 **그대로 import** 해서 쓴다. 배치와
온라인 실행이 같은 프롬프트를 만들어야 캐시 키가 일치한다.

custom_id로 **캐시 파일 이름(해시)** 을 그대로 쓴다. 그래서 결과를 받으면
별도 매핑 없이 .cache/<model>/<custom_id>.json 으로 떨어뜨리기만 하면 되고,
그 다음부터 run_v2.py는 API를 한 번도 부르지 않고 캐시만으로 완주한다.

사용법
------
    python run_batch.py submit --client openai:gpt-4o-mini --n 60 --seeds 3
    python run_batch.py status
    python run_batch.py fetch
    (게이트 2차 호출분이 남으므로 fetch 후 submit을 한 번 더 실행한다)
    python run_v2.py --client openai:gpt-4o-mini --n 60 --seeds 3   # 캐시만으로 완주

submit은 **멱등**이다. 이미 캐시에 있는 항목은 절대 다시 넣지 않으므로,
몇 번을 실행해도 남은 것만 큐에 들어간다.
"""
import argparse
import json
import sys
from pathlib import Path

from src.conditions import GATE_SYSTEM, GATED, SYSTEM, SYSTEM_FOR, parse_verdict, render_gate
from run_v2 import CONDS, build_jobs

for _stream in (sys.stdout, sys.stderr):
    try:
        _stream.reconfigure(errors="replace")
    except (AttributeError, ValueError):
        pass

STATE = Path("batch_state.json")


def body(client, system, user, seed):
    """배치 요청 본문. client.param_mode 에 따라 파라미터를 뺀다."""
    b = {"model": client.model,
         "messages": [{"role": "system", "content": system},
                      {"role": "user", "content": user}]}
    if client.param_mode == "full":
        b["temperature"] = client.temperature
        b["seed"] = seed
    elif client.param_mode == "no_seed":
        b["temperature"] = client.temperature
    return b


def seeds_of(args):
    return [20260911 + s * 1000 for s in range(args.seeds)]


def needed_requests(client, args):
    """아직 캐시에 없는 호출 목록을 만든다.

    1단계(판정)와 2단계(게이트)를 함께 훑는다. 게이트 호출은 1단계 결과가
    있어야 필요 여부를 알 수 있으므로, 1단계가 아직 캐시에 없으면 건너뛴다
    ― fetch 후 submit을 다시 돌리면 그때 잡힌다.
    """
    reqs, pending_gate = {}, 0
    for seed in seeds_of(args):
        _, jobs = build_jobs(args, seed)
        for job in jobs:
            sysp = GATE_SYSTEM if job["condition"] in SYSTEM_FOR else SYSTEM
            kf = client._key(sysp, job["prompt"], seed)
            if not kf.exists():
                reqs.setdefault(kf.stem, (sysp, job["prompt"], seed))
                continue
            if job["condition"] not in GATED:
                continue
            # 1단계가 이미 있으니 게이트가 필요한지 판정해본다
            try:
                raw = json.loads(kf.read_text(encoding="utf-8"))["text"]
            except (OSError, json.JSONDecodeError, KeyError):
                continue
            v = parse_verdict(raw)
            if v["verdict"] == "benign" or v["action"] == "close":
                gp = render_gate(job["alert"])
                gkf = client._key(GATE_SYSTEM, gp, seed)
                if not gkf.exists() and gkf.stem not in reqs:
                    reqs[gkf.stem] = (GATE_SYSTEM, gp, seed)
                    pending_gate += 1      # 중복 제거 후의 고유 호출 수
    return reqs, pending_gate


def stage1_keys(client, args):
    """1단계 호출의 고유 캐시 키 집합.

    조건이 달라도 프롬프트가 **바이트 단위로 같으면** 같은 호출이다
    (예: P2의 1단계는 P1과 동일하다). 그런 항목은 한 번만 호출하면 되고,
    temperature=0이므로 같은 응답을 공유하는 것이 오히려 비교를 정확하게
    만든다 ― 두 조건의 차이가 프롬프트가 아닌 곳에서만 생기기 때문이다.
    """
    keys, njobs = {}, 0
    for seed in seeds_of(args):
        _, jobs = build_jobs(args, seed)
        njobs += len(jobs)
        for job in jobs:
            sysp = GATE_SYSTEM if job["condition"] in SYSTEM_FOR else SYSTEM
            keys[client._key(sysp, job["prompt"], seed).stem] = True
    return keys, njobs


def load_state():
    if STATE.exists():
        return json.loads(STATE.read_text(encoding="utf-8"))
    return {"batches": []}


def save_state(st):
    with open(STATE, "w", encoding="utf-8") as fh:
        json.dump(st, fh, indent=1)


def cmd_submit(args):
    from src.client import Client
    client = Client(args.client)
    client.param_mode = args.params.replace("-", "_")
    reqs, gate_n = needed_requests(client, args)
    keys, njobs = stage1_keys(client, args)
    need1 = sum(1 for k in reqs if k in keys)
    print(f"\n판정 항목 {njobs:,}건 → 고유 1단계 호출 {len(keys):,}건 "
          f"(프롬프트가 같은 조건끼리는 한 번만 호출)")
    print(f"  그중 캐시 완료 {len(keys) - need1:,}건 / 남은 호출 {need1:,}건")
    if gate_n:
        print(f"게이트 2차 호출 필요 {gate_n:,}건")
    if not reqs:
        print("큐에 넣을 항목이 없습니다. 캐시가 이미 완전합니다.")
        print("이제 run_v2.py를 그대로 실행하면 호출 0회로 완주합니다.\n")
        return
    print(f"이번에 제출할 신규 호출 {len(reqs):,}건")

    items = sorted(reqs.items())
    tok = sum(len(u) for _, (s, u, _) in items) // 4
    print(f"예상 입력 토큰 ≒ {tok:,} (배치 큐 한도는 티어별로 다름)")
    if args.dry_run:
        print("--dry-run: 실제 제출은 하지 않았습니다.\n")
        return

    st = load_state()
    chunks = [items[i:i + args.max_per_batch]
              for i in range(0, len(items), args.max_per_batch)]
    print(f"{len(chunks)}개 배치로 나눠 제출합니다 (배치당 최대 {args.max_per_batch:,}건)\n")

    for ci, chunk in enumerate(chunks, 1):
        path = Path(f"batch_input_{ci}.jsonl")
        with open(path, "w", encoding="utf-8") as fh:
            for cid, (system, user, seed) in chunk:
                fh.write(json.dumps({
                    "custom_id": cid,
                    "method": "POST",
                    "url": "/v1/chat/completions",
                    # 본문은 온라인 경로(Client.complete)와 **동일**해야 한다.
                    # 단, temperature/seed를 거부하는 모델은 --params 로 뺀다.
                    # 캐시 키는 본문이 아니라 (model, temperature, seed, 프롬프트)로
                    # 계산하므로 여기서 무엇을 빼든 키는 그대로다.
                    "body": body(client, system, user, seed),
                }, ensure_ascii=False) + "\n")
        try:
            up = client._c.files.create(file=open(path, "rb"), purpose="batch")
            b = client._c.batches.create(input_file_id=up.id,
                                         endpoint="/v1/chat/completions",
                                         completion_window="24h",
                                         metadata={"description": f"soc-injection {ci}/{len(chunks)}"})
        except Exception as e:
            print(f"  [{ci}/{len(chunks)}] 제출 실패: {type(e).__name__}: {e}")
            print("  큐 토큰 한도 초과라면 --max-per-batch 를 줄여서 다시 시도하세요.")
            save_state(st)
            return
        st["batches"].append({"id": b.id, "n": len(chunk), "file": str(path),
                              "status": b.status, "fetched": False})
        print(f"  [{ci}/{len(chunks)}] {b.id} 제출 완료 ({len(chunk):,}건, status={b.status})")
        save_state(st)

    print("\n제출 끝. 보통 수십 분~24시간 안에 처리됩니다.")
    print("  python run_batch.py status   로 진행 상황 확인")
    print("  python run_batch.py fetch    로 결과를 캐시에 내려받기\n")


def cmd_status(args):
    from src.client import Client
    client = Client(args.client)
    st = load_state()
    if not st["batches"]:
        print("\n제출된 배치가 없습니다.\n")
        return
    print()
    done = 0
    for b in st["batches"]:
        try:
            cur = client._c.batches.retrieve(b["id"])
        except Exception as e:
            print(f"  {b['id']}  조회 실패: {e}")
            continue
        b["status"] = cur.status
        rc = getattr(cur, "request_counts", None)
        prog = f"{rc.completed}/{rc.total} (실패 {rc.failed})" if rc else ""
        flag = " [내려받음]" if b["fetched"] else ""
        print(f"  {b['id']}  {cur.status:<12} {prog}{flag}")
        if cur.status == "completed" and not b["fetched"]:
            done += 1
    save_state(st)
    if done:
        print(f"\n내려받을 수 있는 배치 {done}개 → python run_batch.py fetch\n")
    else:
        print()


def cmd_fetch(args):
    from src.client import Client
    client = Client(args.client)
    st = load_state()
    written = errors = 0
    for b in st["batches"]:
        if b["fetched"]:
            continue
        try:
            cur = client._c.batches.retrieve(b["id"])
        except Exception as e:
            print(f"  {b['id']} 조회 실패: {e}")
            continue
        if cur.status != "completed":
            print(f"  {b['id']} 아직 {cur.status} ― 건너뜀")
            continue
        text = client._c.files.content(cur.output_file_id).text
        for line in text.splitlines():
            if not line.strip():
                continue
            rec = json.loads(line)
            if rec.get("error") or not rec.get("response") or \
                    rec["response"].get("status_code") != 200:
                errors += 1
                continue
            body = rec["response"]["body"]
            content = body["choices"][0]["message"]["content"] or ""
            # custom_id가 곧 캐시 파일 이름이다
            client._write_cache(client.cache / f"{rec['custom_id']}.json", content)
            written += 1
        b["fetched"] = True
        b["status"] = cur.status
        save_state(st)
        print(f"  {b['id']} 내려받기 완료")

    print(f"\n캐시에 기록 {written:,}건" + (f", 실패 {errors:,}건" if errors else ""))
    reqs, gate_n = needed_requests(client, args)
    if reqs:
        print(f"아직 남은 호출 {len(reqs):,}건"
              + (f" (그중 게이트 2차 {gate_n:,}건)" if gate_n else ""))
        print("→ python run_batch.py submit 을 한 번 더 실행하세요.\n")
    else:
        print("모든 호출이 캐시에 있습니다.")
        print("→ 이제 run_v2.py를 실행하면 API 호출 0회로 결과가 나옵니다.\n")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("cmd", nargs="?", choices=["submit", "status", "fetch"])
    ap.add_argument("--client", default="openai:gpt-4o-mini")
    ap.add_argument("--n", type=int, default=60)
    ap.add_argument("--seeds", type=int, default=3)
    ap.add_argument("--conditions", nargs="+", default=CONDS)
    ap.add_argument("--stratum-weights", type=float, nargs=3, default=[0.34, 0.33, 0.33])
    ap.add_argument("--pipeline", default="parse", choices=["parse", "serialize", "raw"])
    ap.add_argument("--max-per-batch", type=int, default=1000,
                    help="배치 1개에 넣을 최대 요청 수. 큐 토큰 한도에 걸리면 줄인다")
    ap.add_argument("--params", default="full",
                    choices=["full", "no-seed", "minimal"],
                    help="요청 본문에 넣을 파라미터. temperature/seed를 거부하는 "
                         "모델은 minimal 로 준다 (온라인 스모크 테스트가 알려줌)")
    ap.add_argument("--models", action="store_true",
                    help="사용 가능한 모델 id를 출력하고 끝낸다")
    ap.add_argument("--dry-run", action="store_true")
    args = ap.parse_args()
    if args.models:
        from src.client import Client
        c = Client(args.client)
        ids = sorted(m.id for m in c._c.models.list().data)
        print("\n사용 가능한 모델 id\n" + "-" * 40)
        for i in ids:
            print(" ", i)
        print(f"\n총 {len(ids)}개\n")
        return 0
    if not args.cmd:
        ap.error("submit / status / fetch 중 하나를 지정하세요 (또는 --models)")
    {"submit": cmd_submit, "status": cmd_status, "fetch": cmd_fetch}[args.cmd](args)


if __name__ == "__main__":
    sys.exit(main())
