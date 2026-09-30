"""실 API 클라이언트 ― 캐싱·재시도·비용 집계.

설계 원칙
---------
1. **1항목 1호출, 무상태.** 이전 항목의 판정이 다음 항목에 영향을 주지 않는다.
   서브에이전트 파일럿에서 측정을 망친 것이 바로 이 상태 공유였다.
2. **디스크 캐시.** (모델, system, user)의 해시로 캐싱한다. 중단 후 재실행하면
   이미 받은 응답은 비용 0으로 재사용된다. 실험이 중간에 죽어도 잃는 게 없다.
3. **비용 집계.** 토큰과 추정 비용을 누적해 보고한다.
"""
import hashlib
import json
import os
import re
import threading
import time
from collections import deque
from pathlib import Path

_RETRY_AFTER_RE = re.compile(r"try again in ([\d.]+)s", re.IGNORECASE)
_DAILY_CAP_RE = re.compile(r"requests per day|\(RPD\)|tokens per day|\(TPD\)", re.IGNORECASE)


class RateLimiter:
    """분당 호출 수를 제한하는 슬라이딩 윈도우. 여러 스레드가 공유해서 쓴다.

    무료/미결제 계정은 OpenAI가 RPM을 매우 낮게(예: 10) 잡아둔다. 워커를
    여러 개 띄우면 그 한도를 순식간에 다 써서 429가 연쇄적으로 난다.
    이 리미터는 호출 '전에' 미리 속도를 늦춰서 애초에 429가 나지 않게 한다.
    """

    def __init__(self, rpm: int | None):
        self.rpm = rpm
        self.times: deque[float] = deque()
        self.lock = threading.Lock()

    def acquire(self):
        if not self.rpm:
            return
        while True:
            with self.lock:
                now = time.time()
                while self.times and now - self.times[0] > 60:
                    self.times.popleft()
                if len(self.times) < self.rpm:
                    self.times.append(now)
                    return
                wait = 60 - (now - self.times[0]) + 0.05
            time.sleep(max(wait, 0.05))

# 1M 토큰당 USD. 가격은 바뀌므로 --price 로 덮어쓸 수 있게 해두었다.
PRICES = {
    "gpt-4o-mini":       (0.15, 0.60),
    "gpt-4.1-mini":      (0.40, 1.60),
    "gpt-4.1-nano":      (0.10, 0.40),
    "gpt-4o":            (2.50, 10.00),
    "claude-haiku-4-5":  (1.00, 5.00),
    "claude-sonnet-4-5": (3.00, 15.00),
}


class Usage:
    def __init__(self):
        self.calls = self.cached = self.pin = self.pout = 0

    def add(self, pin, pout):
        self.calls += 1
        self.pin += pin
        self.pout += pout

    def cost(self, model):
        cin, cout = PRICES.get(model, (0.0, 0.0))
        return (self.pin * cin + self.pout * cout) / 1_000_000

    def report(self, model):
        return (f"호출 {self.calls}회 (캐시 적중 {self.cached}회) · "
                f"입력 {self.pin:,} / 출력 {self.pout:,} 토큰 · "
                f"추정 ${self.cost(model):.3f}")


class Client:
    """OpenAI / Anthropic 공통 래퍼."""

    def __init__(self, spec: str, cache_dir: str = ".cache", temperature: float = 0.0,
                 rpm: int | None = None):
        self.provider, _, self.model = spec.partition(":")
        self.temperature = temperature
        self.usage = Usage()
        self.cache = Path(cache_dir) / self.model.replace("/", "_")
        self.cache.mkdir(parents=True, exist_ok=True)
        self.limiter = RateLimiter(rpm)
        # 일일 한도(RPD/TPD)에 걸린 걸 한 번이라도 확인하면 즉시 이 플래그를
        # 세운다. 다른 모든 스레드/작업은 그 뒤로 API를 부르지도 않고 즉시
        # 실패 처리한다 ― 어차피 오늘 안에는 뚫릴 리 없는 걸 항목마다
        # 5번씩 재시도하며 몇 시간을 날리는 걸 막기 위함.
        self._daily_cap_hit = threading.Event()
        self.param_mode = "full"

        if self.provider == "mock":
            # 오프라인 배선 점검용. 실제 모델 행동을 예측하지 않는다.
            from .llm import MockClient
            self._c = MockClient()
            self.model = self.model or "mock"
        elif self.provider == "openai":
            from openai import OpenAI
            if not os.getenv("OPENAI_API_KEY"):
                raise RuntimeError("OPENAI_API_KEY 환경변수가 없습니다.")
            self._c = OpenAI()
        elif self.provider == "anthropic":
            import anthropic
            if not os.getenv("ANTHROPIC_API_KEY"):
                raise RuntimeError("ANTHROPIC_API_KEY 환경변수가 없습니다.")
            self._c = anthropic.Anthropic()
        else:
            raise ValueError(f"지원하지 않는 provider: {self.provider}")

    # 파라미터 규격 단계. full → no_seed → minimal 순으로 내려간다.
    # 캐시 키는 (model, temperature, seed, system, user)로 계산하므로 여기서
    # 무엇을 실제로 전송하든 키는 바뀌지 않는다 ― 배치와 온라인이 같은 캐시를
    # 공유하는 성질은 유지된다.
    PARAM_MODES = ("full", "no_seed", "minimal")

    def _openai_params(self, system, user, seed):
        kw = dict(model=self.model,
                  messages=[{"role": "system", "content": system},
                            {"role": "user", "content": user}])
        if self.param_mode == "full":
            kw["temperature"] = self.temperature
            kw["seed"] = seed
        elif self.param_mode == "no_seed":
            kw["temperature"] = self.temperature
        return kw

    def _downgrade_params(self, msg: str) -> bool:
        """파라미터 거부로 보이면 한 단계 내린다. 내렸으면 True."""
        low = msg.lower()
        looks_like_param_issue = any(
            s in low for s in ("temperature", "seed", "unsupported_parameter",
                               "unsupported value", "unrecognized request argument",
                               "unexpected keyword"))
        if not looks_like_param_issue:
            return False
        i = self.PARAM_MODES.index(self.param_mode)
        if i + 1 >= len(self.PARAM_MODES):
            return False
        self.param_mode = self.PARAM_MODES[i + 1]
        print(f"  [알림] 모델이 파라미터를 거부했습니다. 규격을 "
              f"'{self.param_mode}'로 낮춰서 계속합니다. "
              f"(배치 제출 시 --params {self.param_mode.replace('_', '-')} 를 주세요)",
              flush=True)
        return True

    def _key(self, system, user, seed):
        h = hashlib.sha256()
        for part in (self.model, str(self.temperature), str(seed), system, user):
            h.update(part.encode())
            h.update(b"\x00")
        return self.cache / f"{h.hexdigest()[:40]}.json"

    def _write_cache(self, kf: Path, text: str):
        """원자적 쓰기. 동시에 같은 프롬프트를 처리하는 스레드가 있어도
        읽는 쪽이 반쯤 쓰인 파일을 보지 않도록 임시파일 후 rename 한다."""
        tmp = kf.with_suffix(f".{os.getpid()}.{threading.get_ident()}.tmp")
        tmp.write_text(json.dumps({"text": text}))
        os.replace(tmp, kf)

    def complete(self, system: str, user: str, seed: int = 0, max_retries: int = 5) -> str:
        kf = self._key(system, user, seed)
        if kf.exists():
            try:
                out = json.loads(kf.read_text())["text"]
                self.usage.cached += 1
                return out
            except (json.JSONDecodeError, KeyError, OSError):
                pass        # 손상된 캐시는 무시하고 다시 호출한다

        if self._daily_cap_hit.is_set():
            # 이번 실행에서 이미 일일 한도를 확인했다. 오늘 안에는 안 풀리므로
            # API를 부르지도 않고 바로 실패 처리한다 (남은 항목마다 5번씩
            # 재시도하며 시간·쿼터를 낭비하지 않기 위함).
            raise RuntimeError("일일 한도(RPD/TPD) 도달 확인됨 ― 이번 실행에서는 재시도 안 함")

        last = None
        for attempt in range(max_retries):
            try:
                self.limiter.acquire()   # 호출 전에 속도를 미리 늦춘다 (429 예방)
                if self.provider == "mock":
                    text = self._c.complete(system, user)
                    self.usage.add(len(user) // 4, 40)
                    self._write_cache(kf, text)
                    return text
                if self.provider == "openai":
                    # 상위·추론 모델은 temperature나 seed를 아예 거부하기도 한다.
                    # 거부당하면 파라미터를 한 단계씩 내리고 그 사실을 기억해서
                    # 이후 호출부터는 처음부터 맞는 규격으로 보낸다.
                    kw = self._openai_params(system, user, seed)
                    try:
                        r = self._c.chat.completions.create(**kw)
                    except TypeError:
                        self._downgrade_params("TypeError")
                        r = self._c.chat.completions.create(
                            **self._openai_params(system, user, seed))
                    except Exception as e:
                        if not self._downgrade_params(str(e)):
                            raise
                        r = self._c.chat.completions.create(
                            **self._openai_params(system, user, seed))
                    text = r.choices[0].message.content or ""
                    self.usage.add(r.usage.prompt_tokens, r.usage.completion_tokens)
                else:
                    r = self._c.messages.create(
                        model=self.model, max_tokens=300, temperature=self.temperature,
                        system=system, messages=[{"role": "user", "content": user}])
                    text = r.content[0].text
                    self.usage.add(r.usage.input_tokens, r.usage.output_tokens)

                self._write_cache(kf, text)
                return text
            except Exception as e:            # 레이트리밋·일시 장애 재시도
                last = e
                if _DAILY_CAP_RE.search(str(e)):
                    # RPM처럼 몇 초 기다리면 풀리는 게 아니라 하루 단위 한도다.
                    # 이 프로세스 안에서 더 재시도해봐야 소용없으니 즉시 포기하고,
                    # 다른 스레드/작업들도 곧바로 실패 처리하도록 플래그를 세운다.
                    self._daily_cap_hit.set()
                    break
                if attempt == max_retries - 1:
                    break
                # OpenAI가 429 메시지에 "try again in 6s" 식으로 정확한 대기시간을
                # 알려준다. 있으면 그대로 따르고(+여유 1초), 없으면 지수 백오프.
                m = _RETRY_AFTER_RE.search(str(e))
                wait = float(m.group(1)) + 1.0 if m else min(2 ** attempt, 30)
                time.sleep(wait)
        raise RuntimeError(f"API 호출 실패 ({max_retries}회 재시도): {last}")
