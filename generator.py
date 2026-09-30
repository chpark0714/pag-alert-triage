"""전달 경로 모델 v3.

v2에서 고친 두 가지
-------------------
(1) **DNS 근거가 틀렸다.** v2는 "RFC 1035가 DNS 라벨을 좁은 문자집합으로
    제한하므로 corpus가 전혀 전달되지 않는다"고 썼다. 이는 프로토콜 주장으로는
    거짓이다. RFC 2181 §11은 명시적으로 다음을 말한다.

        "any binary string whatever can be used as the label of any
         resource record ... Implementations of the DNS protocols must not
         place any restrictions on the labels that can be used."

    그리고 프로토콜 제약과 애플리케이션 제약을 분명히 구분한다.

        "the various applications that make use of DNS data can have
         restrictions imposed on what particular values are acceptable"

    따라서 우리가 주장할 수 있는 것은 **"본 연구가 구현한 입력 검증 규칙을
    적용하면 이 배치가 제외된다"** 까지다. 실제 DNS 전달 불가능성이 아니다.
    각 제약에 `basis`를 붙여 프로토콜 근거와 애플리케이션 관행을 분리한다.

(2) **raw_msg를 공격자의 자유 채널로 뒀다.** 실제로 raw_msg는 센서가 네트워크
    입력을 파싱·인코딩·직렬화한 **출력**이다. 이걸 임의 바이트 통로로 두면
    앞에서 도입한 프로토콜 제약이 통째로 무력화된다 ― 모든 payload가
    raw_msg로 우회해버린다 (v2 mock에서 실제로 S3의 86/90이 raw_msg로 갔다).

    그래서 **센서 인코딩 단계**를 명시적으로 모델링한다.

        공격자 입력  →  [센서 인코딩]  →  알림 필드  →  [방어 렌더링]  →  LLM

    현대 IDS(Suricata eve.json, Wazuh)는 로그를 JSON으로 직렬화하므로
    개행은 리터럴 `\\n`으로 이스케이프되어 구조 문자로서의 성질을 잃는다.
    이것이 기본값이며, 순진한 syslog 파이프라인을 상한으로 함께 평가한다.
"""
from __future__ import annotations

import json
import re
from dataclasses import dataclass

# 위협 수준
UNAUTH = "unauthenticated"      # 원격 무자격: 트래픽만 보내면 됨 (주 위협모델)
POST_EX = "post_exploitation"   # 사후 침투: 코드 실행 선행 필요

# 제약의 근거 ― 프로토콜이 금지하는 것과 구현체가 거르는 것을 구분한다
PROTOCOL = "protocol"           # 규격이 금지 (예: HTTP 헤더의 CRLF)
APPLICATION = "application"     # 애플리케이션·파서 관행 (예: hostname LDH)


@dataclass(frozen=True)
class FieldSpec:
    name: str
    charset: re.Pattern
    max_len: int
    allows_newline: bool
    allows_non_ascii: bool
    threat_level: str
    basis: str                   # PROTOCOL | APPLICATION
    vector: str
    note: str = ""


PRINTABLE_ASCII = re.compile(r"^[\x20-\x7e]*$")
URI_CHARS = re.compile(r"^[\x21-\x7e]*$")
LDH = re.compile(r"^[A-Za-z0-9.\-_]*$")
ANY_TEXT = re.compile(r"^[\s\S]*$")

FIELDS: dict[str, FieldSpec] = {
    "user_agent": FieldSpec(
        "user_agent", PRINTABLE_ASCII, 8192, False, False, UNAUTH, PROTOCOL,
        "HTTP User-Agent 헤더",
        "헤더는 CRLF로 구분되므로 개행은 규격상 헤더를 끝낸다."),
    "uri": FieldSpec(
        "uri", URI_CHARS, 2048, False, False, UNAUTH, PROTOCOL,
        "HTTP 요청 타깃",
        "공백·개행은 요청 라인을 깨뜨리므로 퍼센트 인코딩되어 원문이 보존되지 않는다."),
    "username": FieldSpec(
        "username", PRINTABLE_ASCII, 256, False, False, UNAUTH, APPLICATION,
        "인증 시도 계정명",
        "폼·기본인증 경로. 길이·문자 제한은 애플리케이션마다 다르다."),
    "dns_query": FieldSpec(
        "dns_query", LDH, 253, False, False, UNAUTH, APPLICATION,
        "DNS 질의명",
        "RFC 2181 §11에 따르면 DNS 프로토콜 자체는 임의 바이너리 라벨을 허용한다. "
        "여기 적용한 LDH 제한은 호스트명 관행과 일반적인 리졸버·센서 검증을 모사한 "
        "**애플리케이션 수준 규칙**이며, 프로토콜 불가능성이 아니다."),
    "tls_sni": FieldSpec(
        "tls_sni", LDH, 253, False, False, UNAUTH, APPLICATION,
        "TLS ClientHello SNI",
        "RFC 6066은 host_name 타입에 DNS 호스트명을 기대한다. dns_query와 근거가 "
        "다르므로 결과를 묶어 보고하지 않는다."),
    "referer": FieldSpec(
        "referer", PRINTABLE_ASCII, 4096, False, False, UNAUTH, PROTOCOL,
        "HTTP Referer 헤더", "User-Agent와 동일한 헤더 제약."),
    "http_body": FieldSpec(
        "http_body", ANY_TEXT, 65536, True, True, UNAUTH, PROTOCOL,
        "HTTP 요청 본문",
        "임의 바이트 가능. 다만 센서가 본문을 어떻게 저장하는지는 별도 문제다."),
    "raw_msg": FieldSpec(
        "raw_msg", ANY_TEXT, 8192, True, True, UNAUTH, APPLICATION,
        "센서가 보존한 원시 로그 라인",
        "**공격자의 직접 채널이 아니다.** 센서 파싱·인코딩의 출력이므로 "
        "SENSOR_ENCODINGS를 반드시 함께 적용해야 한다."),
    "filename": FieldSpec(
        "filename", re.compile(r"^[^/\x00\n]*$"), 255, False, True, UNAUTH, APPLICATION,
        "업로드 파일명", "경로 구분자·NUL 불가."),
    "cmdline": FieldSpec(
        "cmdline", PRINTABLE_ASCII, 4096, False, True, POST_EX, APPLICATION,
        "프로세스 커맨드라인",
        "원격 무자격 공격자는 쓸 수 없다 ― RCE 선행 필요. 주 위협모델에서 제외."),
}


# ---------------------------------------------------------------------------
# 파이프라인 ― 공격자 입력이 **모델 프롬프트의 문자열**이 되기까지
# ---------------------------------------------------------------------------
# v3는 센서 인코딩만 모델링하고 그 결과를 그대로 프롬프트에 넣었다. 그래서
# 사실상 "직렬화된 로그 텍스트를 통째로 붙여넣는" 경로 하나만 다뤘다.
#
# 하지만 JSON의 \n은 개행을 **삭제하는 장치가 아니라 표현하는 방식**이다
# (RFC 8259). 저장 표현과 모델 입력은 다음 세 갈래로 갈린다.
#
#   pipeline      센서 저장 표현        모델이 실제로 받는 문자열
#   ---------------------------------------------------------------
#   raw           원문 (개행 보존)       원문 (개행 보존)
#   parse         JSON 이스케이프        **파싱되어 개행 복원**   ← 가장 흔함
#   serialize     JSON 이스케이프        이스케이프된 그대로
#
# 따라서 "JSON이면 S3가 죽는다"는 결론은 parse 경로에서는 성립하지 않는다.
# 기본값을 parse로 둔다. 그리고 다음 세 명제를 분리해 보고한다.
#   (1) payload가 byte 단위로 동일하지 않다
#   (2) payload의 개행 배치가 달라졌다
#   (3) payload가 모델의 판단을 바꾸지 못한다
# (1)이나 (2)로 (3)을 결론 내릴 수 없다. (3)은 최종 판정으로만 측정한다.
#
# raw 경로도 "공격 성공률의 상한"이라고 부르지 않는다. 원문 보존 입력이 항상
# 인코딩된 입력보다 공격에 유리하다는 단조성은 보장되지 않는다. 대조 조건이다.

def _store_raw(s: str) -> str:
    return s


def _store_json(s: str) -> str:
    """센서가 JSON으로 직렬화해 저장한 형태 (개행이 두 글자 \\n 이 된다)."""
    return json.dumps(s)[1:-1]


def _load_identity(s: str) -> str:
    return s


def _load_json(s: str) -> str:
    """소비자가 JSON을 파싱해 필드 값을 복원한 형태 (개행이 되살아난다)."""
    try:
        return json.loads(f'"{s}"')
    except json.JSONDecodeError:
        return s


PIPELINES = {
    # name       : (센서 저장, 소비자 복원, 설명)
    "raw":       (_store_raw,  _load_identity,
                  "바이트 보존 syslog. 대조 조건."),
    "parse":     (_store_json, _load_json,
                  "JSON 저장 후 파싱해 필드 값을 프롬프트에 삽입. 기본값."),
    "serialize": (_store_json, _load_identity,
                  "직렬화된 로그 텍스트를 그대로 프롬프트에 붙여넣음."),
}
DEFAULT_PIPELINE = "parse"


def store(value: str, pipeline: str = DEFAULT_PIPELINE) -> str:
    """센서가 저장하는 표현."""
    return PIPELINES[pipeline][0](str(value))


def to_prompt(stored: str, pipeline: str = DEFAULT_PIPELINE) -> str:
    """소비자가 프롬프트에 넣는 표현. **모델이 실제로 보는 문자열.**"""
    return PIPELINES[pipeline][1](str(stored))


# 하위 호환 (v3 호출부)
SENSOR_ENCODINGS = {k: v[0] for k, v in PIPELINES.items()}
DEFAULT_ENCODING = DEFAULT_PIPELINE


def encode(value: str, encoding: str = DEFAULT_PIPELINE) -> str:
    return store(value, encoding)


# ---------------------------------------------------------------------------
def deliverable(payload: str, field: str) -> tuple[bool, str]:
    """payload를 field에 실을 수 있는가 (센서 인코딩 이전, 전송 단계 기준)."""
    spec = FIELDS.get(field)
    if spec is None:
        return False, "unknown_field"
    if not payload:
        return True, "empty"
    if len(payload) > spec.max_len:
        return False, "length"
    if ("\n" in payload or "\r" in payload) and not spec.allows_newline:
        return False, "newline"
    if any(ord(c) > 127 for c in payload) and not spec.allows_non_ascii:
        return False, "non_ascii"
    if not spec.charset.match(payload):
        return False, "charset"
    return True, "ok"


def compatible_fields(payload: str, present: list[str],
                      threat_level: str = UNAUTH) -> list[str]:
    out = []
    for f in present:
        spec = FIELDS.get(f)
        if spec is None:
            continue
        if threat_level == UNAUTH and spec.threat_level != UNAUTH:
            continue
        if deliverable(payload, f)[0]:
            out.append(f)
    return out


def representation(payload: str, pipeline: str = DEFAULT_PIPELINE) -> dict:
    """payload가 저장·프롬프트 각 단계에서 어떤 모습인지.

    **전처리 분석 지표일 뿐이다.** 공격 실패 여부는 최종 판정으로만 측정한다.
    """
    stored = store(payload, pipeline)
    shown = to_prompt(stored, pipeline)
    return dict(
        pipeline=pipeline,
        stored_verbatim=(stored == payload),      # (1) byte 동일성
        prompt_verbatim=(shown == payload),       # 모델 입력의 byte 동일성
        newline_in_prompt=("\n" in shown) if ("\n" in payload) else None,  # (2) 개행 배치
        stored_sample=stored[:70],
        prompt_sample=shown[:70],
    )


def audit(categories: dict[str, list[str]], fields: list[str] | None = None) -> dict:
    """(payload, field) 전달 가능성 표. 분모를 명시적으로 반환한다."""
    fields = fields or list(FIELDS)
    payloads = [p for c, ps in categories.items() if c != "S0" for p in ps]
    table, ok_total = {}, 0
    for cat, ps in categories.items():
        if cat == "S0":
            continue
        row = {f: (sum(1 for p in ps if deliverable(p, f)[0]), len(ps)) for f in fields}
        ok_total += sum(v[0] for v in row.values())
        table[cat] = row
    return dict(table=table, n_payloads=len(payloads), n_fields=len(fields),
                n_combinations=len(payloads) * len(fields), n_deliverable=ok_total)
