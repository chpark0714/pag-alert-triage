"""필드 신뢰 등급 (D1).

내용이 아니라 '필드 이름'으로 신뢰도를 정한다.
내용 기반 판단은 공격자가 조작할 수 있지만, 스키마는 조작할 수 없다.
"""

# T0: IDS/센서가 생성한 필드. 공격자 영향 없음.
T0_TRUSTED = {
    "rule_id", "signature", "sensor", "detect_time", "severity_prior",
    "category", "ids_engine",
}

# T1: 인프라가 측정한 관측값. 값 자체는 공격자가 유발하지만 '문자열'을 쓸 수는 없음.
T1_OBSERVED = {
    "src_ip", "dst_ip", "src_port", "dst_port", "proto",
    "bytes_in", "bytes_out", "conn_count", "duration_ms", "http_status",
}

# T2: 공격자가 문자열 내용을 직접 기록하는 필드. ← 인젝션 통로
T2_UNTRUSTED = {
    "user_agent", "uri", "http_body", "dns_query", "username",
    "cmdline", "raw_msg", "referer", "filename", "tls_sni",
}


def tier(field: str) -> str:
    if field in T0_TRUSTED:
        return "T0"
    if field in T1_OBSERVED:
        return "T1"
    if field in T2_UNTRUSTED:
        return "T2"
    return "T2"  # 미지의 필드는 비신뢰로 취급 (fail-closed)


def split_by_tier(alert: dict) -> tuple[dict, dict]:
    """알림을 (신뢰 가능 필드, 비신뢰 필드)로 분리."""
    trusted = {k: v for k, v in alert.items() if tier(k) in ("T0", "T1")}
    untrusted = {k: v for k, v in alert.items() if tier(k) == "T2"}
    return trusted, untrusted
