# ICCA'26 제출판 (v13 short) — 감축 기록

대상: IEEE-ICCA'26, A4 6쪽, 마감 2026-10-30. 긴 판(v12, 16쪽)은 GitHub 저장소에 "extended version"으로 동봉.

## 결과
- `PAG_paper_ICCA26_short.pdf` — 6쪽, 5,287단어 (v12: 16쪽, 13,365단어)
- 소스 `content_v13_short.js` + `build13.js` (A4, 여백 19/43/14.32 mm, 푸터·쪽번호 없음)
- 모든 수치는 여전히 `results.json`에서 읽음. 손으로 친 숫자 없음.

## 구조 (v12 → short)
| v12 | short |
|---|---|
| I Intro (7문단) | I Intro (6문단, 기여 4항목) |
| II Related (4소절 + Table I) | II Related (2문단, 표 없음) |
| III Threat Model (3소절 + Table II) | III Threat Model and Methods (2소절) |
| IV Method (D1–D3) | → III-B로 병합 |
| V Design (8소절 + Table III) | IV Design (4소절, 조건표를 본문으로) |
| VI Pilot (5소절 + Table IV) | → IV-D 두 문장 (28.6% vs 5.6%) |
| VII Results (8소절, Table V–X, Fig.1) | V Results (5소절, Table I·II, Fig.1) |
| VIII Discussion (5소절) | VI Discussion (2문단) |
| IX Limitations (12항목) | VII Limitations and Future Work (1문단, 9항목 각각 후속 실험 명시) |
| X Conclusion | VIII Conclusion |
| Appendix (프롬프트 전문) | 저장소 |
| 참고문헌 24 | 20 ([19]–[21] RFC, [23] Efron 삭제; 22→19, 24→20) |

## 저장소로 옮긴 것 (short에서 "extended version" 언급)
- 전달 경로 표 (Table II), 전이 셀 표 (VII), 계층별 표 (VIII), 게이트 표 (IX a/b), 문구 사다리 표 (X), 실행 회계 표 (V c)
- 파일럿 3회 상세, 프롬프트 전문 부록
- 소비 경로(raw/parse/serialize) 논의, ASR_cond 정의 상세

## 유지된 핵심
- 공동 1차 지표 쌍, Newcombe J 구간, McNemar/Holm 6개 사전 지정 비교 (Table II)
- Table I (a)(b) 두 모델 전 조건, Fig. 1
- 게이트 전량 거부 + G 조건 + R0 대조 수치
- 문구 분해 (L0/L1/L2/N) 수치는 본문에, 표는 저장소
- 한계는 전부 "future work" 형식으로 재서술했지만 내용은 삭제하지 않음 (심사 8라운드에서 요구된 항목이므로)

## 남은 placeholder
- `[REPOSITORY URL]` — 기여 (4). GitHub URL·태그 확정 후 `REPO` 상수 1곳만 교체.

## 이름 표기 확인 필요
- 학생 이름 순서/표기 (Angelin Lipika Edwin Jose Jebaslin Vijila) — 본인 확인 후 확정.

## 심사 피드백 반영 (short v13, 2차)
검증 후 전부 채택. 각 항목의 근거:
1. "Every prompt change … raised OER" — B1→B1N: 누락 49.1→48.1, OER 47.2→47.2 (results.json). 반례 확인 → "구조화 기준선→출처 조건→게이트의 각 단계와 노트의 각 절"로 한정. "additively" 삭제. "labeling and note account for…" → "referenced appendix의 추가 이점 미검출". "D2 produced no advantage" → "appendix relocation showed no detectable advantage over inline rendering". "threat appeared on one" → "attack success from this corpus was observed on one".
2. cc/cf 정의 추가(Metrics). "40%" → "27 of 68 under B0"(B0 cf=27, cc+cf=68). 게이트 "26 malicious alerts" → "26 evaluations of malicious alerts (19 injected-variant misses, 13 injection-attributable, 7 clean-variant)" — P1 cf=13, ff=6, fc=1 → 19/7 확인.
3. 초록에 "relative to the naive baseline" + B1 수치 병기; §I·결론은 B1 기준(49.1→17.6, 47.2→94.4)으로 전환.
4. Table I(a)(b)에 N 행 추가. Frontier 4개 OER에 L0/L1/L2(P1)/N 명명. Methods에 payload 배정(카테고리 순환, 15개 중 균등 추출, 필드는 호환·라벨 보존 조건 하 무작위), OER 규칙(verdict≠benign ∧ action≠close; monitor+suspicious = 과경보), seed 의미(생성 seed 3개 = 알림·페이로드·필드 고정, 같은 값을 4o-mini sampling seed로 전달) 추가.
5. Holm 범위 명시(사다리 2개 가족, 나머지 raw). 범위 "49.1–38.9" → min/max 계산으로 "38.9–50.0". "p = <0.001" → "p < 0.001" (peq 헬퍼).
6. Fig.1 학회용 변형 `fig1_safety_cost_conf.png` (글자 1.2배, N을 frontier 행 라벨에 병합, y축 하한 −10). 캡션 "all conditions" → 조건 명시(L0·L1 제외), "lie on" → "lie near the diagonal".
같은 문장이 있는 v12(확장판)에도 동일 수정 적용.

## 심사 피드백 반영 (short v13, 3차)
전부 채택 (검증: P0→P1은 누락 16.7→17.6 ↑, OER 98.6→94.4 ↓ — "every step" 반례 확인).
- Discussion·Results의 "every step"/"columns move together" → "Relative to B1, P0 and P1 reduced misses while increasing OER; the gate further…" 로 비교 직접 지정. "two views of one movement" → "did not move independently" + 임계값 해석은 '부합'으로 통일.
- "cuts the injection rate by two-thirds" → "reduced the injected miss rate by 64% relative to B1 (53 to 19 of 108)" — results.json에서 계산(relred 헬퍼).
- "ladder is flat" → "no differences among the wordings were detected". "Attack success varied; the cost did not" → "Attack success differed between models; increased OER was observed on both". Discussion의 appendix 중복 문장 1개 삭제. 파일럿 28.6%/5.6%에 지표명(injection success rate) 부여.
- v12에도 동일 적용 (Discussion 문단 하나를 template literal로 전환).
- 남은 필수 항목: [REPOSITORY URL]. 저장소에는 prompts.json(프롬프트·게이트 규칙), records.json(경보·payload·조건별 출력), results.json(cc/cf/fc/ff), MANIFEST.json(모델 ID·날짜·sampling)이 이미 있음.

## Acknowledgment (AI 사용 고지) — 양 판 공통
IEEE 정책: AI 생성 콘텐츠(텍스트·그림·코드)는 Acknowledgments에 고지, 시스템명·해당 섹션·사용 수준 명시. 문법 교정 수준은 면제(권장).
넣은 문구(short): Claude (Anthropic) — 전 섹션 초안·수정, 생성기·하네스·통계·그림 코드 작성·디버깅, 60개 payload 문자열 작성([11] 분류 하). 모든 AI 산출물은 저자 검토, 수치는 공개 스크립트로 per-item 기록에서 재생성해 수기 대조. 저자 전적 책임.
v12: 위 + "§II의 문헌 노트는 제1저자가 AI 없이 작성·1차 출처 검증". Limitations의 "payloads were written by the authors" → "authored … with AI assistance (see Acknowledgment)"로 정합.
최종 문구(저자 확정): Claude — 전 섹션 텍스트 초안·수정, 생성·실행·통계·플롯 코드, 60개 payload 생성; ChatGPT — 구조·통계 해석·결과-주장 일관성·문구에 대한 피드백; 저자가 검토·수정, 모든 수치를 공개 스크립트로 per-item 기록에서 재생성, 최종 원고·코드·분석·결론 책임. v12는 학생 문헌 노트 문장 추가.
