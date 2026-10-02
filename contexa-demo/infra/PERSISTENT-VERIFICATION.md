# Runtime Lab 영속 검증 환경

기본 사용자는 기존 `standalone` 방식으로 실행합니다. 전체 검증은 `application-persistent.yml`을 추가하여 기존 Contexa의 `distributed` 구현과 Spring Session Redis를 사용합니다. 별도 데모 보안 엔진은 없습니다.

- `docker compose -f compose.persistent.yml up -d`: 데모 전용 Redis16379, Kafka19092, Zookeeper. 포트는 localhost에만 바인딩합니다.
- Redis는 AOF/everysec/noeviction, Kafka/Zookeeper는 전용 named volume을 사용합니다. AOF everysec는 전원 손실 시 최근 약1초까지의 쓰기 손실 가능성을 배제하지 않습니다. 재기동 유지와 무손실 보장은 다릅니다.
- Spring profile은 `<portal|baseline|contexa>,persistent`. HTTP 세션 namespace는 역할별 `contexa:lab:<role>:session`입니다. Native 보안 저장소는 같은 전용 Redis DB0을 사용합니다.
- 현재 실검수 런처는 `.runtime/rebuild-phase-b/start-persistent-gpt5nano.ps1 -BuildName build-NNN`. local APIKEY.md는 환경변수로만 전달하며 로그/명령 인수/소스에 기록하지 않습니다.
- 기존 Enterprise Redis6379, PostgreSQL5432, 다른 Docker network와 공유하지 않습니다. 업무/증거는 기존 데모 PostgreSQL15432의 각 소유 DB를 유지합니다.

## 재기동과 초기화

재기동에는 `restart` 또는 기존 볼륨을 유지한 `up -d`를 사용합니다. 초기화를 기동 스크립트에 넣지 않습니다. 현재 검증에는 초기화가 필요하지 않아 데이터 삭제를 하지 않았습니다.

초기화가 실제로 필요하면 다음 순서를 적용합니다.

1. 진행 중인 업무/LLM/소비자 작업을 종료하고 현재 실행을 완료·중단·실패 중 실제 상태로 확정합니다. 원본 요청/결정/업무/수신/관측 누락과 코드·설정·데이터 manifest를 먼저 보존합니다.
2. 컨테이너와 볼륨의 실제 Compose project가 `contexa-runtime-lab-persistent`, scope label이 `persistent-verification`인지 확인합니다. 이름 추측만으로 지우지 않습니다. Redis endpoint/DB, Kafka cluster ID/topic/group, 연결 앱을 기록합니다.
3. 필요한 초기 상태의 범위를 정합니다. Redis 액션만 삭제하고 과거 Kafka 미처리 이벤트를 남기거나, offset만 되돌려 옛 판단을 새 실행으로 주입하는 초기화를 하지 않습니다. PostgreSQL 업무/학습 원본과의 일관성도 확인합니다.
4. 원본을 복구할 수 있게 전용 데이터/설정/offset을 보존하고 검증한 후, 필요한 데모 범위에만 초기화를 적용합니다. 가능하면 별도 세대의 새 전용 볼륨으로 시작하고 이전 볼륨을 보존합니다. 비밀이 들어 있는 데이터 백업은 Git·대화·증거 보고서에 내보내지 않습니다.
5. 새 환경/실행 ID로 구분하고 전후 상태를 대조합니다. 초기화에 의한 보안 제한 해제를 정상 MFA 복귀·만료·보안 회복이나 연속 재기동 성공으로 계산하지 않습니다.

공유 Redis의 FLUSHALL, 전체 Docker prune, 다른 프로젝트의 볼륨/토픽/consumer group 삭제는 사용하지 않습니다. 제품의 치명적 문제는 재현·최소 diff·완료 기준을 준비한 뒤 사용자 승인 후 수정합니다.

## 현재 확인한 한계

2026-09-27 B-ENG-02 승인 범위의 제품 3개 파일 수정 후 실제 Kafka 발행·소비·재기동을 검수했습니다. build-024→025에서 실제 업무 request ID와 Kafka event ID·partition/offset·payload hash, consumer offset 유지 및 Redis 보안 액션의 논리 필드·세션 유지를 대조했습니다. 같은 JAR의 standalone 기동/로그인/메모리 빈 선택도 build-026에서 확인했습니다. 이 범위의 통과가 Phase B 전체 완료나 모든 장애에서 무손실을 보장하는 것은 아닙니다.

kafka-init은 native 이벤트 경로의 세 토픽을 --if-not-exists로 준비하고 종료합니다. 기존 메시지나 offset을 삭제하지 않고 가짜 이벤트를 발행하지 않습니다. 2026-09-27 실제 종료 코드 0을 확인했습니다.

LLM 판단·신뢰성 검수에는 gpt-5-nano를 사용합니다. 2026-09-27 사용자 추가 지시에 따라 대량 @Protectable 요청의 안전성·견고성·결함 검수는 로컬 Ollama로 분리합니다. 각 실행의 목적과 실제 모델을 보존하고 두 결과를 섞지 않습니다. AI 비활성 baseline의 입력/관측 검수에는 모델 호출이 없습니다.
