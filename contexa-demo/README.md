# Contexa Runtime Lab

Runtime Lab은 로그인 이후 업무 요청을 Contexa가 어떻게 관측·판단·제한하고, 추가 확인 후 업무로 복귀시키는지 직접 비교하는 데모입니다. 인증·인가·MFA·위험 분석·액션·학습은 기존 Contexa 엔진이 담당합니다. 데모는 합성 업무, 비교 실행, 원본 관측, 설명과 보고서, 참여 공간 운영만 담당합니다.

## 체험 화면

참여 확인 → 내 체험 공간 → 체험 안내 → 사례 선택 → 업무 조건 확인 → 양쪽 업무 실행 → 결과와 요청 근거 → 보고서 순서로 연결됩니다. 한 화면은 한 책임을 가집니다. 추가 확인은 Contexa의 기존 인증 화면을 사용합니다. 허용·추가 확인·차단과 기술 실패는 구분되며, 수집되지 않은 결과를 성공으로 표시하지 않습니다. 화면은 한국어·영어를 지원합니다.

## 개인용 실행

개인용 기본 설정에서는 공개 슬롯 제한을 활성화하지 않습니다. [.env.example](.env.example)을 모듈의 비공개 `.env`로 복사하고 데이터베이스·메일·모델 설정을 작성하십시오. `LAB_DB_PASSWORD`에는 실제 PostgreSQL 비밀번호가 필요합니다. Properties 파일의 값에는 따옴표를 둘러쓰지 않습니다. 비밀번호나 API 키를 코드·이슈·스크린샷에 넣지 마십시오.

`RuntimeLabApplication`의 직접 실행과 실행 JAR 모두 작업 디렉터리의 설정을 찾고, 없으면 애플리케이션이 위치한 `contexa-demo` 모듈의 `.env`를 찾습니다. 다른 비공개 파일을 쓰려면 실행 환경 변수 `LAB_ENV_FILE`에 절대 경로를 지정하십시오. 비어 있지 않은 환경 변수·명령행 설정은 유지하며, 비밀번호의 빈 설정은 로딩한 파일의 실제 `LAB_DB_PASSWORD`로 보완합니다. 유효한 설정이 없으면 DB 연결 전에 누락된 설정 이름을 표시하고 시작을 거부합니다. 비밀번호를 코드에 기본값으로 넣지 않습니다.

```powershell
$env:JAVA_HOME='YOUR_JDK_17_DIRECTORY'
.\gradlew.bat :contexa-demo:bootJar -x test
```

저장소 루트에서 수행합니다. `RuntimeLabApplication`은 기본 portal 역할입니다. 실제 비교 체험에는 portal·baseline·contexa의 세 역할과 설정에 맞는 전용 저장소가 필요합니다. PostgreSQL은 pgvector를 사용합니다. 영속 분산 실행은 기존 persistent 프로필의 Redis·Kafka를 사용합니다. 메모리 실행과 영속 실행의 근거를 섞어 비교하지 마십시오.

## 공개 설치

`compose.public.yml`은 Enterprise 없이 기존 OSS 엔진을 포함한 세 역할, 전용 PostgreSQL, 세대별 Redis·Kafka·ZooKeeper를 실행합니다. 설치당 **한 쌍의 업무 공간을 한 참여자에게 독점 임대**합니다. 다른 참여자는 준비된 공간을 기다립니다. 기본 사용 시간30분, 비교3회, 보안 모델 HTTP 전송 시도24회, 검색 모델 전송48회, 업무 API 요청60회입니다. 동시 실행·실패한 전송·retry/fallback도 전송 한도에 포함합니다. 모델 HTTP 입력은 전송당128KiB까지 허용합니다. 한도 초과는 실제 거부로 남고 AI 판단으로 바뀌지 않습니다.

1. JDK17·Docker Compose를 준비하고 위 명령으로 JAR를 빌드합니다. 설치 프로젝트 이름은 `contexa-runtime-lab-public` 또는 `contexa-lab-...`로 정하십시오.
2. [infra/public.env.example](infra/public.env.example)을 버전 관리 밖에 복사합니다. 같은 호스트의 서로 다른 HTTPS 역할 주소, RP host, 새로운 UUID와 그 hex, 실제 SMTP를 설정합니다. 인증서가 해당 호스트와 일치해야 합니다. 파일 경로는 절대 경로입니다.
3. 비공개 TLS 디렉터리에 유효한 인증서·개인 키가 담긴 `lab.p12`를 준비합니다. 비공개 secrets 디렉터리에 이름이 정확히 `LAB_DB_PASSWORD`, `LAB_TLS_PASSWORD`, `LAB_ACCOUNT_PASSWORD`, `SPRING_MAIL_PASSWORD`, `OPENAI_API_KEY`인 파일을 각각 만들고 값만 넣습니다. 운영자의 파일 접근 권한을 제한하십시오. 공개 체험용 계정 비밀번호는 `LAB_ACCOUNT_PASSWORD`로 주입합니다. 유료 판단 모델은 `gpt-5-nano`입니다. 견고성 검수만 수행할 때는 Ollama로 명시적으로 설정하고 OpenAI 파일을 비워 둡니다.
4. Ollama의 `mxbai-embed-large:latest`를 준비합니다. 견고성 검수에 쓸 chat 모델도 미리 준비하십시오. 런타임은 모델을 자동으로 내려받지 않습니다. Linux 호스트에서 Ollama 주소가 컨테이너에 접근 가능한 실제 주소인지 확인하십시오.
5. `docker compose -p PROJECT --env-file /absolute/private/operator.env -f contexa-demo/compose.public.yml up -d --build`를 저장소 루트에서 실행합니다. 세 역할이 모두 healthy인 뒤 portal 주소를 엽니다. 호스트 포트는 기본 loopback에만 열립니다. 외부 공개에는 해당 origin으로 TLS를 유지하는 운영자의 프록시가 필요합니다. 프록시에서 HTTPS를 끊고 HTTP로 전달하는 구성은 이 설치가 지원하지 않습니다.

역할별 JAR는10001 사용자로 실행하며 Docker 소켓을 받지 않습니다. 저장소·Redis·Kafka는 호스트에 노출하지 않습니다. 세대별 DB·Redis/Kafka 볼륨과 세션 namespace·cookie 이름이 달라 이전 참여자의 보안 상태를 다음 참여자에게 재사용하지 않습니다. 공개 origin/RP/쿠키 조건이 맞지 않으면 시작을 거부합니다. 실제 공개 도메인의 신뢰 가능한 인증서와 Windows Hello 검수 없이 인터넷 공개·Passkey 전체 통과를 주장할 수 없습니다.

## 종료·재할당·재기동

사용자는 `내 체험 공간`에서 종료를 확인할 수 있습니다. 만료·취소 후에는 업무 접근과 새 모델 전송을 거부하며 대기 실행은 종료 상태로 전환합니다. 이미 발행한 업무가 실행되지 않았다고 소급하지 않습니다. 원본 관측과 보고서는 그대로 보존합니다.

운영자는 `RESET_REQUIRED`이고 ACTIVE 임대가 없는 자신의 설치에만 다음 명령을 사용합니다.

```powershell
.\contexa-demo\infra\rotate-public-slot.ps1 -SettingsFile 'D:\private\operator.env' -Project contexa-runtime-lab-public
```

```sh
./contexa-demo/infra/rotate-public-slot.sh /absolute/private/operator.env contexa-runtime-lab-public
```

이 명령은 이전 업무 작업자와 세대별 저장소 프로세스를 먼저 중지하고, 새로운 UUID의 DB·볼륨으로 준비합니다. 이전 DB·볼륨과 중앙 참여·증거 저장소를 삭제하지 않습니다. 신규 작업자의 같은 세대 등록과 실제 생존 확인 후에만 할당합니다. 실패 시 양쪽 원본과 설정을 보존하고 오류를 해결한 뒤 같은 새 설정으로 기동하십시오. ACTIVE 상태에서 UUID를 임의로 바꾸지 마십시오.

일반 재기동은 같은 설정의 `docker compose ... up -d --no-build`입니다. UUID를 바꾸거나 `down -v`·공유 Redis flush·Kafka 전체 삭제를 하지 마십시오. 재기동은 사용 시간과 한도를 갱신하지 않습니다.

## 보존·삭제 정책

이 설치는 근거를 자동 삭제하지 않습니다. 최대64개의 등록 세대를 보존한 뒤 추가 회수를 거부하여 운영자가 확인하게 합니다. 공개 전 운영자는 법적·조직적 요구에 맞는 보존 기간, 참여자 요청 처리 책임자와 백업 정책을 정해야 합니다. 체험 공간의30분은 저장된 근거의 삭제 시각이 아닙니다.

삭제는 운영자가 보존 기간이 지난 **해당 설치의 종료 세대**와 백업을 확인한 뒤 수행합니다. ACTIVE 임대·진행 중 업무·다운로드·원본 조회가 있는 세대는 삭제하면 안 됩니다. 중앙 lease/evidence store의 세대 연결, Docker 프로젝트/볼륨 라벨, DB 이름을 대조하고 필요한 보고서와 원본을 먼저 보관하십시오. 직접 연결된 근거를 지우면 해당 보고서의 원본 재조회는 불가능해집니다. 그 사실과 삭제 시각을 남기고, 완료된 실증으로 새로 표시하지 마십시오. 공유 설치나 메인 검수 환경에 대한 prune·flush·전체 DB 삭제는 사용하지 않습니다. 앱에는 운영자 삭제 권한이 없습니다.

## 실제 검수한 범위

현행56개 완료조건·G01~10·U/Q의 결과와 공개 미검증 범위는 [전체 공개 완료 판정](../docs/2026-10-01-03-contexa-runtime-lab-전체-공개-완료판정.md)을 따릅니다. 실제 업무·GPT 판단·Windows Hello·원본/보고·화면과 공개 운영 구현의 확인 범위를 구별합니다. 현재 로컬 검수 설치를 실제 인터넷 공개 완료로 표시하지 않습니다.

Phase D 실행과 최초 실패는 [실행대장](../docs/2026-10-01-02-contexa-runtime-lab-Phase-D-구현-및-실행대장.md)에 기록합니다. Windows Docker Desktop의 새 전용 볼륨과 HTTPS 설치를 실제 기동했습니다. 로컬 검수용 인증서는 공개 CA·인터넷 공개 증거가 아닙니다. Ubuntu WSL CLI가 같은 Docker Desktop Linux 엔진을 사용하는 검수와 독립 Linux 호스트 설치를 구분합니다. 업무 로그인 문제 처리와 최초 참여자5명 검수는 사용자 지시에 따라 제외되며 수행했다고 표시하지 않습니다. 기존 실제 GPT 판단·Windows Hello 근거도 새 공개 설치에서 다시 수행한 것으로 바꾸지 않습니다. 정량 보안 성능 연구는 별도 PERF-01이며 데모의 일반 성공률처럼 표시하지 않습니다.
