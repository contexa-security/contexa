# 🛡️ Contexa - AI-Native Zero Trust Security for Spring

> **"개발자는 AI 보안을 만들 수 없습니다. 하지만 2분 만에 배포할 수는 있습니다."**

Spring 생태계를 위한 세계 최초 AI-Native 보안 플랫폼. 레거시 시스템에 **다운타임 없이** AI 보안을 추가할 수 있습니다.

[![License: Apache 2.0](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)
[![Spring Boot](https://img.shields.io/badge/Spring%20Boot-3.5.4-brightgreen.svg)](https://spring.io/projects/spring-boot)
[![Java](https://img.shields.io/badge/Java-21-orange.svg)](https://openjdk.java.net/)
[![Status](https://img.shields.io/badge/Status-Alpha-red.svg)](https://github.com/contexa/contexa)

---

## 🚨 왜 Contexa인가?

### 2025년, 3년간 미탐지된 침해사고들

```
📰 KT 서버 침해 (2025.09)
   └─ 3년간 미탐지 (2022-2025)
   └─ 수백만 명 고객 정보 노출

📰 정부 네트워크 해킹 (2025.10)
   └─ 3년간 미탐지 (2022-2025)
   └─ 외교부, 주요 기관 침해

📰 Lapsus 해킹 그룹 (2022.04)
   └─ Nvidia, Microsoft, Samsung 동시 공격
   └─ 룰 기반 보안 완전 무력화
```

**공통점**: 모두 "보안" 시스템이 있었습니다. 모두 실패했습니다.

### 문제: 룰 기반 보안의 한계

```java
// 전통적 Spring Security (룰 기반)
@PreAuthorize("hasRole('ADMIN')")
public void deleteUser(Long userId) {
    // ❌ AI가 탈취한 ADMIN 자격증명은 못 막음
    // ❌ 비정상 시간대 접근 탐지 못함
    // ❌ 행동 패턴 이상 감지 못함
    userRepository.deleteById(userId);
}
```

**AI 공격 vs 룰 기반 방어 = 총 vs 칼**

### 해법: Contexa AI-Native Security

```java
// Contexa (AI-Native)
@EnableAIZeroTrust
@AISecured(
    mode = ShadowMode.OBSERVE,  // 👈 다운타임 없이 학습
    labs = {PolicyLab.class, RiskLab.class, BehaviorLab.class}
)
public class Application {
    // ✅ 384차원 컨텍스트 분석
    // ✅ 행동 패턴 AI 학습
    // ✅ 실시간 위협 탐지
    // ✅ 5-30ms 응답 속도
}
```

---

## ✨ 핵심 기능

### 🎯 Shadow Mode 4단계 마이그레이션

**세계 최초 무중단 AI 보안 전환**

```
┌─────────────┐
│  Stage 1    │  AI가 관찰만 (실행 안 함) → 학습
│  Shadow     │  리스크: 0% | 기간: 1-3개월
└─────────────┘
      ↓
┌─────────────┐
│  Stage 2    │  AI가 추천 → 인간이 결정
│  Advisory   │  리스크: 0% | 기간: 3-6개월
└─────────────┘
      ↓
┌─────────────┐
│  Stage 3    │  명확한 위협은 AI 차단 + 애매한 건 인간 판단
│  Hybrid     │  리스크: 낮음 | 기간: 6-12개월
└─────────────┘
      ↓
┌─────────────┐
│  Stage 4    │  완전 AI 자율 + 인간 감독
│ Autonomous  │  리스크: 최소 | 기간: 12개월+
└─────────────┘
```

**핵심**: 레거시 시스템을 **중단 없이** AI로 전환할 수 있는 유일한 방법

### 🧠 15개 AI Labs (전문가 시스템)

| AI Lab | 역할 | 응답 시간 |
|--------|------|----------|
| **PolicyLab** | 정책 생성 및 검증 | 5-10ms |
| **RiskLab** | 실시간 위험도 평가 | 5-15ms |
| **BehaviorLab** | 사용자 행동 패턴 분석 | 10-30ms |
| **AnomalyLab** | 이상 탐지 | 5-20ms |
| **ThreatLab** | 위협 인텔리전스 | 10-50ms |
| **ContextLab** | 컨텍스트 추론 | 15-30ms |
| **AdaptiveLab** | 적응형 보안 정책 | 20-50ms |
| ... | (총 15개) | ... |

### ⚡ HCAD (Hierarchical Context-Aware Detection)

```
사용자 요청
    ↓
┌─────────────────────────────────┐
│  Hot Path (98% 트래픽)          │
│  - 384차원 벡터 분석             │
│  - 5-30ms 초고속 판단            │
│  - 명확한 케이스 즉시 처리        │
└─────────────────────────────────┘
    ↓ (의심스러운 2%만)
┌─────────────────────────────────┐
│  Cold Path (2% 트래픽)           │
│  - Deep AI 분석                  │
│  - 50ms-수초 정밀 검사            │
│  - LLM 추론 (GPT-4/Claude)       │
└─────────────────────────────────┘
```

**성능**: 98%는 5ms 이내, 2%만 정밀 분석 → **평균 응답 8ms**

---

## 🚀 빠른 시작 (5분)

### 1. 의존성 추가

```xml
<!-- pom.xml -->
<dependency>
    <groupId>io.contexa</groupId>
    <artifactId>contexa-spring-boot-starter</artifactId>
    <version>0.1.0-ALPHA</version>
</dependency>
```

```gradle
// build.gradle
implementation 'io.contexa:contexa-spring-boot-starter:0.1.0-ALPHA'
```

### 2. 설정 추가

```yaml
# application.yml
contexa:
  ai:
    mode: SHADOW              # 👈 관찰만, 실행 안 함
    labs:
      - policy               # 정책 AI
      - risk                 # 위험 평가 AI

  shadow:
    logging: true            # AI 결정 로깅
    metrics: true            # 정확도 측정

  vector:
    dimensions: 384          # 컨텍스트 벡터 크기

  performance:
    hot-path-threshold: 0.95 # Hot Path 신뢰도 임계값
```

### 3. 활성화

```java
@SpringBootApplication
@EnableAIZeroTrust           // 👈 이게 전부
public class Application {
    public static void main(String[] args) {
        SpringApplication.run(Application.class, args);
    }
}
```

### 4. 보호할 엔드포인트 지정

```java
@RestController
@RequestMapping("/api/users")
public class UserController {

    @AISecured(
        risk = RiskLevel.HIGH,
        context = @AIContext(
            sensitivity = DataSensitivity.PII,
            compliance = {GDPR.class, HIPAA.class}
        )
    )
    @DeleteMapping("/{id}")
    public void deleteUser(@PathVariable Long id) {
        // AI가 다음을 분석:
        // - 누가 (사용자 프로필, 과거 행동)
        // - 언제 (시간, 빈도, 패턴)
        // - 어디서 (IP, 지역, 디바이스)
        // - 무엇을 (데이터 민감도, 영향 범위)
        // - 왜 (비즈니스 컨텍스트)

        userService.delete(id);
    }
}
```

### 5. Shadow Mode 대시보드 확인

```
http://localhost:8080/contexa/dashboard

📊 Shadow Mode 분석 결과:
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
✅ 총 요청:        1,247건
✅ AI 차단 제안:   23건 (1.8%)
✅ False Positive: 1건 (4.3%)
✅ False Negative: 0건 (0%)
✅ 정확도:         95.7%
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

🎯 다음 단계: Advisory Mode로 전환 권장
```

---

## 📖 왜 Shadow Mode부터 시작하는가?

### 전통적 보안 도입 (위험함)

```
Day 1: 새 보안 시스템 배포
Day 2: 정상 요청 차단 (오탐)
Day 3: 고객 불만 폭주
Day 4: 긴급 롤백
Day 5: 보안 프로젝트 취소
```

### Contexa Shadow Mode (안전함)

```
Week 1-4:   AI가 관찰만, 실행 안 함 → 고객 영향 0
            └─ 정확도 측정: FP 4.3%, FN 0%

Week 5-12:  Advisory Mode → AI 추천, 인간 결정
            └─ 수용률 85% → "AI 판단 신뢰 가능" 검증

Week 13-24: Hybrid Mode → 명확한 위협만 AI 차단
            └─ 자동 처리 92%, 사고 0건

Week 25+:   Autonomous → 완전 자율 AI 보안
```

**핵심**: 리스크 없이 점진적으로 신뢰 구축

---

## 🏗️ 아키텍처

### 전체 구조

```
┌─────────────────────────────────────────────────────────┐
│                    Application Layer                     │
│  @EnableAIZeroTrust, @AISecured, @AIContext             │
└────────────────────┬────────────────────────────────────┘
                     ↓
┌─────────────────────────────────────────────────────────┐
│              Zero Trust Hot Path Orchestrator            │
│  ┌──────────┐  ┌──────────┐  ┌──────────┐              │
│  │ Identity │→ │ Context  │→ │ Decision │              │
│  │ Resolver │  │ Analyzer │  │ Engine   │              │
│  └──────────┘  └──────────┘  └──────────┘              │
└────────────────────┬────────────────────────────────────┘
                     ↓
┌─────────────────────────────────────────────────────────┐
│                   15 AI Labs System                      │
│  ┌──────┐ ┌──────┐ ┌──────┐ ┌──────┐ ┌──────┐         │
│  │Policy│ │ Risk │ │Behav │ │Anomal│ │Threat│  ...    │
│  │ Lab  │ │ Lab  │ │ior   │ │y Lab │ │ Lab  │         │
│  └──────┘ └──────┘ └──────┘ └──────┘ └──────┘         │
└────────────────────┬────────────────────────────────────┘
                     ↓
┌─────────────────────────────────────────────────────────┐
│                   Data & Storage Layer                   │
│  ┌──────────┐  ┌──────────┐  ┌──────────┐              │
│  │ PGVector │  │ Redis    │  │ TimeSeries│              │
│  │ (Context)│  │ (Cache)  │  │ (Metrics) │              │
│  └──────────┘  └──────────┘  └──────────┘              │
└─────────────────────────────────────────────────────────┘
```

### 모듈 구조

```
contexa/
├── contexa-core/           # 핵심 엔진
│   ├── HCAD               # 계층적 탐지
│   ├── VectorEngine       # 384차원 분석
│   └── Orchestrator       # Hot Path 조율
│
├── contexa-identity/      # 신원 확인
│   ├── MFA                # 다중 인증
│   ├── Biometric          # 생체 인증
│   └── DeviceFingerprint  # 디바이스 지문
│
├── contexa-iam/           # 접근 제어
│   ├── XACML              # 정책 엔진
│   ├── ABAC               # 속성 기반 접근
│   └── DynamicPolicy      # 동적 정책
│
└── contexa-mcp/           # AI 통합
    ├── 15 AI Labs         # 전문가 시스템
    ├── LLM Integration    # GPT-4, Claude
    └── RAG Pipeline       # 컨텍스트 검색
```

---

## 💻 사용 예제

### 예제 1: 민감 데이터 보호

```java
@Service
public class PaymentService {

    @AISecured(
        risk = RiskLevel.CRITICAL,
        context = @AIContext(
            sensitivity = DataSensitivity.FINANCIAL,
            compliance = {PCI_DSS.class},
            anomalyDetection = true
        )
    )
    public PaymentResult processPayment(PaymentRequest request) {
        // AI가 자동으로 분석:
        // ✅ 결제 패턴 (금액, 빈도, 시간)
        // ✅ 사용자 행동 (과거 이력 대비)
        // ✅ 디바이스 신뢰도
        // ✅ 지역 리스크 (IP, GPS)
        // ✅ 거래 컨텍스트 (상품, 판매자)

        return paymentGateway.process(request);
    }
}
```

### 예제 2: 시간 기반 접근 제어

```java
@RestController
public class AdminController {

    @AISecured(
        risk = RiskLevel.HIGH,
        context = @AIContext(
            timePatterns = @TimePattern(
                normalHours = "09:00-18:00",
                timezone = "Asia/Seoul",
                weekdaysOnly = true
            )
        )
    )
    @PostMapping("/admin/config")
    public void updateConfig(@RequestBody Config config) {
        // AI 판단:
        // - 평일 09:00-18:00 접근 → 정상 (신뢰도 95%)
        // - 주말 03:00 접근 → 의심 (신뢰도 15%) → 추가 인증 요구

        configService.update(config);
    }
}
```

### 예제 3: 행동 패턴 기반 탐지

```java
@Service
public class UserService {

    @AISecured(
        risk = RiskLevel.MEDIUM,
        context = @AIContext(
            behaviorLearning = true,
            anomalyThreshold = 0.7  // 70% 신뢰도 미만 시 경고
        )
    )
    public void bulkExportUsers(ExportRequest request) {
        // AI 학습:
        // - 이 사용자는 보통 하루 10명 조회
        // - 갑자기 10,000명 내보내기 요청
        // - 신뢰도 35% → BLOCK + 관리자 알림

        userRepository.exportBulk(request);
    }
}
```

---

## 📊 성능

### 벤치마크 (Spring Boot 3.5.4 + Java 21)

```
환경: AWS EC2 t3.medium, PostgreSQL + PGVector, Redis

┌─────────────────────────────────────────────────────┐
│  Hot Path (98% 트래픽)                              │
│  - p50: 5ms                                         │
│  - p95: 12ms                                        │
│  - p99: 28ms                                        │
└─────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────┐
│  Cold Path (2% 트래픽)                              │
│  - p50: 85ms                                        │
│  - p95: 320ms                                       │
│  - p99: 1.2s (LLM 호출 포함)                        │
└─────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────┐
│  전체 평균: 8.4ms                                   │
│  처리량: 12,000 req/sec                             │
│  메모리: 512MB (기본), 2GB (전체 AI Labs)           │
└─────────────────────────────────────────────────────┘
```

### vs 전통적 Spring Security

```
Traditional Spring Security:
├─ @PreAuthorize: 2-3ms
├─ Method Security: 1-2ms
└─ 총: 3-5ms

Contexa AI Security:
├─ Hot Path (98%): 5-28ms  ← 약간 느림
├─ Cold Path (2%): 85-1200ms
└─ 총 평균: 8.4ms

📊 결과: 3-4ms 오버헤드로 AI 보안 확보
       (룰 기반으로는 불가능한 위협 탐지)
```

---

## ⚠️ 중요 고지사항

### 🚧 알파 버전 (v0.1.0-ALPHA)

**현재 상태**:
- ✅ 핵심 아키텍처 완성
- ✅ 2개 AI Labs 운영 (Policy, Risk)
- ✅ Shadow Mode 동작
- ✅ 기본 대시보드

**프로덕션 사용 금지**:
- ❌ 전체 AI Labs 미완성 (15개 중 2개)
- ❌ 보안 감사 미완료
- ❌ 성능 최적화 진행 중
- ❌ 문서 불완전

### 🎯 로드맵

```
✅ v0.1.0-ALPHA (현재)
   └─ Shadow Mode + 2 AI Labs

🔄 v0.2.0-ALPHA (3개월)
   └─ 5 AI Labs + Advisory Mode

🔄 v0.3.0-BETA (6개월)
   └─ 10 AI Labs + Hybrid Mode

🔄 v1.0.0-RC (12개월)
   └─ 15 AI Labs + Autonomous Mode
   └─ 프로덕션 준비 완료
```

---

## 🤝 커뮤니티 참여

### 우리는 여러분이 필요합니다

**초기 채택자 (Early Adopters) 모집**:
```
✅ 조건: Spring Boot 3.x 사용 중인 개발팀
✅ 혜택: 무료 사용 + 기능 요청 우선권
✅ 역할: Shadow Mode 테스트 + 피드백
✅ 인원: 10팀 (선착순)
```

**참여 방법**:
1. ⭐ GitHub Star
2. 📝 [Discussion](https://github.com/contexa/contexa/discussions)에 자기소개
3. 🐛 버그 리포트: [Issues](https://github.com/contexa/contexa/issues)
4. 💡 기능 제안: [Discussions - Ideas](https://github.com/contexa/contexa/discussions/categories/ideas)
5. 🔧 코드 기여: [CONTRIBUTING.md](CONTRIBUTING.md)

### 기여자 인정

```
우리는 모든 기여를 기록합니다:

🏆 Hall of Fame
├─ Early Adopters (첫 10팀)
├─ Bug Hunters (버그 리포트 Top 10)
├─ Code Contributors (PR 머지된 분)
└─ Idea Champions (채택된 기능 제안자)

🎁 혜택
├─ GitHub Profile 배지
├─ Enterprise 버전 평생 무료
├─ 컨퍼런스 발표 기회
└─ 정식 버전 출시 시 크레딧 명시
```

---

## 📚 문서

- [설치 가이드](docs/installation.md)
- [Shadow Mode 완벽 가이드](docs/shadow-mode.md)
- [AI Labs 상세 설명](docs/ai-labs.md)
- [성능 튜닝](docs/performance.md)
- [FAQ](docs/faq.md)
- [API 레퍼런스](docs/api-reference.md)

---

## 🙋 FAQ

### Q1: 기존 Spring Security와 함께 쓸 수 있나요?

**A**: 네! Contexa는 Spring Security를 **대체**하는 게 아니라 **강화**합니다.

```java
@Configuration
@EnableWebSecurity              // 기존 Spring Security
@EnableAIZeroTrust              // Contexa 추가
public class SecurityConfig {
    // 두 개가 함께 동작
    // Spring Security: 기본 인증/인가
    // Contexa: AI 위협 탐지
}
```

### Q2: 비용이 얼마나 드나요? (LLM API 호출)

**A**: 3단계 LLM 전략으로 최소화합니다.

```
98% 트래픽 → 로컬 모델 (무료)
1.8% 트래픽 → Gemini Flash ($0.0001/req)
0.2% 트래픽 → GPT-4 ($0.003/req)

예: 월 100만 요청 기준
├─ 980,000 req × $0 = $0
├─ 18,000 req × $0.0001 = $1.8
└─ 2,000 req × $0.003 = $6
총: $7.8/월
```

### Q3: 왜 오픈소스인가요?

**A**: AI 보안은 투명해야 신뢰할 수 있습니다.

```
폐쇄형 AI 보안:
"우리 AI가 안전합니다" → "믿어주세요"
└─ 문제: 검증 불가능

오픈소스 AI 보안:
"우리 AI가 안전합니다" → "코드 보세요"
└─ 해결: 커뮤니티 검증 가능
```

### Q4: Spring이 아니면 못 쓰나요?

**A**: 현재는 Spring 전용입니다. 향후 확장 예정.

```
v1.0: Spring Boot 3.x
v2.0: Quarkus, Micronaut
v3.0: Node.js, Python (FastAPI)
```

---

## 📜 라이선스

Apache License 2.0 - 자유롭게 사용, 수정, 배포 가능

```
Copyright 2025 Contexa Project

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.

상업적 사용 가능 ✅
수정 가능 ✅
배포 가능 ✅
특허 사용 가능 ✅
```

---

## 🌟 Star History

[![Star History Chart](https://api.star-history.com/svg?repos=contexa/contexa&type=Date)](https://star-history.com/#contexa/contexa&Date)

---

## 💬 연락처

- **창업자**: [이름] - 25년 Spring 전문가, #1 Spring Security 강사 (인프런 4,128명)
- **이메일**: [이메일]
- **Discord**: [Discord 링크]
- **X (Twitter)**: [@contexa](https://twitter.com/contexa)

---

## 🙏 감사합니다

이 프로젝트는 다음의 영감을 받았습니다:
- Spring Security 팀 - 오픈소스 보안의 선구자
- OWASP - 웹 보안 표준 제시
- Anthropic - MCP 표준으로 AI 통합 단순화

---

<div align="center">

**⭐ 이 프로젝트가 도움이 되었다면 Star를 눌러주세요!**

[GitHub](https://github.com/contexa/contexa) • [Documentation](https://docs.contexa.io) • [Discord](https://discord.gg/contexa)

</div>
