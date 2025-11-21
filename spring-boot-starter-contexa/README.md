# Spring Boot Starter for Contexa

Contexa Community Starter - AI-Native IAM 플랫폼을 위한 Spring Boot AutoConfiguration 기반 한 줄 통합

## 개요

Contexa는 Spring AI 기반의 차세대 AI-Native IAM(Identity and Access Management) 플랫폼입니다.
이 Starter는 Contexa Community Edition의 핵심 기능을 Spring Boot 애플리케이션에 자동으로 구성합니다.

## 주요 기능

- **HCAD (Hyper-lightweight Context Anomaly Detector)**: 초경량 실시간 이상 탐지
- **AI-Native LLM 통합**: OpenAI, Ollama, Anthropic Claude 지원
- **RAG 기반 보안 분석**: PgVector 기반 벡터 스토어 통합
- **Zero Trust Architecture**: 계층적 보안 분석 (3-Tier LLM Strategy)
- **Autonomous Security Plane**: 24시간 자율 운영 보안 에이전트

## 빠른 시작

### 1. 의존성 추가

Gradle:
```gradle
dependencies {
    implementation 'io.contexa:spring-boot-starter-contexa:0.1.0-ALPHA'
}
```

Maven:
```xml
<dependency>
    <groupId>io.contexa</groupId>
    <artifactId>spring-boot-starter-contexa</artifactId>
    <version>0.1.0-ALPHA</version>
</dependency>
```

### 2. 설정 파일 (application.yml)

```yaml
# Contexa 기본 설정
contexa:
  # LLM 설정 (기본: 활성화)
  llm:
    enabled: true

  # HCAD 설정 (기본: 활성화)
  hcad:
    enabled: true

  # RAG 설정 (기본: 활성화)
  rag:
    enabled: true

  # Autonomous Security Plane (기본: 활성화)
  autonomous:
    enabled: true

  # Simulation (기본: 비활성화)
  simulation:
    enabled: false

# Spring AI 설정
spring:
  ai:
    openai:
      api-key: ${OPENAI_API_KEY}

    ollama:
      base-url: http://localhost:11434

    vectorstore:
      pgvector:
        index-type: HNSW
        distance-type: COSINE_DISTANCE

# 데이터베이스 설정
spring:
  datasource:
    url: jdbc:postgresql://localhost:5432/contexa
    username: postgres
    password: ${DB_PASSWORD}
```

### 3. 애플리케이션 시작

```java
@SpringBootApplication
public class MyContextaApplication {
    public static void main(String[] args) {
        SpringApplication.run(MyContextaApplication.class, args);
    }
}
```

## 선택적 의존성

### Redis (HCAD 캐싱, 분산 락)
```gradle
implementation 'org.springframework.boot:spring-boot-starter-data-redis'
```

### Kafka (이벤트 스트리밍)
```gradle
implementation 'org.springframework.kafka:spring-kafka'
```

### Redisson (분산 락)
```gradle
implementation 'org.redisson:redisson-spring-boot-starter:3.48.0'
```

## AutoConfiguration 모듈

Starter는 다음 AutoConfiguration 모듈을 자동으로 활성화합니다:

1. **CoreInfrastructureAutoConfiguration**: Redis, Kafka, Vector Store 인프라
2. **CoreLLMAutoConfiguration**: 3계층 보안 LLM 시스템
3. **CoreRAGAutoConfiguration**: RAG 기반 보안 분석
4. **CoreHCADAutoConfiguration**: HCAD 실시간 이상 탐지 (21개 Bean)
5. **CoreAutonomousAutoConfiguration**: Autonomous Security Plane (20개 Bean)
6. **CoreSimulationAutoConfiguration**: 공격 시뮬레이션 (선택적)

## Migration Guide

### @ComponentScan에서 AutoConfiguration으로 마이그레이션

기존 코드:
```java
@SpringBootApplication
@ComponentScan(basePackages = "io.contexa")
public class OldApplication {
    // ...
}
```

새로운 코드:
```java
@SpringBootApplication  // AutoConfiguration 자동 활성화!
public class NewApplication {
    // ...
}
```

## 문제 해결

### 1. AutoConfiguration이 활성화되지 않는 경우

`application.yml`에서 명시적으로 활성화:
```yaml
contexa:
  llm:
    enabled: true
  hcad:
    enabled: true
```

### 2. Bean 충돌이 발생하는 경우

`@ConditionalOnMissingBean`으로 인해 사용자 정의 Bean이 우선합니다:
```java
@Configuration
public class MyContextaConfig {

    @Bean
    public HCADAnalysisService customHCADAnalysisService() {
        // 커스텀 구현
    }
}
```

## 라이선스

Apache License 2.0

## 지원

- GitHub Issues: https://github.com/your-org/contexa
- Documentation: https://docs.contexa.io
