# Spring Boot Starter for Contexa Enterprise

Contexa Enterprise Starter - 엔터프라이즈급 AI-Native IAM 플랫폼

## 개요

Contexa Enterprise Edition은 Community Edition의 모든 기능에 더하여 엔터프라이즈급 기능을 제공합니다.

## Enterprise 전용 기능

- **SOAR (Security Orchestration, Automation and Response)**: 자동화된 보안 대응
- **Spring AI Tool Calling**: MCP 기반 Tool 실행
- **Advanced Analytics**: 고급 위협 분석 및 보고서
- **Multi-Tenancy**: 다중 테넌트 지원
- **Enterprise Integration**: Kafka, Redis, Redisson 필수 통합

## 빠른 시작

### 1. 의존성 추가

Gradle:
```gradle
dependencies {
    implementation 'io.contexa:spring-boot-starter-contexa-enterprise:0.1.0-ALPHA'
}
```

Maven:
```xml
<dependency>
    <groupId>io.contexa</groupId>
    <artifactId>spring-boot-starter-contexa-enterprise</artifactId>
    <version>0.1.0-ALPHA</version>
</dependency>
```

### 2. 설정 파일 (application.yml)

```yaml
# Contexa Enterprise 설정
contexa:
  # Community 기능 (모두 포함)
  llm:
    enabled: true
  hcad:
    enabled: true
  rag:
    enabled: true
  autonomous:
    enabled: true

  # Enterprise 전용 기능
  enterprise:
    enabled: true  # Enterprise 기능 활성화

# Redis (필수)
spring:
  data:
    redis:
      host: localhost
      port: 6379

# Kafka (필수)
spring:
  kafka:
    bootstrap-servers: localhost:9092

# Redisson (분산 락, 필수)
spring:
  redisson:
    config: |
      singleServerConfig:
        address: "redis://localhost:6379"

# Quartz (Tool Calling 스케줄링)
spring:
  quartz:
    job-store-type: jdbc
```

## AutoConfiguration 모듈

Enterprise Starter는 Community Starter의 모든 AutoConfiguration에 더하여:

7. **EnterpriseToolAutoConfiguration**: Spring AI Tool Calling (6개 Configuration)
   - EnterpriseBeanConfiguration
   - ToolCallingConfiguration
   - StandardMcpClientConfiguration
   - ToolConfiguration
   - ToolExecutionConfiguration
   - SoarToolConfiguration

## Enterprise 필수 의존성

Enterprise Edition은 다음 인프라를 필수로 요구합니다:

- **Redis**: HCAD 실시간 분석, 분산 캐싱, 이벤트 스트림
- **Kafka**: SOAR 통합, 실시간 위협 이벤트 스트리밍
- **Redisson**: 분산 락, 스케줄링, Pub/Sub
- **Quartz**: Tool Calling 스케줄링

## Community Edition과의 차이점

| 기능 | Community | Enterprise |
|------|-----------|------------|
| HCAD | ✅ | ✅ |
| LLM 통합 | ✅ | ✅ |
| RAG | ✅ | ✅ |
| Autonomous Security | ✅ | ✅ |
| SOAR | ❌ | ✅ |
| Tool Calling | ❌ | ✅ |
| Multi-Tenancy | ❌ | ✅ |
| Advanced Analytics | ❌ | ✅ |
| Redis | 선택적 | 필수 |
| Kafka | 선택적 | 필수 |

## Migration Guide

### Community에서 Enterprise로 업그레이드

1. 의존성 변경:
```gradle
// Before
implementation 'io.contexa:spring-boot-starter-contexa:0.1.0-ALPHA'

// After
implementation 'io.contexa:spring-boot-starter-contexa-enterprise:0.1.0-ALPHA'
```

2. Enterprise 기능 활성화:
```yaml
contexa:
  enterprise:
    enabled: true
```

3. 필수 인프라 설정:
- Redis 설정 추가
- Kafka 설정 추가
- Redisson 설정 추가

## 라이선스

Commercial License (Enterprise Edition)

## 지원

- Enterprise Support: support@contexa.io
- Documentation: https://docs.contexa.io/enterprise
- GitHub Issues: https://github.com/your-org/contexa
