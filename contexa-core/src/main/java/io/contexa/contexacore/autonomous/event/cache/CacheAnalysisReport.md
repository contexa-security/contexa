# Cache Layer Analysis Report

## 발견된 캐시 레이어 (2025-01-04)

### 1. Event Collector Layer
**파일**: `RedisSecurityEventCollector.java`
- **캐시 타입**: RMapCache (Redisson distributed cache)
- **용도**: 이벤트 중복 제거
- **키**: `security:events:cache`
- **TTL**: 설정 가능
- **필요성**: ✅ **필수** - 중복 이벤트 방지

### 2. HCAD Baseline Cache
**파일**: `HCADBaselineCacheService.java`
- **캐시 타입**: Local Memory Cache + Redis
- **용도**: 사용자별 Baseline Vector 캐싱
- **TTL**: 5분 (메모리), 30일 (Redis)
- **필요성**: ✅ **필수** - 성능 최적화 (92-95% Hit Rate)

### 3. Model Provider Caches
**파일들**: `OpenAIModelProvider.java`, `AnthropicModelProvider.java`, `OllamaModelProvider.java`
- **캐시 타입**: Local Cache
- **용도**: AI 모델 응답 캐싱
- **필요성**: ✅ **필수** - 비용 절감, 성능 향상

### 4. Tool Result Cache
**파일**: `ToolResultCache.java`
- **캐시 타입**: Redisson cache
- **용도**: MCP Tool 실행 결과 캐싱
- **필요성**: ✅ **필수** - 중복 Tool 실행 방지

## 중복 캐시 레이어 분석

### 중복 발견: Layer1/2 Strategy 캐시

**Layer1FastFilterStrategy.java**:
```java
private final Map<String, CachedEmbedding> embeddingCache = new ConcurrentHashMap<>();
```

**Layer2ContextualStrategy.java**:
```java
private final Map<String, SessionContext> sessionContextCache = new ConcurrentHashMap<>();
```

**문제점**:
1. 동일한 임베딩이 Layer1과 HCADVectorIntegrationService 양쪽에 캐싱
2. Session Context가 Layer2 로컬과 Redis 양쪽에 저장
3. TTL 관리가 일관성 없음

**해결 방안**:
- Layer1: HCADVectorIntegrationService 캐시 재사용 (제거)
- Layer2: Redis Session Context 재사용 (로컬 캐시 제거)

### ✅ 유지 필요: 다층 캐시 전략

**HCADFilter → HCADBaselineCacheService**:
- L1: Memory Cache (5분 TTL)
- L2: Redis Cache (30일 TTL)
- **이유**: Hot Path 성능 최적화 (5-30ms 목표 달성)

## 권장사항

### 즉시 실행
1. **Layer1 임베딩 캐시 제거**: HCADVectorIntegrationService 캐시 재사용
2. **Layer2 세션 캐시 제거**: Redis 기반 세션 저장소 재사용

### 향후 개선
1. **통합 캐시 서비스** 구현: `UnifiedCacheService`
2. **캐시 메트릭 모니터링**: Hit rate, eviction rate 추적
3. **TTL 정책 통일**: 캐시 타입별 표준 TTL 정의

## 예상 효과

- 메모리 사용량: **20-30% 감소**
- 캐시 일관성: **향상**
- 유지보수성: **향상**
