# Cache Layer Analysis Report

## Discovered Cache Layers (2025-01-04)

### 1. Event Collector Layer
**File**: `RedisSecurityEventCollector.java`
- **Cache Type**: RMapCache (Redisson distributed cache)
- **Purpose**: Event deduplication
- **Key**: `security:events:cache`
- **TTL**: Configurable
- **Necessity**: ✅ **Required** - Prevents duplicate events

### 2. HCAD Baseline Cache
**File**: `HCADBaselineCacheService.java`
- **Cache Type**: Local Memory Cache + Redis
- **Purpose**: Per-user Baseline Vector caching
- **TTL**: 5 minutes (memory), 30 days (Redis)
- **Necessity**: ✅ **Required** - Performance optimization (92-95% Hit Rate)

### 3. Model Provider Caches
**Files**: `OpenAIModelProvider.java`, `AnthropicModelProvider.java`, `OllamaModelProvider.java`
- **Cache Type**: Local Cache
- **Purpose**: AI model response caching
- **Necessity**: ✅ **Required** - Cost reduction, performance improvement

### 4. Tool Result Cache
**File**: `ToolResultCache.java`
- **Cache Type**: Redisson cache
- **Purpose**: MCP Tool execution result caching
- **Necessity**: ✅ **Required** - Prevents duplicate Tool execution

## Duplicate Cache Layer Analysis

### Duplication Found: Layer1/2 Strategy Cache

**Layer1FastFilterStrategy.java**:
```java
private final Map<String, CachedEmbedding> embeddingCache = new ConcurrentHashMap<>();
```

**Layer2ContextualStrategy.java**:
```java
private final Map<String, SessionContext> sessionContextCache = new ConcurrentHashMap<>();
```

**Issues**:
1. The same embeddings are cached in both Layer1 and HCADVectorIntegrationService
2. Session Context is stored in both Layer2 local and Redis
3. TTL management is inconsistent

**Resolution**:
- Layer1: Reuse HCADVectorIntegrationService cache (remove)
- Layer2: Reuse Redis Session Context (remove local cache)

### ✅ Retain: Multi-tier Cache Strategy

**HCADFilter → HCADBaselineCacheService**:
- L1: Memory Cache (5 min TTL)
- L2: Redis Cache (30 day TTL)
- **Reason**: Hot Path performance optimization (achieves 5-30ms target)

## Recommendations

### Immediate Actions
1. **Remove Layer1 embedding cache**: Reuse HCADVectorIntegrationService cache
2. **Remove Layer2 session cache**: Reuse Redis-based session store

### Future Improvements
1. **Implement unified cache service**: `UnifiedCacheService`
2. **Cache metrics monitoring**: Track hit rate, eviction rate
3. **Unify TTL policies**: Define standard TTL per cache type

## Expected Results

- Memory usage: **20-30% reduction**
- Cache consistency: **improved**
- Maintainability: **improved**
