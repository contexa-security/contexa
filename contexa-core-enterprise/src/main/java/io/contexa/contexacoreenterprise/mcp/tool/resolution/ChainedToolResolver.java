package io.contexa.contexacoreenterprise.mcp.tool.resolution;

import io.github.resilience4j.circuitbreaker.CircuitBreaker;
import io.github.resilience4j.circuitbreaker.CircuitBreakerConfig;
import io.contexa.contexacoreenterprise.mcp.tool.common.EnhancedToolCallback;
import io.contexa.contexacoreenterprise.dashboard.metrics.mcp.MCPToolMetrics;
import io.contexa.contexacoreenterprise.mcp.tool.provider.McpClientProvider;
import io.contexa.contexacommon.annotation.SoarTool;
import jakarta.annotation.PostConstruct;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.ai.tool.ToolCallback;
import org.springframework.ai.tool.definition.ToolDefinition;
import org.springframework.ai.tool.resolution.DelegatingToolCallbackResolver;
import org.springframework.ai.tool.resolution.ToolCallbackResolver;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.ApplicationContext;
import org.springframework.context.annotation.Primary;


import java.time.Duration;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.stream.Collectors;

/**
 * ChainedToolResolver - Spring AI 도구 해결 구현
 *
 * Spring AI의 DelegatingToolCallbackResolver를 기반으로 사용하여
 * 캐싱, Circuit Breaker, 메트릭 수집 등의 추가 기능을 제공합니다.
 * prefix 없이 기본 도구 이름을 사용하며, 메타데이터로 도구 출처를 구분합니다.
 *
 * <p>Common 모듈의 ChainedToolResolver 인터페이스를 구현하여 Core 모듈과의 계약을 준수합니다.</p>
 *
 * @author AI Security Framework
 * @since 3.0.0
 */

@Primary
@Slf4j
@RequiredArgsConstructor
public class ChainedToolResolver implements ToolCallbackResolver, io.contexa.contexacommon.mcp.tool.ChainedToolResolver {
    
    private final MCPToolMetrics metricsCollector;
    private final SpringBeanToolCallbackResolver springBeanToolCallbackResolver;
    private final McpToolResolver mcpToolResolver;
    private final StaticToolCallbackResolver staticToolCallbackResolver;
    private final FallbackToolResolver fallbackToolResolver;
    
    // 추가 기능을 위한 추가 필드
    private DelegatingToolCallbackResolver delegatingResolver;
    private CircuitBreaker circuitBreaker;
    private final Map<String, ToolCallback> toolCache = new ConcurrentHashMap<>();
    private final Map<String, String> toolSourceMapping = new ConcurrentHashMap<>(); // 도구명 -> 출처 매핑

    @PostConstruct
    public void init() {
        // DelegatingToolCallbackResolver 초기화
        List<ToolCallbackResolver> resolvers = Arrays.asList(
            mcpToolResolver,                // MCP 도구 우선
            springBeanToolCallbackResolver,  // Spring Bean 도구
            staticToolCallbackResolver,      // 정적 도구
            fallbackToolResolver            // Fallback
        );
        this.delegatingResolver = new DelegatingToolCallbackResolver(resolvers);

        // Circuit Breaker 설정
        CircuitBreakerConfig config = CircuitBreakerConfig.custom()
            .failureRateThreshold(50)
            .waitDurationInOpenState(Duration.ofSeconds(30))
            .permittedNumberOfCallsInHalfOpenState(3)
            .slidingWindowSize(10)
            .build();

        this.circuitBreaker = CircuitBreaker.of("tool-resolver", config);

        log.info("ChainedToolResolver 초기화 완료: {} 개의 Resolver", resolvers.size());

        // 초기 도구 캐시 구성
        initializeToolCache();
    }
    
    /**
     * 초기 도구 캐시 구성 (선택적)
     */
    private void initializeToolCache() {
        try {
            Set<String> toolNames = getRegisteredToolNames();
            log.info("초기 도구 캐시 구성: {} 개 도구", toolNames.size());

            // 자주 사용되는 도구들을 미리 캐시 (선택적)
            for (String toolName : toolNames) {
                if (shouldPreCache(toolName)) {
                    ToolCallback tool = delegatingResolver.resolve(toolName);
                    if (tool != null) {
                        toolCache.put(toolName, tool);
                    }
                }
            }

            log.debug("총 {} 개 도구 사전 캐시됨", toolCache.size());
        } catch (Exception e) {
            log.warn("초기 캐시 구성 중 오류 (무시됨): {}", e.getMessage());
        }
    }
    
    /**
     * 사전 캐시 여부 판단
     */
    private boolean shouldPreCache(String toolName) {
        // 핵심 도구들만 사전 캐시
        return toolName.contains("query") ||
               toolName.contains("analysis") ||
               toolName.contains("scan");
    }

    /**
     * 도구 해결 - 추가 기능 포함
     * prefix 없는 기본 이름으로 도구를 검색합니다.
     */
    @Override
    public ToolCallback resolve(String toolName) {
        // 1. 캐시 확인
        ToolCallback cached = toolCache.get(toolName);
        if (cached != null) {
            log.trace("도구 캐시에서 반환: {}", toolName);
            metricsCollector.recordCacheHit(toolName);
            return cached;
        }

        // 2. Circuit Breaker로 보호된 실행
        try {
            return circuitBreaker.executeSupplier(() -> resolveInternal(toolName));
        } catch (Exception e) {
            log.warn("Circuit Breaker 오픈 상태. Fallback 사용: {}", toolName);
            return fallbackToolResolver.resolve(toolName);
        }
    }
    
    /**
     * 내부 도구 해결 로직
     */
    private ToolCallback resolveInternal(String toolName) {
        long startTime = System.nanoTime();

        try {
            // DelegatingToolCallbackResolver의 기본 해결 로직 사용
            ToolCallback tool = delegatingResolver.resolve(toolName);

            if (tool != null) {
                long elapsedTime = System.nanoTime() - startTime;

                // 메트릭 기록
                String resolverName = identifyResolver(tool);
                metricsCollector.recordResolution(resolverName, elapsedTime);

                log.debug("도구 발견: {} (resolver: {}, 시간: {}μs)",
                         toolName, resolverName, elapsedTime / 1000);

                // 향상된 도구 래핑
                ToolCallback enhancedTool = enhanceToolCallback(tool, toolName, resolverName);

                // 캐시 저장
                toolCache.put(toolName, enhancedTool);
                toolSourceMapping.put(toolName, resolverName);

                return enhancedTool;
            }

            throw new ToolNotFoundException("도구를 찾을 수 없음: " + toolName);

        } finally {
            metricsCollector.recordTotalResolutionTime(
                System.nanoTime() - startTime
            );
        }
    }
    
    /**
     * 도구 콜백 향상 - 메타데이터 추가 및 보안 강화
     */
    private ToolCallback enhanceToolCallback(ToolCallback tool, String toolName, String resolverName) {
        // 기본 도구가 이미 충분한 기능을 가진 경우 그대로 반환
        if (tool instanceof EnhancedToolCallback) {
            return tool;
        }

        // 메타데이터로 도구 출처 추가 (prefix 없이)
        Map<String, Object> metadata = new HashMap<>();
        // Spring AI의 ToolDefinition은 metadata를 직접 제공하지 않음

        // 도구 출처 정보 추가
        metadata.put("resolver", resolverName);
        metadata.put("cached", false);
        metadata.put("enhancedAt", System.currentTimeMillis());

        // MCP 도구인지 확인 (prefix 없이 메타데이터로)
        if (resolverName.equals("McpToolResolver") ||
            metadata.containsKey("source") && "mcp".equals(metadata.get("source"))) {
            metadata.put("type", "mcp");
            metadata.put("requiresApproval", true);
        }

        return EnhancedToolCallback.builder()
            .delegate(tool)
            .toolType(determineToolType(tool, metadata))
            .securityValidation(true)
            .contextAware(true)
            .source(resolverName)
            .metadata(metadata)
            .metricsCollector(metricsCollector)  // 메트릭 수집기 전달
            .build();
    }
    
    /**
     * Resolver 식별
     */
    private String identifyResolver(ToolCallback tool) {
        // 클래스 이름으로 추론
        String className = tool.getClass().getSimpleName();
        if (className.contains("Mcp")) {
            return "McpToolResolver";
        } else if (className.contains("Static")) {
            return "StaticToolCallbackResolver";
        } else if (className.contains("Spring")) {
            return "SpringBeanToolCallbackResolver";
        }

        return "UnknownResolver";
    }

    /**
     * 도구 타입 결정 - 메타데이터 기반
     */
    private EnhancedToolCallback.ToolType determineToolType(ToolCallback tool, Map<String, Object> metadata) {
        // 메타데이터에서 타입 확인
        if (metadata.containsKey("type")) {
            String type = metadata.get("type").toString().toUpperCase();
            try {
                return EnhancedToolCallback.ToolType.valueOf(type);
            } catch (Exception e) {
                log.debug("알 수 없는 도구 타입: {}", type);
            }
        }

        // 메타데이터 source로 판단
        if (metadata.containsKey("source")) {
            String source = metadata.get("source").toString();
            if ("mcp".equalsIgnoreCase(source)) {
                return EnhancedToolCallback.ToolType.MCP;
            }
        }

        // 도구 이름으로 판단 (fallback)
        String toolName = tool.getToolDefinition().name();
        if (toolName.contains("fallback")) {
            return EnhancedToolCallback.ToolType.FALLBACK;
        }

        // 기본값
        return EnhancedToolCallback.ToolType.SOAR;
    }
    
    /**
     * 정적 도구 목록 반환
     */
    private Map<String, ToolCallback> getStaticTools() {
        // 기본 정적 도구 없음
        return Map.of();
    }

    /**
     * 캐시 초기화
     */
    public void clearCache() {
        toolCache.clear();
        log.info("도구 캐시 초기화됨");
    }

    /**
     * 모든 사용 가능한 도구 반환
     * prefix 없는 기본 이름으로 도구를 반환합니다.
     */
    @Override
    public ToolCallback[] getAllToolCallbacks() {
        List<ToolCallback> allTools = new ArrayList<>();

        for (ToolCallbackResolver resolver : getResolvers()) {
            try {
                // SpringBeanToolCallbackResolver의 경우
                if (resolver instanceof SpringBeanToolCallbackResolver springResolver) {
                    var tools = springResolver.getAllTools();
                    allTools.addAll(tools.values());
                }
                // McpToolResolver의 경우
                else if (resolver instanceof McpToolResolver mcpResolver) {
                    var tools = mcpResolver.getAllTools();
                    allTools.addAll(tools);
                }
                // StaticToolCallbackResolver의 경우
                else if (resolver instanceof StaticToolCallbackResolver staticResolver) {
                    var tools = staticResolver.getAllTools();
                    allTools.addAll(tools.values());
                }
            } catch (Exception e) {
                log.warn("Resolver에서 도구 수집 실패: {} - {}",
                    resolver.getClass().getSimpleName(), e.getMessage());
            }
        }

        log.info("총 {} 개의 도구 수집됨", allTools.size());
        return allTools.toArray(new ToolCallback[0]);
    }
    
    /**
     * 등록된 모든 도구 이름 반환
     * prefix 없는 기본 이름을 반환합니다.
     */
    public Set<String> getRegisteredToolNames() {
        Set<String> toolNames = new HashSet<>();

        // 캐시된 도구명
        toolNames.addAll(toolCache.keySet());

        // 모든 resolver에서 도구 이름 수집
        for (ToolCallbackResolver resolver : getResolvers()) {
            try {
                if (resolver instanceof SpringBeanToolCallbackResolver springResolver) {
                    var tools = springResolver.getAllTools();
                    toolNames.addAll(tools.keySet());
                } else if (resolver instanceof McpToolResolver mcpResolver) {
                    var tools = mcpResolver.getAllTools();
                    tools.forEach(tool -> toolNames.add(tool.getToolDefinition().name()));
                } else if (resolver instanceof StaticToolCallbackResolver staticResolver) {
                    var tools = staticResolver.getAllTools();
                    toolNames.addAll(tools.keySet());
                }
            } catch (Exception e) {
                log.debug("Resolver에서 도구 이름 수집 중 오류: {}", e.getMessage());
            }
        }

        return toolNames;
    }
    
    /**
     * 도구 통계 정보 반환 - 향상된 버전
     */
    public Map<String, Object> getToolStatistics() {
        Map<String, Object> stats = new HashMap<>();

        // 기본 통계
        stats.put("totalTools", getRegisteredToolNames().size());
        stats.put("cachedTools", toolCache.size());
        stats.put("resolverCount", getResolvers().size());
        stats.put("circuitBreakerState", circuitBreaker.getState().toString());

        // 도구 출처별 통계
        Map<String, Long> sourceStats = toolSourceMapping.values().stream()
            .collect(Collectors.groupingBy(source -> source, Collectors.counting()));
        stats.put("toolsBySource", sourceStats);

        // Resolver별 도구 개수
        Map<String, Integer> resolverToolCounts = new HashMap<>();
        for (ToolCallbackResolver resolver : getResolvers()) {
            String resolverName = resolver.getClass().getSimpleName();
            try {
                int toolCount = 0;
                if (resolver instanceof SpringBeanToolCallbackResolver springResolver) {
                    toolCount = springResolver.getAllTools().size();
                } else if (resolver instanceof McpToolResolver mcpResolver) {
                    toolCount = mcpResolver.getAllTools().size();
                } else if (resolver instanceof StaticToolCallbackResolver staticResolver) {
                    toolCount = staticResolver.getAllTools().size();
                }
                resolverToolCounts.put(resolverName, toolCount);
            } catch (Exception e) {
                resolverToolCounts.put(resolverName, 0);
            }
        }
        stats.put("resolverToolCounts", resolverToolCounts);

        // 캐시 효율성
        if (metricsCollector != null) {
            // MetricsCollector가 제공하는 메트릭 사용
            stats.put("metricsAvailable", true);
        }

        // 등록된 도구 이름들 (디버그 모드에서만)
        if (log.isDebugEnabled()) {
            stats.put("registeredTools", getRegisteredToolNames());
        }

        return stats;
    }
    
    /**
     * Resolver 목록 가져오기
     */
    private List<ToolCallbackResolver> getResolvers() {
        // DelegatingToolCallbackResolver의 resolver 목록
        return Arrays.asList(
            mcpToolResolver,
            springBeanToolCallbackResolver,
            staticToolCallbackResolver,
            fallbackToolResolver
        );
    }

    /**
     * 통계 정보 반환 (기존 메서드 이름 - deprecated)
     *
     * @deprecated Use getToolStatistics() instead
     */
    @Deprecated
    public Map<String, Object> getStatistics() {
        return getToolStatistics();
    }

    /**
     * 도구를 찾을 수 없을 때 발생하는 예외
     */
    public static class ToolNotFoundException extends RuntimeException {
        public ToolNotFoundException(String message) {
            super(message);
        }
    }
}
