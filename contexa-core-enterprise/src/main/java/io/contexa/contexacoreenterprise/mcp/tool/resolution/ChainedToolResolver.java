package io.contexa.contexacoreenterprise.mcp.tool.resolution;

import io.contexa.contexacommon.mcp.tool.ToolResolver;
import io.github.resilience4j.circuitbreaker.CircuitBreaker;
import io.github.resilience4j.circuitbreaker.CircuitBreakerConfig;
import io.contexa.contexacoreenterprise.mcp.tool.common.EnhancedToolCallback;
import io.contexa.contexacoreenterprise.dashboard.metrics.mcp.MCPToolMetrics;
import jakarta.annotation.PostConstruct;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.ai.tool.ToolCallback;
import org.springframework.ai.tool.resolution.DelegatingToolCallbackResolver;
import org.springframework.ai.tool.resolution.ToolCallbackResolver;
import org.springframework.context.annotation.Primary;


import java.time.Duration;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.stream.Collectors;



@Primary
@Slf4j
@RequiredArgsConstructor
public class ChainedToolResolver implements ToolCallbackResolver, ToolResolver {
    
    private final MCPToolMetrics metricsCollector;
    private final SpringBeanToolCallbackResolver springBeanToolCallbackResolver;
    private final McpToolResolver mcpToolResolver;
    private final StaticToolCallbackResolver staticToolCallbackResolver;
    private final FallbackToolResolver fallbackToolResolver;
    
    
    private DelegatingToolCallbackResolver delegatingResolver;
    private CircuitBreaker circuitBreaker;
    private final Map<String, ToolCallback> toolCache = new ConcurrentHashMap<>();
    private final Map<String, String> toolSourceMapping = new ConcurrentHashMap<>(); 

    @PostConstruct
    public void init() {
        
        List<ToolCallbackResolver> resolvers = Arrays.asList(
            mcpToolResolver,                
            springBeanToolCallbackResolver,  
            staticToolCallbackResolver,      
            fallbackToolResolver            
        );
        this.delegatingResolver = new DelegatingToolCallbackResolver(resolvers);

        
        CircuitBreakerConfig config = CircuitBreakerConfig.custom()
            .failureRateThreshold(50)
            .waitDurationInOpenState(Duration.ofSeconds(30))
            .permittedNumberOfCallsInHalfOpenState(3)
            .slidingWindowSize(10)
            .build();

        this.circuitBreaker = CircuitBreaker.of("tool-resolver", config);

        log.info("ChainedToolResolver 초기화 완료: {} 개의 Resolver", resolvers.size());

        
        initializeToolCache();
    }
    
    
    private void initializeToolCache() {
        try {
            Set<String> toolNames = getRegisteredToolNames();
            log.info("초기 도구 캐시 구성: {} 개 도구", toolNames.size());

            
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
    
    
    private boolean shouldPreCache(String toolName) {
        
        return toolName.contains("query") ||
               toolName.contains("analysis") ||
               toolName.contains("scan");
    }

    
    @Override
    public ToolCallback resolve(String toolName) {
        
        ToolCallback cached = toolCache.get(toolName);
        if (cached != null) {
            log.trace("도구 캐시에서 반환: {}", toolName);
            metricsCollector.recordCacheHit(toolName);
            return cached;
        }

        
        try {
            return circuitBreaker.executeSupplier(() -> resolveInternal(toolName));
        } catch (Exception e) {
            log.warn("Circuit Breaker 오픈 상태. Fallback 사용: {}", toolName);
            return fallbackToolResolver.resolve(toolName);
        }
    }
    
    
    private ToolCallback resolveInternal(String toolName) {
        long startTime = System.nanoTime();

        try {
            
            ToolCallback tool = delegatingResolver.resolve(toolName);

            if (tool != null) {
                long elapsedTime = System.nanoTime() - startTime;

                
                String resolverName = identifyResolver(tool);
                metricsCollector.recordResolution(resolverName, elapsedTime);

                log.debug("도구 발견: {} (resolver: {}, 시간: {}μs)",
                         toolName, resolverName, elapsedTime / 1000);

                
                ToolCallback enhancedTool = enhanceToolCallback(tool, toolName, resolverName);

                
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
    
    
    private ToolCallback enhanceToolCallback(ToolCallback tool, String toolName, String resolverName) {
        
        if (tool instanceof EnhancedToolCallback) {
            return tool;
        }

        
        Map<String, Object> metadata = new HashMap<>();
        

        
        metadata.put("resolver", resolverName);
        metadata.put("cached", false);
        metadata.put("enhancedAt", System.currentTimeMillis());

        
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
            .metricsCollector(metricsCollector)  
            .build();
    }
    
    
    private String identifyResolver(ToolCallback tool) {
        
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

    
    private EnhancedToolCallback.ToolType determineToolType(ToolCallback tool, Map<String, Object> metadata) {
        
        if (metadata.containsKey("type")) {
            String type = metadata.get("type").toString().toUpperCase();
            try {
                return EnhancedToolCallback.ToolType.valueOf(type);
            } catch (Exception e) {
                log.debug("알 수 없는 도구 타입: {}", type);
            }
        }

        
        if (metadata.containsKey("source")) {
            String source = metadata.get("source").toString();
            if ("mcp".equalsIgnoreCase(source)) {
                return EnhancedToolCallback.ToolType.MCP;
            }
        }

        
        String toolName = tool.getToolDefinition().name();
        if (toolName.contains("fallback")) {
            return EnhancedToolCallback.ToolType.FALLBACK;
        }

        
        return EnhancedToolCallback.ToolType.SOAR;
    }
    
    
    private Map<String, ToolCallback> getStaticTools() {
        
        return Map.of();
    }

    
    public void clearCache() {
        toolCache.clear();
        log.info("도구 캐시 초기화됨");
    }

    
    @Override
    public ToolCallback[] getAllToolCallbacks() {
        List<ToolCallback> allTools = new ArrayList<>();

        for (ToolCallbackResolver resolver : getResolvers()) {
            try {
                
                if (resolver instanceof SpringBeanToolCallbackResolver springResolver) {
                    var tools = springResolver.getAllTools();
                    allTools.addAll(tools.values());
                }
                
                else if (resolver instanceof McpToolResolver mcpResolver) {
                    var tools = mcpResolver.getAllTools();
                    allTools.addAll(tools);
                }
                
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
    
    
    public Set<String> getRegisteredToolNames() {
        Set<String> toolNames = new HashSet<>();

        
        toolNames.addAll(toolCache.keySet());

        
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
    
    
    public Map<String, Object> getToolStatistics() {
        Map<String, Object> stats = new HashMap<>();

        
        stats.put("totalTools", getRegisteredToolNames().size());
        stats.put("cachedTools", toolCache.size());
        stats.put("resolverCount", getResolvers().size());
        stats.put("circuitBreakerState", circuitBreaker.getState().toString());

        
        Map<String, Long> sourceStats = toolSourceMapping.values().stream()
            .collect(Collectors.groupingBy(source -> source, Collectors.counting()));
        stats.put("toolsBySource", sourceStats);

        
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

        
        if (metricsCollector != null) {
            
            stats.put("metricsAvailable", true);
        }

        
        if (log.isDebugEnabled()) {
            stats.put("registeredTools", getRegisteredToolNames());
        }

        return stats;
    }
    
    
    private List<ToolCallbackResolver> getResolvers() {
        
        return Arrays.asList(
            mcpToolResolver,
            springBeanToolCallbackResolver,
            staticToolCallbackResolver,
            fallbackToolResolver
        );
    }

    
    @Deprecated
    public Map<String, Object> getStatistics() {
        return getToolStatistics();
    }

    
    public static class ToolNotFoundException extends RuntimeException {
        public ToolNotFoundException(String message) {
            super(message);
        }
    }
}
