package io.contexa.contexacoreenterprise.soar.tool.provider;

import io.contexa.contexacoreenterprise.mcp.integration.ToolIntegrationProvider;
import io.contexa.contexacommon.annotation.SoarTool;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.ai.tool.ToolCallback;
import org.springframework.ai.tool.definition.ToolDefinition;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.ApplicationContext;
import org.springframework.core.annotation.AnnotatedElementUtils;

import jakarta.annotation.PostConstruct;
import java.lang.reflect.Method;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.stream.Collectors;

@Slf4j
@RequiredArgsConstructor
public class SoarToolIntegrationProvider implements ToolIntegrationProvider {
    
    @Autowired
    private ApplicationContext applicationContext;

    private final Map<String, ToolCallback> toolCache = new ConcurrentHashMap<>();
    private final Map<String, SoarTool.RiskLevel> riskLevelCache = new ConcurrentHashMap<>();
    private final Map<String, ToolMetadata> metadataCache = new ConcurrentHashMap<>();

    private volatile boolean initialized = false;

    @PostConstruct
    public void initialize() {
                
        try {
            discoverAndCacheSoarTools();
            initialized = true;

            logDiscoveredTools();
            
        } catch (Exception e) {
            log.error("SoarToolIntegrationProvider initialization failed", e);
            initialized = false;
        }
    }

    @Override
    public ToolCallback[] getToolCallbacks() {
        ensureInitialized();
        return toolCache.values().toArray(new ToolCallback[0]);
    }

    @Override
    public Optional<ToolCallback> getToolCallback(String name) {
        ensureInitialized();
        return Optional.ofNullable(toolCache.get(name));
    }

    @Override
    public SoarTool.RiskLevel getToolRiskLevel(String name) {
        ensureInitialized();
        return riskLevelCache.getOrDefault(name, SoarTool.RiskLevel.MEDIUM);
    }

    @Override
    public boolean requiresApproval(String name) {
        SoarTool.RiskLevel riskLevel = getToolRiskLevel(name);

        return riskLevel == SoarTool.RiskLevel.HIGH || 
               riskLevel == SoarTool.RiskLevel.CRITICAL;
    }

    @Override
    public Set<String> getRegisteredToolNames() {
        ensureInitialized();
        return new HashSet<>(toolCache.keySet());
    }

    @Override
    public String getProviderType() {
        return "SOAR";
    }

    @Override
    public boolean isReady() {
        return initialized && !toolCache.isEmpty();
    }

    public ToolMetadata getToolMetadata(String name) {
        ensureInitialized();
        return metadataCache.get(name);
    }

    public Map<String, Object> getStatistics() {
        Map<String, Object> stats = new HashMap<>();

        stats.put("totalTools", toolCache.size());
        stats.put("initialized", initialized);

        Map<SoarTool.RiskLevel, Long> riskDistribution = riskLevelCache.values().stream()
            .collect(Collectors.groupingBy(
                level -> level,
                Collectors.counting()
            ));
        stats.put("riskDistribution", riskDistribution);

        long approvalRequiredCount = riskLevelCache.values().stream()
            .filter(level -> level == SoarTool.RiskLevel.HIGH || 
                           level == SoarTool.RiskLevel.CRITICAL)
            .count();
        stats.put("approvalRequiredTools", approvalRequiredCount);

        Map<String, Long> categoryDistribution = metadataCache.values().stream()
            .collect(Collectors.groupingBy(
                metadata -> metadata.category,
                Collectors.counting()
            ));
        stats.put("categoryDistribution", categoryDistribution);
        
        return stats;
    }

    public void refresh() {
                
        toolCache.clear();
        riskLevelCache.clear();
        metadataCache.clear();
        
        discoverAndCacheSoarTools();
        
            }

    private void discoverAndCacheSoarTools() {
        
        Map<String, ToolCallback> toolCallbackBeans = 
            applicationContext.getBeansOfType(ToolCallback.class);

        for (Map.Entry<String, ToolCallback> entry : toolCallbackBeans.entrySet()) {
            String beanName = entry.getKey();
            ToolCallback toolCallback = entry.getValue();
            
            try {
                processSoarTool(beanName, toolCallback);
            } catch (Exception e) {
                log.error("Tool processing failed: {} - {}", beanName, e.getMessage());
            }
        }

        Map<String, Object> soarToolBeans = 
            applicationContext.getBeansWithAnnotation(SoarTool.class);

        for (Map.Entry<String, Object> entry : soarToolBeans.entrySet()) {
            String beanName = entry.getKey();
            Object bean = entry.getValue();

            if (!(bean instanceof ToolCallback)) {
                try {
                    ToolCallback wrapped = wrapAsToolCallback(beanName, bean);
                    if (wrapped != null) {
                        processSoarTool(beanName, wrapped);
                    }
                } catch (Exception e) {
                    log.error("Tool wrapping failed: {} - {}", beanName, e.getMessage());
                }
            }
        }
    }

    private void processSoarTool(String beanName, ToolCallback toolCallback) {
        String toolName = toolCallback.getToolDefinition().name();

        toolCache.put(toolName, toolCallback);

        SoarTool.RiskLevel riskLevel = extractRiskLevel(toolCallback);
        riskLevelCache.put(toolName, riskLevel);

        ToolMetadata metadata = createToolMetadata(beanName, toolCallback, riskLevel);
        metadataCache.put(toolName, metadata);
        
            }

    private ToolCallback wrapAsToolCallback(String beanName, Object bean) {
        Class<?> beanClass = bean.getClass();
        SoarTool soarTool = AnnotatedElementUtils.findMergedAnnotation(
            beanClass, SoarTool.class);
        
        if (soarTool == null) {
            return null;
        }

        return new ToolCallback() {
            @Override
            public ToolDefinition getToolDefinition() {
                return new ToolDefinition() {
                    @Override
                    public String name() {
                        return soarTool.name().isEmpty() ? beanName : soarTool.name();
                    }
                    
                    @Override
                    public String description() {
                        return soarTool.description();
                    }
                    
                    @Override
                    public String inputSchema() {
                        
                        return "{}";
                    }
                };
            }
            
            @Override
            public String call(String arguments) {
                try {
                    Method[] methods = bean.getClass().getDeclaredMethods();
                    for (Method method : methods) {
                        if (method.isAnnotationPresent(SoarTool.class)) {
                            method.setAccessible(true);
                            Object result;
                            if (method.getParameterCount() == 1) {
                                result = method.invoke(bean, arguments);
                            } else if (method.getParameterCount() == 0) {
                                result = method.invoke(bean);
                            } else {
                                log.error("Unsupported parameter count for @SoarTool method on bean: {}", beanName);
                                return "";
                            }
                            return result != null ? result.toString() : "";
                        }
                    }
                    log.error("No @SoarTool method found on bean: {}", beanName);
                    return "";
                } catch (Exception e) {
                    log.error("Tool execution failed for bean: {}", beanName, e);
                    throw new RuntimeException("Tool execution failed: " + beanName, e);
                }
            }
        };
    }

    private SoarTool.RiskLevel extractRiskLevel(ToolCallback toolCallback) {
        try {
            Class<?> toolClass = toolCallback.getClass();

            SoarTool classAnnotation = AnnotatedElementUtils.findMergedAnnotation(
                toolClass, SoarTool.class);
            
            if (classAnnotation != null) {
                return classAnnotation.riskLevel();
            }

            for (Method method : toolClass.getMethods()) {
                SoarTool methodAnnotation = AnnotatedElementUtils.findMergedAnnotation(
                    method, SoarTool.class);
                if (methodAnnotation != null) {
                    return methodAnnotation.riskLevel();
                }
            }
            
        } catch (Exception e) {
            log.error("Failed to extract risk level from tool: {}", toolCallback.getToolDefinition().name(), e);
        }

        return SoarTool.RiskLevel.MEDIUM;
    }

    private ToolMetadata createToolMetadata(String beanName, ToolCallback toolCallback, 
                                           SoarTool.RiskLevel riskLevel) {
        ToolDefinition definition = toolCallback.getToolDefinition();

        String category = inferCategory(definition.name());
        
        return new ToolMetadata(
            definition.name(),
            beanName,
            definition.description(),
            riskLevel,
            category,
            requiresApproval(definition.name()),
            System.currentTimeMillis()
        );
    }

    private String inferCategory(String toolName) {
        String lowerName = toolName.toLowerCase();
        
        if (lowerName.contains("network") || lowerName.contains("scan")) {
            return "NETWORK";
        } else if (lowerName.contains("process") || lowerName.contains("system")) {
            return "SYSTEM";
        } else if (lowerName.contains("file") || lowerName.contains("directory")) {
            return "FILESYSTEM";
        } else if (lowerName.contains("security") || lowerName.contains("threat")) {
            return "SECURITY";
        } else if (lowerName.contains("log") || lowerName.contains("audit")) {
            return "MONITORING";
        } else {
            return "GENERAL";
        }
    }

    private void ensureInitialized() {
        if (!initialized) {
            throw new IllegalStateException("SoarToolIntegrationProvider is not initialized");
        }
    }

    private void logDiscoveredTools() {
        if (!log.isInfoEnabled()) {
            return;
        }

        Map<String, List<ToolMetadata>> byCategory = metadataCache.values().stream()
            .collect(Collectors.groupingBy(m -> m.category));
        
        for (Map.Entry<String, List<ToolMetadata>> entry : byCategory.entrySet()) {
            String category = entry.getKey();
            List<ToolMetadata> tools = entry.getValue();

            for (ToolMetadata tool : tools) {
                            }
        }

        Map<SoarTool.RiskLevel, Long> riskStats = riskLevelCache.values().stream()
            .collect(Collectors.groupingBy(
                level -> level,
                Collectors.counting()
            ));
        
                for (Map.Entry<SoarTool.RiskLevel, Long> entry : riskStats.entrySet()) {
                    }
    }

    public static class ToolMetadata {
        public final String name;
        public final String beanName;
        public final String description;
        public final SoarTool.RiskLevel riskLevel;
        public final String category;
        public final boolean requiresApproval;
        public final long registeredAt;
        
        public ToolMetadata(String name, String beanName, String description,
                           SoarTool.RiskLevel riskLevel, String category,
                           boolean requiresApproval, long registeredAt) {
            this.name = name;
            this.beanName = beanName;
            this.description = description;
            this.riskLevel = riskLevel;
            this.category = category;
            this.requiresApproval = requiresApproval;
            this.registeredAt = registeredAt;
        }
    }
}