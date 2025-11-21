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

/**
 * SOAR Tool Integration Provider
 * 
 * Spring 컨텍스트에서 SOAR 도구들을 수집하여 제공하는 통합 Provider입니다.
 * @SoarTool 어노테이션이 있는 모든 Spring Bean들을 자동으로 발견하고 관리합니다.
 * 
 * 주요 기능:
 * - Spring ApplicationContext에서 SOAR 도구 자동 발견
 * - 도구별 위험도 레벨 관리
 * - 승인 정책 적용
 * - 도구 메타데이터 캐싱
 * 
 * 이 Provider는 UnifiedToolCallbackProvider와 통합되어
 * SOAR 도구들을 중앙에서 관리할 수 있게 합니다.
 */
@Slf4j
@RequiredArgsConstructor
public class SoarToolIntegrationProvider implements ToolIntegrationProvider {
    
    @Autowired
    private ApplicationContext applicationContext;
    
    // 도구 캐시
    private final Map<String, ToolCallback> toolCache = new ConcurrentHashMap<>();
    private final Map<String, SoarTool.RiskLevel> riskLevelCache = new ConcurrentHashMap<>();
    private final Map<String, ToolMetadata> metadataCache = new ConcurrentHashMap<>();
    
    // 초기화 상태
    private volatile boolean initialized = false;
    
    /**
     * 초기화 - Spring 컨텍스트에서 SOAR 도구들을 발견하고 캐싱
     */
    @PostConstruct
    public void initialize() {
        log.info("SoarToolIntegrationProvider 초기화 시작");
        
        try {
            discoverAndCacheSoarTools();
            initialized = true;
            
            log.info("SoarToolIntegrationProvider 초기화 완료: {} 개의 SOAR 도구 발견", 
                toolCache.size());
            
            // 발견된 도구 상세 로깅
            logDiscoveredTools();
            
        } catch (Exception e) {
            log.error("SoarToolIntegrationProvider 초기화 실패", e);
            initialized = false;
        }
    }
    
    /**
     * 모든 SOAR Tool Callback 반환
     */
    @Override
    public ToolCallback[] getToolCallbacks() {
        ensureInitialized();
        return toolCache.values().toArray(new ToolCallback[0]);
    }
    
    /**
     * 특정 SOAR 도구 가져오기
     */
    @Override
    public Optional<ToolCallback> getToolCallback(String name) {
        ensureInitialized();
        return Optional.ofNullable(toolCache.get(name));
    }
    
    /**
     * 도구의 위험도 레벨 확인
     */
    @Override
    public SoarTool.RiskLevel getToolRiskLevel(String name) {
        ensureInitialized();
        return riskLevelCache.getOrDefault(name, SoarTool.RiskLevel.MEDIUM);
    }
    
    /**
     * 승인이 필요한 도구인지 확인
     */
    @Override
    public boolean requiresApproval(String name) {
        SoarTool.RiskLevel riskLevel = getToolRiskLevel(name);
        
        // HIGH, CRITICAL 레벨은 승인 필요
        return riskLevel == SoarTool.RiskLevel.HIGH || 
               riskLevel == SoarTool.RiskLevel.CRITICAL;
    }
    
    /**
     * 등록된 SOAR 도구 이름 목록
     */
    @Override
    public Set<String> getRegisteredToolNames() {
        ensureInitialized();
        return new HashSet<>(toolCache.keySet());
    }
    
    /**
     * 프로바이더 타입
     */
    @Override
    public String getProviderType() {
        return "SOAR";
    }
    
    /**
     * 프로바이더 준비 상태
     */
    @Override
    public boolean isReady() {
        return initialized && !toolCache.isEmpty();
    }
    
    /**
     * 도구 메타데이터 조회
     */
    public ToolMetadata getToolMetadata(String name) {
        ensureInitialized();
        return metadataCache.get(name);
    }
    
    /**
     * 도구 통계 정보
     */
    public Map<String, Object> getStatistics() {
        Map<String, Object> stats = new HashMap<>();
        
        // 기본 통계
        stats.put("totalTools", toolCache.size());
        stats.put("initialized", initialized);
        
        // 위험도별 분포
        Map<SoarTool.RiskLevel, Long> riskDistribution = riskLevelCache.values().stream()
            .collect(Collectors.groupingBy(
                level -> level,
                Collectors.counting()
            ));
        stats.put("riskDistribution", riskDistribution);
        
        // 승인 필요 도구 개수
        long approvalRequiredCount = riskLevelCache.values().stream()
            .filter(level -> level == SoarTool.RiskLevel.HIGH || 
                           level == SoarTool.RiskLevel.CRITICAL)
            .count();
        stats.put("approvalRequiredTools", approvalRequiredCount);
        
        // 도구 카테고리별 분포
        Map<String, Long> categoryDistribution = metadataCache.values().stream()
            .collect(Collectors.groupingBy(
                metadata -> metadata.category,
                Collectors.counting()
            ));
        stats.put("categoryDistribution", categoryDistribution);
        
        return stats;
    }
    
    /**
     * 도구 재발견 및 캐시 갱신
     */
    public void refresh() {
        log.info("SOAR 도구 캐시 갱신 시작");
        
        toolCache.clear();
        riskLevelCache.clear();
        metadataCache.clear();
        
        discoverAndCacheSoarTools();
        
        log.info("SOAR 도구 캐시 갱신 완료: {} 개의 도구", toolCache.size());
    }
    
    // Private 메서드들
    
    /**
     * Spring 컨텍스트에서 SOAR 도구 발견 및 캐싱
     */
    private void discoverAndCacheSoarTools() {
        // 1. ToolCallback 인터페이스를 구현한 모든 빈 찾기
        Map<String, ToolCallback> toolCallbackBeans = 
            applicationContext.getBeansOfType(ToolCallback.class);
        
        log.debug("발견된 ToolCallback 빈: {} 개", toolCallbackBeans.size());
        
        for (Map.Entry<String, ToolCallback> entry : toolCallbackBeans.entrySet()) {
            String beanName = entry.getKey();
            ToolCallback toolCallback = entry.getValue();
            
            try {
                processSoarTool(beanName, toolCallback);
            } catch (Exception e) {
                log.warn("도구 처리 실패: {} - {}", beanName, e.getMessage());
            }
        }
        
        // 2. @SoarTool 어노테이션이 있는 빈들 찾기 (ToolCallback이 아닌 경우)
        Map<String, Object> soarToolBeans = 
            applicationContext.getBeansWithAnnotation(SoarTool.class);
        
        log.debug("@SoarTool 어노테이션 빈: {} 개", soarToolBeans.size());
        
        for (Map.Entry<String, Object> entry : soarToolBeans.entrySet()) {
            String beanName = entry.getKey();
            Object bean = entry.getValue();
            
            // ToolCallback이 아닌 경우 래핑 필요
            if (!(bean instanceof ToolCallback)) {
                try {
                    ToolCallback wrapped = wrapAsToolCallback(beanName, bean);
                    if (wrapped != null) {
                        processSoarTool(beanName, wrapped);
                    }
                } catch (Exception e) {
                    log.warn("도구 래핑 실패: {} - {}", beanName, e.getMessage());
                }
            }
        }
    }
    
    /**
     * SOAR 도구 처리 및 캐싱
     */
    private void processSoarTool(String beanName, ToolCallback toolCallback) {
        String toolName = toolCallback.getToolDefinition().name();
        
        // 도구 캐싱
        toolCache.put(toolName, toolCallback);
        
        // 위험도 레벨 추출 및 캐싱
        SoarTool.RiskLevel riskLevel = extractRiskLevel(toolCallback);
        riskLevelCache.put(toolName, riskLevel);
        
        // 메타데이터 생성 및 캐싱
        ToolMetadata metadata = createToolMetadata(beanName, toolCallback, riskLevel);
        metadataCache.put(toolName, metadata);
        
        log.debug("SOAR 도구 등록: {} (빈: {}, 위험도: {})", 
            toolName, beanName, riskLevel);
    }
    
    /**
     * @SoarTool 어노테이션이 있는 일반 빈을 ToolCallback으로 래핑
     */
    private ToolCallback wrapAsToolCallback(String beanName, Object bean) {
        Class<?> beanClass = bean.getClass();
        SoarTool soarTool = AnnotatedElementUtils.findMergedAnnotation(
            beanClass, SoarTool.class);
        
        if (soarTool == null) {
            return null;
        }
        
        // 간단한 래퍼 구현 (실제로는 더 정교한 구현 필요)
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
                        // 실제 구현에서는 메서드 파라미터를 분석하여 스키마 생성
                        return "{}";
                    }
                };
            }
            
            @Override
            public String call(String arguments) {
                // 실제 구현에서는 리플렉션을 사용하여 메서드 호출
                return "Tool execution not implemented for wrapped bean: " + beanName;
            }
        };
    }
    
    /**
     * ToolCallback에서 위험도 레벨 추출
     */
    private SoarTool.RiskLevel extractRiskLevel(ToolCallback toolCallback) {
        try {
            Class<?> toolClass = toolCallback.getClass();
            
            // 클래스 레벨 @SoarTool 확인
            SoarTool classAnnotation = AnnotatedElementUtils.findMergedAnnotation(
                toolClass, SoarTool.class);
            
            if (classAnnotation != null) {
                return classAnnotation.riskLevel();
            }
            
            // 메서드 레벨 @SoarTool 확인
            for (Method method : toolClass.getMethods()) {
                SoarTool methodAnnotation = AnnotatedElementUtils.findMergedAnnotation(
                    method, SoarTool.class);
                if (methodAnnotation != null) {
                    return methodAnnotation.riskLevel();
                }
            }
            
        } catch (Exception e) {
            log.debug("위험도 레벨 추출 실패: {} - {}", 
                toolCallback.getToolDefinition().name(), e.getMessage());
        }
        
        // 기본값
        return SoarTool.RiskLevel.MEDIUM;
    }
    
    /**
     * 도구 메타데이터 생성
     */
    private ToolMetadata createToolMetadata(String beanName, ToolCallback toolCallback, 
                                           SoarTool.RiskLevel riskLevel) {
        ToolDefinition definition = toolCallback.getToolDefinition();
        
        // 도구 이름에서 카테고리 추론
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
    
    /**
     * 도구 이름에서 카테고리 추론
     */
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
    
    /**
     * 초기화 상태 확인
     */
    private void ensureInitialized() {
        if (!initialized) {
            throw new IllegalStateException("SoarToolIntegrationProvider가 초기화되지 않았습니다");
        }
    }
    
    /**
     * 발견된 도구 상세 로깅
     */
    private void logDiscoveredTools() {
        if (!log.isInfoEnabled()) {
            return;
        }
        
        log.info("SOAR 도구 발견 상세:");
        
        // 카테고리별 그룹핑
        Map<String, List<ToolMetadata>> byCategory = metadataCache.values().stream()
            .collect(Collectors.groupingBy(m -> m.category));
        
        for (Map.Entry<String, List<ToolMetadata>> entry : byCategory.entrySet()) {
            String category = entry.getKey();
            List<ToolMetadata> tools = entry.getValue();
            
            log.info("  📁 {} 카테고리: {} 개 도구", category, tools.size());
            
            for (ToolMetadata tool : tools) {
                log.info("    └─ {} (위험도: {}, 승인: {})", 
                    tool.name, 
                    tool.riskLevel,
                    tool.requiresApproval ? "필요" : "불필요");
            }
        }
        
        // 위험도별 통계
        Map<SoarTool.RiskLevel, Long> riskStats = riskLevelCache.values().stream()
            .collect(Collectors.groupingBy(
                level -> level,
                Collectors.counting()
            ));
        
        log.info("  위험도별 분포:");
        for (Map.Entry<SoarTool.RiskLevel, Long> entry : riskStats.entrySet()) {
            log.info("    └─ {}: {} 개", entry.getKey(), entry.getValue());
        }
    }
    
    /**
     * 도구 메타데이터 내부 클래스
     */
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