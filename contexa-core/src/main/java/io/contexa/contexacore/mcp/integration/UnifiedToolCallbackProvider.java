package io.contexa.contexacore.mcp.integration;

import io.contexa.contexacore.mcp.tool.common.EnhancedToolCallback;
import io.contexa.contexacommon.annotation.SoarTool;
import lombok.extern.slf4j.Slf4j;
import org.springframework.ai.tool.ToolCallback;
import org.springframework.ai.tool.ToolCallbackProvider;
import org.springframework.ai.tool.definition.ToolDefinition;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.stereotype.Component;

import jakarta.annotation.PostConstruct;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.atomic.AtomicLong;

/**
 * Unified Tool Callback Provider
 * 
 * MCP와 SOAR 도구들을 완전히 통합하여 관리하는 통합 Provider입니다.
 * 
 * 주요 기능:
 * - MCP 도구의 투명한 프록시 호출
 * - SOAR와 MCP 간 통합된 승인 플로우 
 * - 도구 간 컨텍스트 공유
 * - 통합된 도구 관리 인터페이스
 * - Graceful degradation 및 오류 복구
 * 
 * 이 Provider가 MCP-SOAR 완벽 연동의 핵심 구현체입니다.
 */
@Slf4j
@Component("unifiedToolCallbackProvider")
public class UnifiedToolCallbackProvider implements ToolCallbackProvider {
    
    @Autowired(required = false)
    @Qualifier("soarToolIntegrationProvider")
    private ToolIntegrationProvider soarProvider;
    
    @Autowired(required = false)
    @Qualifier("mcpToolIntegrationAdapter")
    private ToolIntegrationProvider mcpProvider;
    
    // 통합된 도구 저장소
    private final Map<String, EnhancedToolCallback> unifiedTools = new ConcurrentHashMap<>();
    
    // 도구 호출 통계 및 모니터링
    private final Map<String, ToolExecutionStats> executionStats = new ConcurrentHashMap<>();
    private final AtomicLong totalExecutions = new AtomicLong(0);
    
    // 도구 컨텍스트 공유 저장소
    private final Map<String, Object> sharedContext = new ConcurrentHashMap<>();
    
    @PostConstruct
    public void initializeUnifiedProvider() {
        log.info("UnifiedToolCallbackProvider 초기화 시작");
        
        // SOAR 도구 등록 (직접 호출)
        registerSoarTools();
        
        // MCP 도구 등록 (프록시 호출)
        registerMcpTools();
        
        log.info("UnifiedToolCallbackProvider 초기화 완료: {} 개의 통합 도구", unifiedTools.size());
        
        // 통합 상태 로깅
        logIntegrationStatus();
    }
    
    /**
     * 모든 통합 도구 반환
     */
    @Override
    public ToolCallback[] getToolCallbacks() {
        return unifiedTools.values().toArray(new ToolCallback[0]);
    }
    
    /**
     * 특정 도구 가져오기
     */
    public Optional<EnhancedToolCallback> getUnifiedToolCallback(String name) {
        return Optional.ofNullable(unifiedTools.get(name));
    }
    
    /**
     * 도구 타입별 필터링
     */
    public ToolCallback[] getToolCallbacksByType(EnhancedToolCallback.ToolType type) {
        return unifiedTools.values().stream()
            .filter(tool -> tool.getToolType() == type)
            .toArray(ToolCallback[]::new);
    }
    
    /**
     * 위험도별 도구 필터링 (SOAR + MCP 통합)
     */
    public ToolCallback[] getToolCallbacksByRiskLevel(SoarTool.RiskLevel... levels) {
        Set<SoarTool.RiskLevel> levelSet = new HashSet<>(Arrays.asList(levels));
        
        return unifiedTools.values().stream()
            .filter(tool -> levelSet.contains(tool.getRiskLevel()))
            .toArray(ToolCallback[]::new);
    }
    
    /**
     * 승인이 필요한 도구인지 통합 판단
     */
    public boolean requiresApproval(String toolName) {
        EnhancedToolCallback tool = unifiedTools.get(toolName);
        if (tool == null) return false;
        
        // 도구 자체의 requiresApproval 플래그 우선 확인
        if (tool.isRequiresApproval()) {
            return true;
        }
        
        // 프로바이더 타입에 따라 승인 필요 여부 판단
        if (tool.getToolType() == EnhancedToolCallback.ToolType.SOAR && soarProvider != null) {
            return soarProvider.requiresApproval(toolName);
        }
        
        if (tool.getToolType() == EnhancedToolCallback.ToolType.MCP && mcpProvider != null) {
            return mcpProvider.requiresApproval(toolName);
        }
        
        return false;
    }
    
    /**
     * 도구 실행 결과 추적 및 컨텍스트 공유
     */
    public CompletableFuture<String> executeToolWithContext(String toolName, String arguments, 
                                                           Map<String, Object> executionContext) {
        return CompletableFuture.supplyAsync(() -> {
            try {
                EnhancedToolCallback tool = unifiedTools.get(toolName);
                if (tool == null) {
                    throw new IllegalArgumentException("도구를 찾을 수 없음: " + toolName);
                }
                
                // 실행 전 컨텍스트 준비
                prepareExecutionContext(toolName, executionContext);
                
                // 통계 수집 시작
                long startTime = System.currentTimeMillis();
                ToolExecutionStats stats = executionStats.computeIfAbsent(toolName, 
                    k -> new ToolExecutionStats(toolName));
                
                // 도구 실행
                String result = tool.call(arguments);
                
                // 실행 후 처리
                long executionTime = System.currentTimeMillis() - startTime;
                stats.recordExecution(executionTime, true);
                totalExecutions.incrementAndGet();
                
                // 컨텍스트 업데이트
                updateSharedContext(toolName, result, executionContext);
                
                log.debug("도구 실행 완료: {} ({}ms)", toolName, executionTime);
                return result;
                
            } catch (Exception e) {
                // 실행 실패 처리
                ToolExecutionStats stats = executionStats.get(toolName);
                if (stats != null) {
                    stats.recordExecution(0, false);
                }
                
                log.error("도구 실행 실패: {} - {}", toolName, e.getMessage(), e);
                
                // Graceful degradation
                return handleToolExecutionFailure(toolName, arguments, e);
            }
        });
    }
    
    /**
     * 통합 통계 정보
     */
    public UnifiedIntegrationStats getUnifiedIntegrationStats() {
        int soarToolCount = (int) unifiedTools.values().stream()
            .filter(tool -> tool.getToolType() == EnhancedToolCallback.ToolType.SOAR).count();
        
        int mcpToolCount = (int) unifiedTools.values().stream()
            .filter(tool -> tool.getToolType() == EnhancedToolCallback.ToolType.MCP).count();
        
        return new UnifiedIntegrationStats(
            soarToolCount,
            mcpToolCount,
            unifiedTools.size(),
            totalExecutions.get(),
            mcpProvider != null,
            System.currentTimeMillis()
        );
    }
    
    // Private 메서드들
    
    /**
     * SOAR 도구 등록 (직접 호출)
     */
    private void registerSoarTools() {
        if (soarProvider == null) {
            log.info("SOAR Provider가 없어 SOAR 도구 건너뜀");
            return;
        }
        
        try {
            ToolCallback[] soarTools = soarProvider.getToolCallbacks();
            
            for (ToolCallback soarTool : soarTools) {
                String toolName = soarTool.getToolDefinition().name();
                SoarTool.RiskLevel riskLevel = soarProvider.getToolRiskLevel(toolName);
                
                EnhancedToolCallback unifiedTool = EnhancedToolCallback.builder()
                    .delegate(soarTool)
                    .toolType(EnhancedToolCallback.ToolType.SOAR)
                    .riskLevel(riskLevel)
                    .securityValidation(true)
                    .requiresApproval(riskLevel == SoarTool.RiskLevel.HIGH || 
                                     riskLevel == SoarTool.RiskLevel.CRITICAL)
                    .source("SoarProvider")
                    .category("SOAR")
                    .build();
                
                unifiedTools.put(toolName, unifiedTool);
                log.debug("SOAR 도구 등록: {} (위험도: {})", toolName, riskLevel);
            }
            
            log.info("SOAR 도구 등록 완료: {} 개", soarTools.length);
            
        } catch (Exception e) {
            log.warn("SOAR 도구 등록 실패: {}", e.getMessage());
        }
    }
    
    /**
     * MCP 도구 등록 (프록시 호출)
     */
    private void registerMcpTools() {
        if (mcpProvider == null) {
            log.info("MCP Provider가 없어 MCP 도구 건너뜀");
            return;
        }
        
        try {
            ToolCallback[] mcpTools = mcpProvider.getToolCallbacks();
            
            for (ToolCallback mcpTool : mcpTools) {
                String toolName = mcpTool.getToolDefinition().name();
                
                // MCP 도구는 프록시로 래핑
                EnhancedToolCallback unifiedTool = EnhancedToolCallback.builder()
                    .delegate(mcpTool)
                    .toolType(EnhancedToolCallback.ToolType.MCP)
                    .riskLevel(SoarTool.RiskLevel.LOW)
                    .contextAware(true)
                    .source("McpProvider")
                    .category("MCP")
                    .build();
                
                unifiedTools.put(toolName, unifiedTool);
                log.debug("MCP 도구 등록: {} (프록시)", toolName);
            }
            
            log.info("MCP 도구 등록 완료: {} 개", mcpTools.length);
            
        } catch (Exception e) {
            log.warn("MCP 도구 등록 실패: {}", e.getMessage());
        }
    }
    
    /**
     * MCP 도구 위험도 평가
     */
    private boolean assessMcpToolRisk(String toolName) {
        // 현재는 기본값, 향후 MCP 도구별 정책 확장 가능
        return false;
    }
    
    /**
     * 실행 컨텍스트 준비
     */
    private void prepareExecutionContext(String toolName, Map<String, Object> context) {
        // 공유 컨텍스트에서 관련 정보 추가
        context.putAll(sharedContext);
        context.put("executionId", UUID.randomUUID().toString());
        context.put("timestamp", System.currentTimeMillis());
        context.put("toolName", toolName);
    }
    
    /**
     * 공유 컨텍스트 업데이트
     */
    private void updateSharedContext(String toolName, String result, Map<String, Object> context) {
        sharedContext.put("lastExecutedTool", toolName);
        sharedContext.put("lastExecutionResult", result);
        sharedContext.put("lastExecutionTime", System.currentTimeMillis());
        
        // 도구별 결과 히스토리 (최근 5개만 유지)
        String historyKey = "history_" + toolName;
        @SuppressWarnings("unchecked")
        List<String> history = (List<String>) sharedContext.computeIfAbsent(historyKey, 
            k -> new ArrayList<String>());
        
        history.add(result);
        if (history.size() > 5) {
            history.remove(0);
        }
    }
    
    /**
     * 도구 실행 실패 처리 (Graceful Degradation)
     */
    private String handleToolExecutionFailure(String toolName, String arguments, Exception error) {
        // 실패 로그 기록
        log.error("도구 실행 실패 - 도구: {}, 인수: {}, 오류: {}", toolName, arguments, error.getMessage());
        
        // 대체 동작 시도 - 도구 유형별로 처리
        if (toolName.contains("search")) {
            return "검색 서비스 일시 불가, 나중에 다시 시도해주세요: " + error.getMessage();
        }
        
        if (toolName.contains("security") || toolName.contains("scan")) {
            return "보안 도구 일시 불가, 시스템 관리자에게 문의하세요: " + error.getMessage();
        }
        
        // SOAR 도구 실패
        if (unifiedTools.containsKey(toolName) && 
            unifiedTools.get(toolName).getToolType() == EnhancedToolCallback.ToolType.SOAR) {
            return "SOAR 보안 도구 실행 실패, 수동 확인이 필요합니다: " + error.getMessage();
        }
        
        return "도구 실행 실패: " + error.getMessage();
    }
    
    /**
     * 통합 상태 로깅
     */
    private void logIntegrationStatus() {
        UnifiedIntegrationStats stats = getUnifiedIntegrationStats();
        
        log.info("🔗 UnifiedToolCallbackProvider 통합 상태:");
        log.info("  ├─ SOAR 도구: {} 개 (직접 호출)", stats.soarToolCount());
        log.info("  ├─ MCP 도구: {} 개 (프록시 호출)", stats.mcpToolCount());
        log.info("  ├─ 총 통합 도구: {} 개", stats.totalToolCount());
        log.info("  └─ MCP 활성화: {}", stats.mcpEnabled() ? "✅" : "❌");
        
        // 위험도별 분포
        Map<SoarTool.RiskLevel, Long> riskDistribution = unifiedTools.values().stream()
            .collect(java.util.stream.Collectors.groupingBy(
                EnhancedToolCallback::getRiskLevel,
                java.util.stream.Collectors.counting()
            ));
        
        log.info("위험도별 도구 분포:");
        riskDistribution.forEach((level, count) -> {
            log.info("  └─ {}: {} 개 도구", level, count);
        });
    }
    
    // 내부 클래스들
    
    
    /**
     * 도구 실행 통계
     */
    public static class ToolExecutionStats {
        private final String toolName;
        private long totalExecutions = 0;
        private long successfulExecutions = 0;
        private long totalExecutionTime = 0;
        private long lastExecutionTime = 0;
        
        public ToolExecutionStats(String toolName) {
            this.toolName = toolName;
        }
        
        public synchronized void recordExecution(long executionTime, boolean success) {
            totalExecutions++;
            totalExecutionTime += executionTime;
            lastExecutionTime = System.currentTimeMillis();
            
            if (success) {
                successfulExecutions++;
            }
        }
        
        public String getToolName() { return toolName; }
        public long getTotalExecutions() { return totalExecutions; }
        public long getSuccessfulExecutions() { return successfulExecutions; }
        public double getSuccessRate() { 
            return totalExecutions > 0 ? (double) successfulExecutions / totalExecutions : 0.0; 
        }
        public double getAverageExecutionTime() { 
            return totalExecutions > 0 ? (double) totalExecutionTime / totalExecutions : 0.0; 
        }
        public long getLastExecutionTime() { return lastExecutionTime; }
    }
    
    /**
     * 통합 통계 정보 레코드
     */
    public record UnifiedIntegrationStats(
        int soarToolCount,
        int mcpToolCount,
        int totalToolCount,
        long totalExecutions,
        boolean mcpEnabled,
        long lastUpdateTime
    ) {}
}