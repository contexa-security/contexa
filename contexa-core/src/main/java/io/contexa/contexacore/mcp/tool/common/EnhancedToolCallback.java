package io.contexa.contexacore.mcp.tool.common;

import io.contexa.contexacommon.annotation.SoarTool;
import lombok.Builder;
import lombok.Getter;
import lombok.extern.slf4j.Slf4j;
import org.springframework.ai.tool.ToolCallback;
import org.springframework.ai.tool.definition.ToolDefinition;

import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Enhanced Tool Callback
 * 
 * 통합된 ToolCallback wrapper로 모든 도구 타입을 지원합니다.
 * 기존의 5개 wrapper 클래스를 하나로 통합하여 중복을 제거합니다.
 * 
 * 지원 기능:
 * - 도구 타입 구분 (SOAR, MCP, FALLBACK)
 * - 위험도 레벨 관리
 * - 컨텍스트 전파
 * - 보안 검증
 * - 실행 통계
 * - 메타데이터 관리
 */
@Slf4j
@Getter
@Builder
public class EnhancedToolCallback implements ToolCallback {
    
    /**
     * 도구 타입
     */
    public enum ToolType {
        SOAR("SOAR 보안 도구"),
        MCP("MCP 외부 도구"),
        FALLBACK("Fallback 도구"),
        NATIVE("Native Spring AI 도구");
        
        private final String description;
        
        ToolType(String description) {
            this.description = description;
        }
    }
    
    // 필수 필드
    private final ToolCallback delegate;
    private final ToolType toolType;
    
    // 선택적 필드 (Builder 패턴)
    @Builder.Default
    private final SoarTool.RiskLevel riskLevel = SoarTool.RiskLevel.MEDIUM;
    
    @Builder.Default
    private final Map<String, Object> metadata = new ConcurrentHashMap<>();
    
    @Builder.Default
    private final boolean requiresApproval = false;
    
    @Builder.Default
    private final boolean contextAware = false;
    
    @Builder.Default
    private final boolean securityValidation = false;
    
    private final String source;  // 도구 출처 (예: "brave-search", "soar-provider")
    private final String category; // 도구 카테고리 (예: "NETWORK", "SECURITY")
    
    // 실행 통계
    @Builder.Default
    private final ExecutionStats stats = new ExecutionStats();
    
    /**
     * Tool Definition 반환
     */
    @Override
    public ToolDefinition getToolDefinition() {
        return delegate.getToolDefinition();
    }
    
    /**
     * 도구 실행 - 향상된 기능과 함께
     */
    @Override
    public String call(String arguments) {
        long startTime = System.currentTimeMillis();
        String result = null;
        boolean success = false;
        
        try {
            // 실행 전 처리
            beforeExecution(arguments);
            
            // 보안 검증
            if (securityValidation) {
                validateSecurity(arguments);
            }
            
            // 컨텍스트 전파
            if (contextAware) {
                arguments = enrichWithContext(arguments);
            }
            
            // 실제 도구 실행
            result = delegate.call(arguments);
            success = true;
            
            // 실행 후 처리
            afterExecution(result);
            
            return result;
            
        } catch (Exception e) {
            log.error("도구 실행 실패: {} - {}", getToolName(), e.getMessage(), e);
            handleExecutionError(e);
            throw new RuntimeException("Tool execution failed: " + e.getMessage(), e);
            
        } finally {
            // 통계 기록
            long executionTime = System.currentTimeMillis() - startTime;
            stats.record(executionTime, success);
            
            log.trace("도구 실행 완료: {} ({}ms, 성공: {})", 
                getToolName(), executionTime, success);
        }
    }
    
    /**
     * 도구 이름 반환
     */
    public String getToolName() {
        return delegate.getToolDefinition().name();
    }
    
    /**
     * 도구 설명 반환
     */
    public String getDescription() {
        return String.format("%s - %s (위험도: %s)", 
            delegate.getToolDefinition().description(),
            toolType.description,
            riskLevel);
    }
    
    /**
     * 메타데이터 추가
     */
    public void addMetadata(String key, Object value) {
        metadata.put(key, value);
    }
    
    /**
     * 메타데이터 조회
     */
    public Object getMetadata(String key) {
        return metadata.get(key);
    }
    
    // Private 메서드들
    
    private void beforeExecution(String arguments) {
        log.trace("도구 실행 시작: {} (타입: {}, 위험도: {})", 
            getToolName(), toolType, riskLevel);
        
        // 승인 필요시 체크
        if (requiresApproval) {
            log.debug("승인 필요 도구: {}", getToolName());
            // 실제 승인 로직은 ApprovalAwareToolCallingManager에서 처리
        }
    }
    
    private void afterExecution(String result) {
        log.trace("도구 실행 성공: {}", getToolName());
        
        // 결과 캐싱 등 후처리
        if (metadata.containsKey("cache_results") && 
            Boolean.TRUE.equals(metadata.get("cache_results"))) {
            // 캐싱 로직
        }
    }
    
    private void validateSecurity(String arguments) {
        // 보안 검증 로직
        if (riskLevel == SoarTool.RiskLevel.CRITICAL) {
            log.warn("CRITICAL 위험도 도구 실행: {}", getToolName());
        }
        
        // 인수 검증
        if (arguments != null && arguments.contains("sudo") || 
            arguments.contains("rm -rf")) {
            throw new SecurityException("위험한 명령어 감지: " + arguments);
        }
    }
    
    private String enrichWithContext(String arguments) {
        // 컨텍스트 정보 추가
        // 실제 구현은 컨텍스트 소스에 따라 다름
        return arguments;
    }
    
    private void handleExecutionError(Exception e) {
        // 오류 처리 및 복구 시도
        stats.recordError(e.getClass().getSimpleName());
        
        // 특정 오류에 대한 복구 로직
        if (e instanceof java.net.SocketTimeoutException) {
            log.warn("네트워크 타임아웃 - 재시도 가능: {}", getToolName());
        }
    }
    
    /**
     * 실행 통계 내부 클래스
     */
    public static class ExecutionStats {
        private long totalExecutions = 0;
        private long successfulExecutions = 0;
        private long totalExecutionTime = 0;
        private long lastExecutionTime = 0;
        private final Map<String, Integer> errorCounts = new ConcurrentHashMap<>();
        
        public synchronized void record(long executionTime, boolean success) {
            totalExecutions++;
            totalExecutionTime += executionTime;
            lastExecutionTime = System.currentTimeMillis();
            
            if (success) {
                successfulExecutions++;
            }
        }
        
        public synchronized void recordError(String errorType) {
            errorCounts.merge(errorType, 1, Integer::sum);
        }
        
        public double getSuccessRate() {
            return totalExecutions > 0 ? 
                (double) successfulExecutions / totalExecutions : 0.0;
        }
        
        public double getAverageExecutionTime() {
            return totalExecutions > 0 ? 
                (double) totalExecutionTime / totalExecutions : 0.0;
        }
        
        public long getTotalExecutions() { return totalExecutions; }
        public long getSuccessfulExecutions() { return successfulExecutions; }
        public long getLastExecutionTime() { return lastExecutionTime; }
        public Map<String, Integer> getErrorCounts() { return new ConcurrentHashMap<>(errorCounts); }
    }
    
}