package io.contexa.contexacore.soar.tool;

import io.contexa.contexacore.domain.ApprovalRequest;
import io.contexa.contexacore.soar.approval.ApprovalService;
import io.contexa.contexacore.soar.approval.UnifiedApprovalService;
import lombok.extern.slf4j.Slf4j;
import org.springframework.ai.tool.ToolCallback;
import org.springframework.ai.tool.definition.ToolDefinition;
import org.springframework.ai.tool.metadata.ToolMetadata;

import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.CompletableFuture;

/**
 * 승인 기능이 통합된 ToolCallback
 * Spring AI 1.0.0의 실제 ToolCallback 인터페이스를 완전히 활용
 */
@Slf4j
public class ApprovalToolCallback implements ToolCallback {
    
    private final ToolCallback originalCallback;
    private final ApprovalService approvalService;
    private final UnifiedApprovalService unifiedApprovalService;
    private final String toolName;
    private final boolean approvalRequired;
    private final ToolDefinition toolDefinition;
    private final ToolMetadata toolMetadata;
    
    public ApprovalToolCallback(
            ToolCallback originalCallback,
            ApprovalService approvalService,
            UnifiedApprovalService unifiedApprovalService,
            String toolName,
            boolean approvalRequired,
            ToolDefinition toolDefinition,
            ToolMetadata toolMetadata) {
        this.originalCallback = originalCallback;
        this.approvalService = approvalService;
        this.unifiedApprovalService = unifiedApprovalService;
        this.toolName = toolName;
        this.approvalRequired = approvalRequired;
        this.toolDefinition = toolDefinition;
        this.toolMetadata = toolMetadata;
    }
    
    @Override
    public ToolDefinition getToolDefinition() {
        return toolDefinition;
    }
    
    @Override
    public ToolMetadata getToolMetadata() {
        return toolMetadata;
    }
    
    @Override
    public String call(String toolInput) {
        log.info("SOAR 도구 실행 요청: {} (승인 필요: {})", toolName, approvalRequired);
        
        if (!approvalRequired) {
            log.info("승인 불필요 - 직접 실행: {}", toolName);
            return originalCallback.call(toolInput);
        }
        
        // 비동기 실행 후 동기적으로 대기 (Spring AI 인터페이스 제약)
        try {
            return callAsync(toolInput).get();
        } catch (Exception e) {
            log.error("승인 프로세스 중 오류 발생: {}", toolName, e);
            throw new RuntimeException("Tool approval failed: " + e.getMessage(), e);
        }
    }
    
    /**
     * 비동기 도구 실행 (폴링 없음)
     */
    public CompletableFuture<String> callAsync(String toolInput) {
        log.info("⏸️ 사용자 승인 요청 (비동기): {}", toolName);
        
        // 파라미터 파싱
        Map<String, Object> parameters = parseToolInput(toolInput);
        
        // ApprovalRequest 생성
        io.contexa.contexacore.domain.ApprovalRequest request = 
            io.contexa.contexacore.domain.ApprovalRequest.builder()
                .requestId("tool-" + System.currentTimeMillis())
                .toolName(toolName)
                .actionDescription("Execute tool: " + toolName)
                .parameters(parameters)
                .incidentId("tool-execution")
                .organizationId("default-org")
                .riskLevel(determineRiskLevelEnum(determineRiskLevel(toolName)))
                .requestedBy("ai-model")
                .build();
        
        // UnifiedApprovalService를 통한 비동기 승인 요청 (폴링 없음)
        return unifiedApprovalService.requestApproval(request)
            .thenApply(approved -> {
                if (approved) {
                    log.info("승인 완료 - 도구 실행: {}", toolName);
                    return originalCallback.call(toolInput);
                } else {
                    log.warn("사용자가 도구 실행을 거부: {}", toolName);
                    return createRejectionResponse(toolName, toolInput);
                }
            })
            .exceptionally(throwable -> {
                log.error("승인 프로세스 실패: {}", toolName, throwable);
                return createErrorResponse(toolName, throwable.getMessage());
            });
    }
    
    /**
     * 위험도 문자열을 Enum으로 변환
     */
    private ApprovalRequest.RiskLevel determineRiskLevelEnum(String riskLevel) {
        return switch (riskLevel) {
            case "HIGH" -> io.contexa.contexacore.domain.ApprovalRequest.RiskLevel.HIGH;
            case "MEDIUM" -> io.contexa.contexacore.domain.ApprovalRequest.RiskLevel.MEDIUM;
            case "LOW" -> io.contexa.contexacore.domain.ApprovalRequest.RiskLevel.LOW;
            default -> io.contexa.contexacore.domain.ApprovalRequest.RiskLevel.INFO;
        };
    }
    
    /**
     * 도구 위험도 판단
     */
    private String determineRiskLevel(String toolName) {
        if (toolName.contains("network_isolation") || 
            toolName.contains("block") || 
            toolName.contains("kill") ||
            toolName.contains("quarantine")) {
            return "HIGH";
        }
        
        if (toolName.contains("scan") || 
            toolName.contains("analysis")) {
            return "MEDIUM";
        }
        
        return "LOW";
    }
    
    /**
     * 거부 응답 생성
     */
    private String createRejectionResponse(String toolName, String toolInput) {
        return String.format(
            "{\n" +
            "  \"success\": false,\n" +
            "  \"message\": \"Tool execution was denied by user\",\n" +
            "  \"toolName\": \"%s\",\n" +
            "  \"reason\": \"USER_DENIED\",\n" +
            "  \"timestamp\": \"%s\"\n" +
            "}",
            toolName,
            java.time.Instant.now()
        );
    }
    
    /**
     * 오류 응답 생성
     */
    private String createErrorResponse(String toolName, String errorMessage) {
        return String.format(
            "{\n" +
            "  \"success\": false,\n" +
            "  \"message\": \"Tool execution failed: %s\",\n" +
            "  \"toolName\": \"%s\",\n" +
            "  \"reason\": \"ERROR\",\n" +
            "  \"timestamp\": \"%s\"\n" +
            "}",
            errorMessage != null ? errorMessage : "Unknown error",
            toolName,
            java.time.Instant.now()
        );
    }
    
    /**
     * 도구 입력을 파싱합니다.
     */
    private Map<String, Object> parseToolInput(String toolInput) {
        if (toolInput == null || toolInput.isEmpty()) {
            return new HashMap<>();
        }
        
        try {
            // JSON 문자열을 Map으로 파싱
            com.fasterxml.jackson.databind.ObjectMapper mapper = new com.fasterxml.jackson.databind.ObjectMapper();
            Map<String, Object> parsed = mapper.readValue(toolInput, new com.fasterxml.jackson.core.type.TypeReference<Map<String, Object>>() {});
            log.debug("도구 입력 파싱 성공: {}", parsed);
            return parsed;
        } catch (Exception e) {
            // Spring AI가 자동으로 처리하도록 빈 Map 반환
            // "raw"로 감싸지 않음 - 이것이 Spring AI 자동 바인딩을 방해함
            log.error("도구 입력 파싱 실패 - 빈 Map 반환: toolInput={}", toolInput, e);
            return new HashMap<>();
        }
    }
}