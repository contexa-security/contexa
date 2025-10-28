package io.contexa.contexacore.soar.service;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;
import io.contexa.contexacore.domain.SoarContext;
import io.contexa.contexacore.domain.SoarRequest;
import io.contexa.contexacore.domain.SoarResponse;
import io.contexa.contexacore.std.operations.AICoreOperations;
import io.contexa.contexacommon.enums.DiagnosisType;
import io.contexa.contexacore.soar.approval.UnifiedApprovalService;

import java.time.LocalDateTime;
import java.util.concurrent.CompletableFuture;
import io.contexa.contexacore.soar.manager.SoarInteractionManager;
import io.contexa.contexacore.soar.tool.model.SoarToolCall;
import io.contexa.contexacore.mcp.tool.resolution.ChainedToolResolver;
import lombok.Builder;
import lombok.Getter;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.ai.chat.model.ChatResponse;
import org.springframework.ai.tool.ToolCallback;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Mono;

import java.time.Instant;
import java.util.*;

/**
 * SOAR Tool Calling Service V2
 * Spring AI 공식 tool 패키지를 활용한 Human-in-the-Loop 구현
 * 
 * 핵심 기능:
 * - Spring AI의 ToolCallingChatOptions와 ToolCallingManager 활용
 * - internalToolExecutionEnabled(false)로 외부 제어
 * - 고위험 도구에 대한 승인 프로세스
 */
@Slf4j
@Service
@RequiredArgsConstructor
public class SoarToolCallingService {
    
    private final AICoreOperations<SoarContext> aiNativeProcessor;
    private final SoarInteractionManager interactionManager;
    private final ChainedToolResolver toolResolver;
    private final UnifiedApprovalService unifiedApprovalService;

    /**
     * Human-in-the-Loop가 적용된 SOAR Tool 실행
     * AI 진단 프로세스를 통한 통합 실행
     */
    public Mono<SoarExecutionResult> executeWithApproval(
            String userPrompt,
            String incidentId,
            String organizationId,
            SoarContext soarContext) {
        
        log.info("SOAR Tool 실행 시작 - AI 진단 프로세스 통합");
        log.info("인시던트: {}, 조직: {}", incidentId, organizationId);
        
        String conversationId = UUID.randomUUID().toString();
        Instant startTime = Instant.now();
        
        return Mono.fromCallable(() -> {
            // 1. SoarContext 준비 및 세션 생성
            if (soarContext.getSessionId() == null) {
                String sessionId = interactionManager.createSession(soarContext);
                soarContext.setSessionId(sessionId);
            }
            
            // 도구 실행 플래그 설정
            soarContext.setRequiresToolExecution(true);
            soarContext.setOriginalQuery(userPrompt);
            soarContext.setIncidentId(incidentId);
            soarContext.setOrganizationId(organizationId);
            
            SoarRequest soarRequest = new SoarRequest(soarContext, "soarAnalysis", organizationId);
            soarRequest.setQuery(soarContext.getOriginalQuery());
            soarRequest.setSessionId(soarContext.getSessionId());
            soarRequest.setIncidentId(soarContext.getIncidentId());
            soarRequest.setOrganizationId(soarContext.getOrganizationId());
            soarRequest.setUserId(soarContext.getUserId());
            soarRequest.setThreatLevel(soarContext.getThreatLevel());
            soarRequest.setQueryIntent(soarContext.getQueryIntent());
            soarRequest.setExtractedEntities(soarContext.getExtractedEntities());
            soarRequest.setConversationHistory(soarContext.getConversationHistory());
            soarRequest.setApprovedTools(soarContext.getApprovedTools());
            soarRequest.setRequiresApproval(soarContext.isRequiresApproval());
            soarRequest.setEmergencyMode(soarContext.isEmergencyMode());
            soarRequest.setTimestamp(LocalDateTime.now());
            soarRequest.withParameter("query", userPrompt);
            soarRequest.withParameter("sessionId", soarContext.getSessionId());
            soarRequest.withParameter("incidentId", incidentId);
            soarRequest.withDiagnosisType(DiagnosisType.SOAR);

            // 추가 메타데이터
            Map<String, Object> metadata = new HashMap<>();
            metadata.put("sessionState", soarContext.getSessionState());
            metadata.put("approvalRequests", soarContext.getApprovalRequests());
            metadata.put("lastActivity", soarContext.getLastActivity());
            soarRequest.setMetadata(metadata);


            return soarRequest;
        })
        .flatMap(aiRequest -> {
            // 4. PipelineOrchestrator를 통한 실행 (AI 진단 프로세스)
            log.info("PipelineOrchestrator 실행 시작");
            return aiNativeProcessor.process(aiRequest, SoarResponse.class
            );
        })
        .map(response -> {
            // 5. 실행 결과 변환
            long duration = Instant.now().toEpochMilli() - startTime.toEpochMilli();
            
            // 실행된 도구 목록 수집
            List<String> executedTools = new ArrayList<>();
            if (response.getExecutedTools() != null) {
                executedTools.addAll(response.getExecutedTools());
            }
            
            // 결과 생성 - 전체 SoarResponse를 JSON으로 변환
            String finalResponse = "";
            try {
                // SoarResponse 전체를 JSON으로 변환하여 완전한 정보 전달
                ObjectMapper mapper = new ObjectMapper();
                mapper.registerModule(new JavaTimeModule());
                finalResponse = mapper.writeValueAsString(response);
                log.info("SoarResponse를 JSON으로 변환 성공: {} bytes", finalResponse.length());
            } catch (Exception e) {
                log.warn("SoarResponse JSON 변환 실패, analysisResult만 사용", e);
                finalResponse = response.getAnalysisResult() != null ? response.getAnalysisResult() : "";
            }
            
            return SoarExecutionResult.builder()
                .conversationId(conversationId)
                .incidentId(incidentId)
                .organizationId(organizationId)
                .finalResponse(finalResponse)
                .executedTools(executedTools)
                .completedCount(executedTools.size())
                .failedCount(0)
                .iterations(1)
                .durationMs(duration)
                .success(true)
                .build();
        })
        .onErrorResume(error -> {
            log.error("💥 SOAR 실행 중 오류 발생", error);
            
            return Mono.just(SoarExecutionResult.builder()
                .conversationId(conversationId)
                .incidentId(incidentId)
                .organizationId(organizationId)
                .error(error instanceof Throwable ? ((Throwable) error).getMessage() : error.toString())
                .success(false)
                .build());
        });
    }
    
    /**
     * ChatResponse에 도구 호출이 있는지 확인
     * 실제 Spring AI 구현에 맞게 조정 필요
     */
    private boolean hasToolCalls(ChatResponse chatResponse) {
        // ChatResponse의 실제 구조에 따라 구현
        // 예: content에 function_call이나 tool_use 패턴 확인
        String content = chatResponse.getResult().getOutput().getText();
        return content != null && 
               (content.contains("function_call") || 
                content.contains("tool_use") ||
                content.contains("<tool>"));
    }
    
    /**
     * ChatResponse에서 도구 호출 추출
     */
    private List<SoarToolCall> extractToolCalls(ChatResponse chatResponse) {
        List<SoarToolCall> toolCalls = new ArrayList<>();
        
        // 실제 구현은 AI 모델의 응답 형식에 따라 조정
        // JSON 파싱이나 특정 패턴 매칭 필요
        String content = chatResponse.getResult().getOutput().getText();
        
        // 간단한 예시 - 실제로는 JSON 파싱 필요
        if (content.contains("scan_network")) {
            toolCalls.add(SoarToolCall.builder()
                .name("scan_network")
                .arguments("{\"target\": \"192.168.1.0/24\"}")
                .type("function")
                .build());
        }
        
        return toolCalls;
    }
    
    /**
     * 도구 위험도 평가
     */
    private String assessRiskLevel(String toolName) {
        // 도구 이름 기반 위험도 평가
        if (toolName.contains("isolation") || 
            toolName.contains("block") || 
            toolName.contains("kill") ||
            toolName.contains("quarantine")) {
            return "HIGH";
        }
        
        if (toolName.contains("shutdown") || 
            toolName.contains("terminate") ||
            toolName.contains("destroy")) {
            return "CRITICAL";
        }
        
        if (toolName.contains("scan") || 
            toolName.contains("analyze") ||
            toolName.contains("read")) {
            return "LOW";
        }
        
        return "MEDIUM";
    }
    
    /**
     * 승인 필요 여부 판단
     */
    private boolean isApprovalRequired(String riskLevel) {
        return "HIGH".equals(riskLevel) || "CRITICAL".equals(riskLevel);
    }
    
    /**
     * 도구 실행 승인 요청 (비동기 - 폴링 없음)
     */
    private CompletableFuture<Boolean> requestApprovalAsync(
            SoarToolCall toolCall,
            SoarContext soarContext,
            String incidentId,
            String approvalId) {
        
        try {
            // 파라미터 파싱
            Map<String, Object> parameters = parseToolArguments(toolCall.getArguments());
            
            // ApprovalRequest 객체 생성
            io.contexa.contexacore.domain.ApprovalRequest request = 
                io.contexa.contexacore.domain.ApprovalRequest.builder()
                    .requestId(approvalId)
                    .toolName(toolCall.getName())
                    .actionDescription("Execute tool: " + toolCall.getName())
                    .parameters(parameters)
                    .incidentId(incidentId)
                    .organizationId(soarContext.getOrganizationId())
                    .riskLevel(determineRiskLevelEnum(toolCall.getRiskLevel()))
                    .requestedBy("system")
                    .build();
            
            // UnifiedApprovalService를 통한 비동기 승인 요청
            return unifiedApprovalService.requestApproval(request)
                .exceptionally(throwable -> {
                    log.error("승인 요청 실패: {}", toolCall.getName(), throwable);
                    return false;
                });
            
        } catch (Exception e) {
            log.error("승인 요청 생성 실패: {}", toolCall.getName(), e);
            return CompletableFuture.completedFuture(false);
        }
    }
    
    /**
     * 위험도 문자열을 Enum으로 변환
     */
    private io.contexa.contexacore.domain.ApprovalRequest.RiskLevel determineRiskLevelEnum(String riskLevel) {
        return switch (riskLevel) {
            case "CRITICAL" -> io.contexa.contexacore.domain.ApprovalRequest.RiskLevel.CRITICAL;
            case "HIGH" -> io.contexa.contexacore.domain.ApprovalRequest.RiskLevel.HIGH;
            case "MEDIUM" -> io.contexa.contexacore.domain.ApprovalRequest.RiskLevel.MEDIUM;
            case "LOW" -> io.contexa.contexacore.domain.ApprovalRequest.RiskLevel.LOW;
            default -> io.contexa.contexacore.domain.ApprovalRequest.RiskLevel.INFO;
        };
    }
    
    /**
     * 시스템 프롬프트 생성
     */
    private String buildSystemPrompt(SoarContext soarContext) {
        return String.format("""
            You are a Security Orchestration, Automation and Response (SOAR) assistant.
            You help security analysts investigate and respond to security incidents.
            
            Current Context:
            - Incident ID: %s
            - Threat Type: %s
            - Severity: %s
            - Organization: %s
            
            Guidelines:
            - Use available security tools to analyze and respond to threats
            - Always prioritize safety and minimize false positives
            - Require approval for high-risk actions
            - Provide clear explanations for your recommendations
            """,
            soarContext.getIncidentId(),
            soarContext.getThreatType(),
            soarContext.getSeverity(),
            soarContext.getOrganizationId()
        );
    }
    
    /**
     * 사용자 프롬프트 향상
     */
    private String enhanceUserPrompt(String userPrompt, String incidentId) {
        return String.format("[Incident: %s] %s", incidentId, userPrompt);
    }
    
    /**
     * SOAR 도구 콜백 목록 조회
     */
    private List<ToolCallback> getSoarToolCallbacks() {
        return toolResolver.getRegisteredToolNames()
            .stream()
            .map(toolResolver::resolve)
            .filter(Objects::nonNull)
            .toList();
    }
    
    /**
     * SOAR 실행 결과
     */
    @Builder
    @Getter
    public static class SoarExecutionResult {
        private final String conversationId;
        private final String incidentId;
        private final String organizationId;
        private final String finalResponse;
        private final List<String> executedTools;
        private final int completedCount;
        private final int failedCount;
        private final int iterations;
        private final long durationMs;
        private final boolean success;
        private final String error;
        
        public Map<String, Object> toMap() {
            return Map.of(
                "conversationId", conversationId != null ? conversationId : "",
                "incidentId", incidentId != null ? incidentId : "",
                "organizationId", organizationId != null ? organizationId : "",
                "finalResponse", finalResponse != null ? finalResponse : "",
                "executedTools", executedTools != null ? executedTools : List.of(),
                "statistics", Map.of(
                    "completed", completedCount,
                    "failed", failedCount,
                    "iterations", iterations,
                    "durationMs", durationMs
                ),
                "success", success,
                "error", error != null ? error : ""
            );
        }
    }
    
    /**
     * 도구 인수를 파싱합니다.
     */
    private Map<String, Object> parseToolArguments(String arguments) {
        if (arguments == null || arguments.isEmpty()) {
            return new HashMap<>();
        }
        
        try {
            // JSON 문자열을 Map으로 파싱
            ObjectMapper mapper = new ObjectMapper();
            Map<String, Object> parsed = mapper.readValue(arguments, new com.fasterxml.jackson.core.type.TypeReference<Map<String, Object>>() {});
            
            // 파싱 성공 시 결과 반환
            log.debug("도구 인수 파싱 성공: {}", parsed);
            return parsed;
            
        } catch (Exception e) {
            // Spring AI가 자동으로 처리하도록 빈 Map 반환
            // "raw"로 감싸지 않음 - 이것이 Spring AI 자동 바인딩을 방해함
            log.error("도구 인수 파싱 실패 - 빈 Map 반환: arguments={}", arguments, e);
            return new HashMap<>();
        }
    }
}