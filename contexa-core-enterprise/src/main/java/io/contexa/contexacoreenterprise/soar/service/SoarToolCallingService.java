package io.contexa.contexacoreenterprise.soar.service;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;
import io.contexa.contexacommon.domain.DiagnosisType;
import io.contexa.contexacommon.domain.TemplateType;
import io.contexa.contexacore.domain.SoarContext;
import io.contexa.contexacore.domain.SoarRequest;
import io.contexa.contexacore.domain.SoarResponse;
import io.contexa.contexacore.std.operations.AICoreOperations;
import io.contexa.contexacoreenterprise.soar.approval.UnifiedApprovalService;

import java.time.LocalDateTime;
import java.util.concurrent.CompletableFuture;
import io.contexa.contexacoreenterprise.soar.manager.SoarInteractionManager;
import io.contexa.contexacoreenterprise.soar.tool.model.SoarToolCall;
import io.contexa.contexacoreenterprise.mcp.tool.resolution.ChainedToolResolver;
import lombok.Builder;
import lombok.Getter;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.ai.chat.model.ChatResponse;
import org.springframework.ai.tool.ToolCallback;
import reactor.core.publisher.Mono;

import java.time.Instant;
import java.util.*;

@Slf4j
@RequiredArgsConstructor
public class SoarToolCallingService {
    
    private final AICoreOperations<SoarContext> aiNativeProcessor;
    private final SoarInteractionManager interactionManager;
    private final ChainedToolResolver toolResolver;
    private final UnifiedApprovalService unifiedApprovalService;

    public Mono<SoarExecutionResult> executeWithApproval(
            String userPrompt,
            String incidentId,
            String organizationId,
            SoarContext soarContext) {

        String conversationId = UUID.randomUUID().toString();
        Instant startTime = Instant.now();
        
        return Mono.fromCallable(() -> {
            
            if (soarContext.getSessionId() == null) {
                String sessionId = interactionManager.createSession(soarContext);
                soarContext.setSessionId(sessionId);
            }

            soarContext.setRequiresToolExecution(true);
            soarContext.setOriginalQuery(userPrompt);
            soarContext.setIncidentId(incidentId);
            soarContext.setOrganizationId(organizationId);
            
            SoarRequest soarRequest = new SoarRequest(soarContext, new TemplateType("Soar"), new DiagnosisType("Soar"));
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

            Map<String, Object> metadata = new HashMap<>();
            metadata.put("sessionState", soarContext.getSessionState());
            metadata.put("approvalRequests", soarContext.getApprovalRequests());
            metadata.put("lastActivity", soarContext.getLastActivity());
            soarRequest.setMetadata(metadata);

            return soarRequest;
        })
        .flatMap(aiRequest -> {
            
                        return aiNativeProcessor.process(aiRequest, SoarResponse.class
            );
        })
        .map(response -> {
            
            long duration = Instant.now().toEpochMilli() - startTime.toEpochMilli();

            List<String> executedTools = new ArrayList<>();
            if (response.getExecutedTools() != null) {
                executedTools.addAll(response.getExecutedTools());
            }

            String finalResponse = "";
            try {
                
                ObjectMapper mapper = new ObjectMapper();
                mapper.registerModule(new JavaTimeModule());
                finalResponse = mapper.writeValueAsString(response);
                            } catch (Exception e) {
                log.error("Failed to convert SoarResponse to JSON, using analysisResult only", e);
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
            log.error("Error occurred during SOAR execution", error);
            
            return Mono.just(SoarExecutionResult.builder()
                .conversationId(conversationId)
                .incidentId(incidentId)
                .organizationId(organizationId)
                .error(error instanceof Throwable ? ((Throwable) error).getMessage() : error.toString())
                .success(false)
                .build());
        });
    }

    private boolean hasToolCalls(ChatResponse chatResponse) {

        String content = chatResponse.getResult().getOutput().getText();
        return content != null && 
               (content.contains("function_call") || 
                content.contains("tool_use") ||
                content.contains("<tool>"));
    }

    private List<SoarToolCall> extractToolCalls(ChatResponse chatResponse) {
        List<SoarToolCall> toolCalls = new ArrayList<>();

        String content = chatResponse.getResult().getOutput().getText();

        if (content.contains("scan_network")) {
            toolCalls.add(SoarToolCall.builder()
                .name("scan_network")
                .arguments("{\"target\": \"192.168.1.0/24\"}")
                .type("function")
                .build());
        }
        
        return toolCalls;
    }

    private String assessRiskLevel(String toolName) {
        
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

    private boolean isApprovalRequired(String riskLevel) {
        return "HIGH".equals(riskLevel) || "CRITICAL".equals(riskLevel);
    }

    private CompletableFuture<Boolean> requestApprovalAsync(
            SoarToolCall toolCall,
            SoarContext soarContext,
            String incidentId,
            String approvalId) {
        
        try {
            
            Map<String, Object> parameters = parseToolArguments(toolCall.getArguments());

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

            return unifiedApprovalService.requestApproval(request)
                .exceptionally(throwable -> {
                    log.error("Approval request failed: {}", toolCall.getName(), throwable);
                    return false;
                });
            
        } catch (Exception e) {
            log.error("Failed to create approval request: {}", toolCall.getName(), e);
            return CompletableFuture.completedFuture(false);
        }
    }

    private io.contexa.contexacore.domain.ApprovalRequest.RiskLevel determineRiskLevelEnum(String riskLevel) {
        return switch (riskLevel) {
            case "CRITICAL" -> io.contexa.contexacore.domain.ApprovalRequest.RiskLevel.CRITICAL;
            case "HIGH" -> io.contexa.contexacore.domain.ApprovalRequest.RiskLevel.HIGH;
            case "MEDIUM" -> io.contexa.contexacore.domain.ApprovalRequest.RiskLevel.MEDIUM;
            case "LOW" -> io.contexa.contexacore.domain.ApprovalRequest.RiskLevel.LOW;
            default -> io.contexa.contexacore.domain.ApprovalRequest.RiskLevel.INFO;
        };
    }

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

    private String enhanceUserPrompt(String userPrompt, String incidentId) {
        return String.format("[Incident: %s] %s", incidentId, userPrompt);
    }

    private List<ToolCallback> getSoarToolCallbacks() {
        return toolResolver.getRegisteredToolNames()
            .stream()
            .map(toolResolver::resolve)
            .filter(Objects::nonNull)
            .toList();
    }

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

    private Map<String, Object> parseToolArguments(String arguments) {
        if (arguments == null || arguments.isEmpty()) {
            return new HashMap<>();
        }
        
        try {
            
            ObjectMapper mapper = new ObjectMapper();
            Map<String, Object> parsed = mapper.readValue(arguments, new com.fasterxml.jackson.core.type.TypeReference<Map<String, Object>>() {});

                        return parsed;
            
        } catch (Exception e) {

            log.error("Failed to parse tool arguments - returning empty Map: arguments={}", arguments, e);
            return new HashMap<>();
        }
    }
}