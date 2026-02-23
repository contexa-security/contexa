package io.contexa.contexacoreenterprise.soar.service;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.contexa.contexacommon.domain.DiagnosisType;
import io.contexa.contexacommon.domain.TemplateType;
import io.contexa.contexacore.domain.SoarContext;
import io.contexa.contexacore.domain.SoarRequest;
import io.contexa.contexacore.domain.SoarResponse;
import io.contexa.contexacore.std.operations.AICoreOperations;
import java.time.LocalDateTime;

import io.contexa.contexacoreenterprise.soar.manager.SoarInteractionManager;
import io.contexa.contexacoreenterprise.mcp.tool.resolution.ChainedToolResolver;
import lombok.Builder;
import lombok.Getter;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import reactor.core.publisher.Mono;

import java.time.Instant;
import java.util.*;

@Slf4j
@RequiredArgsConstructor
public class SoarToolCallingService {

    private final AICoreOperations<SoarContext> aiNativeProcessor;
    private final SoarInteractionManager interactionManager;
    private final ChainedToolResolver toolResolver;
    private final ObjectMapper objectMapper;

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
                        finalResponse = objectMapper.writeValueAsString(response);
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

}