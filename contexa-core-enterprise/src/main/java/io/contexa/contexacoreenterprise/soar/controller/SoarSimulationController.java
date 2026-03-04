package io.contexa.contexacoreenterprise.soar.controller;

import io.contexa.contexacoreenterprise.soar.domain.*;
import io.contexa.contexacoreenterprise.soar.service.SoarSimulationService;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.http.ResponseEntity;
import org.springframework.messaging.simp.SimpMessagingTemplate;
import org.springframework.web.bind.annotation.*;
import reactor.core.publisher.Mono;

import java.time.LocalDateTime;
import java.util.List;
import java.util.Map;

@Slf4j
@RequestMapping("/api/soar/simulation")
@RestController
public class SoarSimulationController {
    
    private final SoarSimulationService simulationService;
    private final SimpMessagingTemplate brokerTemplate;

    public SoarSimulationController(SoarSimulationService simulationService,
                                    @Qualifier("brokerMessagingTemplate") SimpMessagingTemplate brokerTemplate) {
        this.simulationService = simulationService;
        this.brokerTemplate = brokerTemplate;
    }

    @PostMapping("/start")
    public Mono<ResponseEntity<SimulationStartResponse>> startSimulation(@RequestBody SimulationStartRequest request) {
                
        return simulationService.startSimulation(request)
            .map(result -> {

                return ResponseEntity.ok(SimulationStartResponse.builder()
                    .sessionId(result.getSessionId())
                    .conversationId(result.getConversationId())
                    .status("COMPLETED")  
                    .message("SOAR analysis completed.")
                    .finalResponse(result.getFinalResponse())  
                    .pipelineStages(List.of(
                        "PREPROCESSING",
                        "CONTEXT_RETRIEVAL",
                        "PROMPT_GENERATION",
                        "LLM_EXECUTION",
                        "RESPONSE_PARSING",
                        "POSTPROCESSING"
                    ))
                    .timestamp(LocalDateTime.now())
                    .build());
            })
            .onErrorResume(error -> {
                log.error("SOAR simulation start failed", error);
                return Mono.just(ResponseEntity.internalServerError()
                    .body(SimulationStartResponse.builder()
                        .status("ERROR")
                        .message("Simulation start failed: " + error.getMessage())
                        .timestamp(LocalDateTime.now())
                        .build()));
            });
    }

    @PostMapping("/stop/{sessionId}")
    public ResponseEntity<Map<String, Object>> stopSimulation(@PathVariable String sessionId) {
        try {
            simulationService.stopSimulation(sessionId);
            return ResponseEntity.ok(Map.of(
                "sessionId", sessionId,
                "status", "CANCELLED",
                "message", "Simulation stopped",
                "timestamp", LocalDateTime.now()
            ));
        } catch (IllegalArgumentException e) {
            log.error("Session not found for stop: {}", sessionId);
            return ResponseEntity.notFound().build();
        } catch (Exception e) {
            log.error("Failed to stop simulation: {}", sessionId, e);
            return ResponseEntity.internalServerError()
                .body(Map.of("error", e.getMessage()));
        }
    }

    @GetMapping("/session/{sessionId}")
    public ResponseEntity<SessionStatusResponse> getSessionStatus(@PathVariable String sessionId) {
                
        return simulationService.getSessionStatus(sessionId)
            .map(status -> ResponseEntity.ok(SessionStatusResponse.builder()
                .sessionId(sessionId)
                .status(status.getStatus())
                .currentStage(status.getCurrentStage())
                .progress(status.getProgress())
                .executedTools(status.getExecutedTools())
                .pendingApprovals(status.getPendingApprovals())
                .mcpServersStatus(status.getMcpServersStatus())
                .timestamp(LocalDateTime.now())
                .build()))
            .orElse(ResponseEntity.notFound().build());
    }

    @PostMapping("/approve")
    public ResponseEntity<ApprovalResponse> approveToolExecution(@RequestBody ApprovalRequest request) {
                
        simulationService.handleApproval(
            request.getSessionId(),
            request.getApprovalId(),
            request.getToolName(),
            request.isApproved(),
            request.getReason()
        );

        notifyApprovalResult(request);
        
        return ResponseEntity.ok(ApprovalResponse.builder()
            .approvalId(request.getApprovalId())
            .status(request.isApproved() ? "APPROVED" : "REJECTED")
            .message("Approval processing completed")
            .timestamp(LocalDateTime.now())
            .build());
    }

    @GetMapping("/mcp-status")
    public ResponseEntity<McpStatusResponse> getMcpServerStatus() {
        Map<String, Boolean> mcpStatus = simulationService.getMcpServerStatus();
        
        return ResponseEntity.ok(McpStatusResponse.builder()
            .context7(mcpStatus.getOrDefault("context7", false))
            .sequential(mcpStatus.getOrDefault("sequential", false))
            .magic(mcpStatus.getOrDefault("magic", false))
            .playwright(mcpStatus.getOrDefault("playwright", false))
            .timestamp(LocalDateTime.now())
            .build());
    }

    private void notifyApprovalResult(ApprovalRequest request) {
        Map<String, Object> event = new java.util.HashMap<>();
        event.put("sessionId", request.getSessionId());
        event.put("approvalId", request.getApprovalId());
        event.put("toolName", request.getToolName());
        event.put("approved", request.isApproved());
        event.put("reason", request.getReason());
        event.put("timestamp", LocalDateTime.now());

        brokerTemplate.convertAndSend("/topic/soar/approvals", event);
    }
}