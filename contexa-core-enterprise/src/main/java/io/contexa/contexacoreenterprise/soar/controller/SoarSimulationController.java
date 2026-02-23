package io.contexa.contexacoreenterprise.soar.controller;

import io.contexa.contexacoreenterprise.soar.domain.*;
import io.contexa.contexacoreenterprise.soar.service.SoarSimulationService;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.http.ResponseEntity;
import org.springframework.messaging.handler.annotation.MessageMapping;
import org.springframework.messaging.handler.annotation.Payload;
import org.springframework.messaging.handler.annotation.SendTo;
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
                    .message("SOAR 분석이 완료되었습니다.")
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
                log.error("SOAR 시뮬레이션 시작 실패", error);
                return Mono.just(ResponseEntity.internalServerError()
                    .body(SimulationStartResponse.builder()
                        .status("ERROR")
                        .message("시뮬레이션 시작 실패: " + error.getMessage())
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
            .message("승인 처리 완료")
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

    @MessageMapping("/soar/pipeline/update")
    @SendTo("/topic/soar/pipeline")
    public PipelineUpdateMessage handlePipelineUpdate(@Payload PipelineUpdateMessage update) {
                return update;
    }

    @MessageMapping("/soar/tool/request")
    @SendTo("/topic/soar/tools")
    public ToolExecutionMessage handleToolRequest(@Payload ToolExecutionMessage request) {
                return request;
    }
    
    private void notifySimulationStart(String sessionId, SimulationStartRequest request) {
        SimulationEvent event = SimulationEvent.builder()
            .sessionId(sessionId)
            .eventType("SIMULATION_STARTED")
            .data(Map.of(
                "incidentId", request.getIncidentId(),
                "threatType", request.getThreatType(),
                "severity", request.getSeverity()
            ))
            .timestamp(LocalDateTime.now())
            .build();

        brokerTemplate.convertAndSend("/topic/soar/events", event);
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