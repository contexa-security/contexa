package io.contexa.contexaiam.aiam.web;

import io.contexa.contexaiam.aiam.service.SoarSimulationService;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
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

/**
 * SOAR 시뮬레이션 컨트롤러
 * 
 * AI + MCP + SOAR 통합 시뮬레이션을 위한 REST 및 WebSocket 엔드포인트 제공
 */
@Slf4j
@RestController
@RequestMapping("/api/soar/simulation")
public class SoarSimulationController {
    
    private final SoarSimulationService simulationService;
    private final SimpMessagingTemplate brokerTemplate;

    public SoarSimulationController(SoarSimulationService simulationService,
                                    @Qualifier("brokerMessagingTemplate") SimpMessagingTemplate brokerTemplate) {
        this.simulationService = simulationService;
        this.brokerTemplate = brokerTemplate;
    }

    /**
     * SOAR 시뮬레이션 시작
     * AI 진단 프로세스와 통합된 SOAR 워크플로우 실행
     */
    @PostMapping("/start")
    public Mono<ResponseEntity<SimulationStartResponse>> startSimulation(@RequestBody SimulationStartRequest request) {
        log.info("SOAR 시뮬레이션 시작 요청: incidentId={}, threatType={}", 
            request.getIncidentId(), request.getThreatType());
        
        return simulationService.startSimulation(request)
            .map(result -> {
                // notifySimulationStart 제거 - SoarSimulationService에서 처리
                
                return ResponseEntity.ok(SimulationStartResponse.builder()
                    .sessionId(result.getSessionId())
                    .conversationId(result.getConversationId())
                    .status("COMPLETED")  // STARTED가 아닌 COMPLETED로 변경
                    .message("SOAR 분석이 완료되었습니다.")
                    .finalResponse(result.getFinalResponse())  // finalResponse 추가
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
    
    /**
     * 세션 상태 조회
     */
    @GetMapping("/session/{sessionId}")
    public ResponseEntity<SessionStatusResponse> getSessionStatus(@PathVariable String sessionId) {
        log.debug("세션 상태 조회: sessionId={}", sessionId);
        
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
    
    /**
     * 도구 실행 승인
     */
    @PostMapping("/approve")
    public ResponseEntity<ApprovalResponse> approveToolExecution(@RequestBody ApprovalRequest request) {
        log.info("도구 실행 승인 요청: sessionId={}, toolName={}, approved={}",
            request.getSessionId(), request.getToolName(), request.isApproved());
        
        simulationService.handleApproval(
            request.getSessionId(),
            request.getApprovalId(),
            request.isApproved(),
            request.getReason()
        );
        
        // WebSocket으로 승인 결과 브로드캐스트
        notifyApprovalResult(request);
        
        return ResponseEntity.ok(ApprovalResponse.builder()
            .approvalId(request.getApprovalId())
            .status(request.isApproved() ? "APPROVED" : "REJECTED")
            .message("승인 처리 완료")
            .timestamp(LocalDateTime.now())
            .build());
    }
    
    /**
     * MCP 서버 상태 조회
     */
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
    
    // WebSocket 메시지 핸들러
    
    /**
     * 파이프라인 진행 상황 업데이트 수신
     */
    @MessageMapping("/soar/pipeline/update")
    @SendTo("/topic/soar/pipeline")
    public PipelineUpdateMessage handlePipelineUpdate(@Payload PipelineUpdateMessage update) {
        log.debug("파이프라인 업데이트: stage={}, progress={}", 
            update.getStage(), update.getProgress());
        return update;
    }
    
    /**
     * 도구 실행 요청 수신
     */
    @MessageMapping("/soar/tool/request")
    @SendTo("/topic/soar/tools")
    public ToolExecutionMessage handleToolRequest(@Payload ToolExecutionMessage request) {
        log.info("도구 실행 요청: toolName={}, requiresApproval={}", 
            request.getToolName(), request.isRequiresApproval());
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
        ApprovalEvent event = ApprovalEvent.builder()
            .sessionId(request.getSessionId())
            .approvalId(request.getApprovalId())
            .toolName(request.getToolName())
            .approved(request.isApproved())
            .reason(request.getReason())
            .timestamp(LocalDateTime.now())
            .build();

        brokerTemplate.convertAndSend("/topic/soar/approvals", event);
    }
    
    // Request/Response DTOs
    
    @Data
    @Builder
    @NoArgsConstructor
    @AllArgsConstructor
    public static class SimulationStartRequest {
        private String incidentId;
        private String threatType;
        private String description;
        private List<String> affectedAssets;
        private String detectedSource;
        private String severity;
        private String organizationId;
        private String userQuery; // 사용자의 자연어 질의
        private Map<String, Object> metadata;
    }
    
    @Data
    @Builder
    @NoArgsConstructor
    @AllArgsConstructor
    public static class SimulationStartResponse {
        private String sessionId;
        private String conversationId;
        private String status;
        private String message;
        private String finalResponse;  // 최종 응답 추가
        private List<String> pipelineStages;
        private LocalDateTime timestamp;
    }
    
    @Data
    @Builder
    @NoArgsConstructor
    @AllArgsConstructor
    public static class SessionStatusResponse {
        private String sessionId;
        private String status;
        private String currentStage;
        private int progress;
        private List<String> executedTools;
        private List<String> pendingApprovals;
        private Map<String, Boolean> mcpServersStatus;
        private LocalDateTime timestamp;
    }
    
    @Data
    @Builder
    @NoArgsConstructor
    @AllArgsConstructor
    public static class ApprovalRequest {
        private String sessionId;
        private String approvalId;
        private String toolName;
        private boolean approved;
        private String reason;
    }
    
    @Data
    @Builder
    @NoArgsConstructor
    @AllArgsConstructor
    public static class ApprovalResponse {
        private String approvalId;
        private String status;
        private String message;
        private LocalDateTime timestamp;
    }
    
    @Data
    @Builder
    @NoArgsConstructor
    @AllArgsConstructor
    public static class McpStatusResponse {
        private boolean context7;
        private boolean sequential;
        private boolean magic;
        private boolean playwright;
        private LocalDateTime timestamp;
    }
    
    @Data
    @Builder
    @NoArgsConstructor
    @AllArgsConstructor
    public static class PipelineUpdateMessage {
        private String sessionId;
        private String stage;
        private int progress;
        private String message;
        private LocalDateTime timestamp;
    }
    
    @Data
    @Builder
    @NoArgsConstructor
    @AllArgsConstructor
    public static class ToolExecutionMessage {
        private String sessionId;
        private String toolName;
        private String description;
        private Map<String, Object> parameters;
        private boolean requiresApproval;
        private String riskLevel;
        private LocalDateTime timestamp;
    }
    
    @Data
    @Builder
    @NoArgsConstructor
    @AllArgsConstructor
    public static class SimulationEvent {
        private String sessionId;
        private String eventType;
        private Map<String, Object> data;
        private LocalDateTime timestamp;
    }
    
    @Data
    @Builder
    @NoArgsConstructor
    @AllArgsConstructor
    public static class ApprovalEvent {
        private String sessionId;
        private String approvalId;
        private String toolName;
        private boolean approved;
        private String reason;
        private LocalDateTime timestamp;
    }
}