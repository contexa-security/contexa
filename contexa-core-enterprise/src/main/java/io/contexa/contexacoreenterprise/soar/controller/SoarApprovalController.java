package io.contexa.contexacoreenterprise.soar.controller;

import io.contexa.contexacore.soar.approval.ApprovalService;
import io.contexa.contexacoreenterprise.soar.service.SoarToolExecutionService;
import io.contexa.contexacoreenterprise.soar.tool.observation.SoarToolObservationContext;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.http.ResponseEntity;
import org.springframework.messaging.simp.SimpMessagingTemplate;
import org.springframework.web.bind.annotation.*;
import reactor.core.publisher.Mono;

import java.util.Map;

@Slf4j
@ResponseBody
@RequestMapping("/api/soar/approval")
public class SoarApprovalController {
    
    private final ApprovalService approvalService;
    private final SoarToolExecutionService soarToolExecutionService;
    private final SimpMessagingTemplate brokerTemplate;

    public SoarApprovalController(
            ApprovalService approvalService,
            SoarToolExecutionService soarToolExecutionService,
            @Qualifier("brokerMessagingTemplate") SimpMessagingTemplate brokerTemplate) {
        this.approvalService = approvalService;
        this.soarToolExecutionService = soarToolExecutionService;
        this.brokerTemplate = brokerTemplate;
    }

    @PostMapping("/execute")
    public Mono<ResponseEntity<Map<String, Object>>> executeSoarTool(
            @RequestBody Map<String, Object> request) {
        
        String prompt = (String) request.get("prompt");
        String incidentId = (String) request.getOrDefault("incidentId", "incident-" + System.currentTimeMillis());
        String organizationId = (String) request.getOrDefault("organizationId", "default-org");

        return soarToolExecutionService.executeWithHumanApproval(prompt, incidentId, organizationId)
            .map(result -> {
                Map<String, Object> response = Map.of(
                    "success", true,
                    "incidentId", incidentId,
                    "result", result,
                    "timestamp", java.time.Instant.now()
                );
                return ResponseEntity.ok(response);
            })
            .onErrorResume(error -> {
                log.error("SOAR Tool 실행 실패", error);
                Map<String, Object> errorResponse = Map.of(
                    "success", false,
                    "incidentId", incidentId,
                    "error", error.getMessage(),
                    "timestamp", java.time.Instant.now()
                );
                return Mono.just(ResponseEntity.internalServerError().body(errorResponse));
            });
    }

    @PostMapping("/approve/{approvalId}")
    public ResponseEntity<Map<String, Object>> approveRequest(
            @PathVariable String approvalId,
            @RequestBody Map<String, Object> approvalData) {
        
        boolean approved = Boolean.TRUE.equals(approvalData.get("approved"));
        String reason = (String) approvalData.getOrDefault("reason", "");

        try {
            
            approvalService.processApproval(approvalId, approved, reason);

            Map<String, Object> message = Map.of(
                "type", "APPROVAL_PROCESSED",
                "approvalId", approvalId,
                "approved", approved,
                "reason", reason,
                "timestamp", java.time.Instant.now()
            );

            brokerTemplate.convertAndSend("/topic/soar/approvals", (Object) message);
            
            Map<String, Object> response = Map.of(
                "success", true,
                "approvalId", approvalId,
                "approved", approved
            );
            
            return ResponseEntity.ok(response);
            
        } catch (Exception e) {
            log.error("승인 처리 실패: {}", approvalId, e);
            
            Map<String, Object> errorResponse = Map.of(
                "success", false,
                "approvalId", approvalId,
                "error", e.getMessage()
            );
            
            return ResponseEntity.internalServerError().body(errorResponse);
        }
    }

    @GetMapping("/pending-list")
    public ResponseEntity<Map<String, Object>> getPendingApprovals() {
        try {
            var pendingApprovals = approvalService.getPendingApprovals();
            
            Map<String, Object> response = Map.of(
                "success", true,
                "pendingApprovals", pendingApprovals,
                "timestamp", java.time.Instant.now()
            );
            
            return ResponseEntity.ok(response);
            
        } catch (Exception e) {
            log.error("대기 중인 승인 목록 조회 실패", e);
            
            Map<String, Object> errorResponse = Map.of(
                "success", false,
                "error", e.getMessage(),
                "timestamp", java.time.Instant.now()
            );
            
            return ResponseEntity.internalServerError().body(errorResponse);
        }
    }

    @GetMapping("/tools")
    public ResponseEntity<Map<String, Object>> getRegisteredTools() {
        try {
            Map<String, Object> stats = soarToolExecutionService.getExecutionStatistics();
            java.util.Set<String> tools = soarToolExecutionService.getRegisteredTools();
            
            Map<String, Object> response = Map.of(
                "success", true,
                "tools", tools,
                "statistics", stats,
                "timestamp", java.time.Instant.now()
            );
            
            return ResponseEntity.ok(response);
            
        } catch (Exception e) {
            log.error("등록된 도구 목록 조회 실패", e);
            
            Map<String, Object> errorResponse = Map.of(
                "success", false,
                "error", e.getMessage(),
                "timestamp", java.time.Instant.now()
            );
            
            return ResponseEntity.internalServerError().body(errorResponse);
        }
    }

    @GetMapping("/status/{incidentId}")
    public ResponseEntity<Map<String, Object>> getExecutionStatus(@PathVariable String incidentId) {
        try {
            
            Map<String, Object> status = Map.of(
                "incidentId", incidentId,
                "status", "PROCESSING", 
                "lastUpdate", java.time.Instant.now()
            );
            
            Map<String, Object> response = Map.of(
                "success", true,
                "status", status,
                "timestamp", java.time.Instant.now()
            );
            
            return ResponseEntity.ok(response);
            
        } catch (Exception e) {
            log.error("도구 실행 상태 조회 실패: {}", incidentId, e);
            
            Map<String, Object> errorResponse = Map.of(
                "success", false,
                "incidentId", incidentId,
                "error", e.getMessage(),
                "timestamp", java.time.Instant.now()
            );
            
            return ResponseEntity.internalServerError().body(errorResponse);
        }
    }

    @GetMapping("/statistics")
    public ResponseEntity<Map<String, Object>> getExecutionStatistics() {
        try {
            Map<String, Object> globalStats = SoarToolObservationContext.getGlobalExecutionStatistics();
            
            Map<String, Object> response = Map.of(
                "success", true,
                "statistics", globalStats,
                "timestamp", java.time.Instant.now()
            );
            
            return ResponseEntity.ok(response);
            
        } catch (Exception e) {
            log.error("통계 조회 중 오류 발생", e);
            return ResponseEntity.internalServerError()
                .body(Map.of("success", false, "error", e.getMessage()));
        }
    }

    @GetMapping("/tools/{toolName}/metrics")
    public ResponseEntity<Map<String, Object>> getToolMetrics(@PathVariable String toolName) {
        try {
            SoarToolObservationContext.ToolExecutionMetrics metrics = 
                SoarToolObservationContext.getToolExecutionMetrics(toolName);
            
            if (metrics == null) {
                return ResponseEntity.notFound().build();
            }
            
            Map<String, Object> response = Map.of(
                "success", true,
                "toolName", toolName,
                "metrics", Map.of(
                    "executionCount", metrics.getExecutionCount(),
                    "averageExecutionTime", metrics.getAverageExecutionTimeMs(),
                    "lastExecutionTime", metrics.getLastExecutionTime()
                ),
                "timestamp", java.time.Instant.now()
            );
            
            return ResponseEntity.ok(response);
            
        } catch (Exception e) {
            log.error("도구 메트릭 조회 중 오류 발생: {}", toolName, e);
            return ResponseEntity.internalServerError()
                .body(Map.of("success", false, "error", e.getMessage()));
        }
    }

    @GetMapping("/health")
    public ResponseEntity<Map<String, Object>> healthCheck() {
        try {
            
            boolean approvalServiceHealthy = (approvalService != null);
            boolean toolExecutionServiceHealthy = (soarToolExecutionService != null);

            int registeredToolCount = soarToolExecutionService.getRegisteredTools().size();

            Map<String, Object> globalStats = SoarToolObservationContext.getGlobalExecutionStatistics();
            
            boolean overallHealthy = approvalServiceHealthy && toolExecutionServiceHealthy && registeredToolCount >= 0;
            
            Map<String, Object> healthStatus = Map.of(
                "status", overallHealthy ? "UP" : "DOWN",
                "components", Map.of(
                    "approvalService", approvalServiceHealthy ? "UP" : "DOWN",
                    "toolExecutionService", toolExecutionServiceHealthy ? "UP" : "DOWN"
                ),
                "metrics", Map.of(
                    "registeredToolCount", registeredToolCount,
                    "globalStats", globalStats
                ),
                "timestamp", java.time.Instant.now()
            );
            
            if (overallHealthy) {
                return ResponseEntity.ok(healthStatus);
            } else {
                return ResponseEntity.status(503).body(healthStatus);
            }
            
        } catch (Exception e) {
            log.error("SOAR 시스템 헬스 체크 실패", e);
            return ResponseEntity.status(503)
                .body(Map.of(
                    "status", "DOWN",
                    "error", e.getMessage(),
                    "timestamp", java.time.Instant.now()
                ));
        }
    }
}