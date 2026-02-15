package io.contexa.contexacoreenterprise.soar.controller;

import io.contexa.contexacore.soar.approval.ApprovalService;
import io.contexa.contexacoreenterprise.soar.service.SoarToolExecutionService;
import io.contexa.contexacoreenterprise.soar.tool.observation.SoarToolObservationContext;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.http.ResponseEntity;
import org.springframework.messaging.simp.SimpMessagingTemplate;
import org.springframework.security.access.prepost.PreAuthorize;
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
                log.error("SOAR tool execution failed", error);
                Map<String, Object> errorResponse = Map.of(
                    "success", false,
                    "incidentId", incidentId,
                    "error", error.getMessage(),
                    "timestamp", java.time.Instant.now()
                );
                return Mono.just(ResponseEntity.internalServerError().body(errorResponse));
            });
    }

    @PreAuthorize("isAuthenticated()")
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
            log.error("Approval processing failed: {}", approvalId, e);
            
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
            log.error("Failed to retrieve pending approvals", e);
            
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
            log.error("Failed to retrieve registered tools", e);
            
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
            log.error("Failed to retrieve tool execution status: {}", incidentId, e);
            
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
            log.error("Statistics query error", e);
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
            log.error("Tool metrics query error: {}", toolName, e);
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
            log.error("SOAR system health check failed", e);
            return ResponseEntity.status(503)
                .body(Map.of(
                    "status", "DOWN",
                    "error", e.getMessage(),
                    "timestamp", java.time.Instant.now()
                ));
        }
    }
}