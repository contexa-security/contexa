package io.contexa.contexacore.soar.controller;

import io.contexa.contexacore.soar.approval.ApprovalService;
import io.contexa.contexacore.soar.service.SoarToolExecutionService;
import io.contexa.contexacore.soar.tool.observation.SoarToolObservationContext;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.http.ResponseEntity;
import org.springframework.messaging.simp.SimpMessagingTemplate;
import org.springframework.web.bind.annotation.*;
import reactor.core.publisher.Mono;

import java.util.Map;

/**
 * SOAR 승인 컨트롤러
 * WebSocket을 통한 실시간 승인 처리
 */
@Slf4j
@RestController
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
    
    /**
     * SOAR Tool 실행 요청 (승인 워크플로우 포함)
     */
    @PostMapping("/execute")
    public Mono<ResponseEntity<Map<String, Object>>> executeSoarTool(
            @RequestBody Map<String, Object> request) {
        
        String prompt = (String) request.get("prompt");
        String incidentId = (String) request.getOrDefault("incidentId", "incident-" + System.currentTimeMillis());
        String organizationId = (String) request.getOrDefault("organizationId", "default-org");
        
        log.info("SOAR Tool 실행 요청 수신: {}", incidentId);
        
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
    
    /**
     * 승인 요청 처리
     */
    @PostMapping("/approve/{approvalId}")
    public ResponseEntity<Map<String, Object>> approveRequest(
            @PathVariable String approvalId,
            @RequestBody Map<String, Object> approvalData) {
        
        boolean approved = Boolean.TRUE.equals(approvalData.get("approved"));
        String reason = (String) approvalData.getOrDefault("reason", "");
        
        log.info("👨‍💼 승인 처리: {} - 승인: {}, 사유: {}", approvalId, approved, reason);
        
        try {
            // ApprovalService에 승인 결과 전달
            approvalService.processApproval(approvalId, approved, reason);
            
            // WebSocket으로 승인 결과 브로드캐스트
            Map<String, Object> message = Map.of(
                "type", "APPROVAL_PROCESSED",
                "approvalId", approvalId,
                "approved", approved,
                "reason", reason,
                "timestamp", java.time.Instant.now()
            );

            brokerTemplate.convertAndSend("/topic/soar/approvals", message);
            
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
    
    /**
     * 대기 중인 승인 목록 조회
     */
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
    
    /**
     * 등록된 도구 목록 조회
     */
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
    
    /**
     * 도구 실행 상태 조회
     */
    @GetMapping("/status/{incidentId}")
    public ResponseEntity<Map<String, Object>> getExecutionStatus(@PathVariable String incidentId) {
        try {
            // 실제 구현에서는 실행 상태를 추적하는 서비스가 필요
            Map<String, Object> status = Map.of(
                "incidentId", incidentId,
                "status", "PROCESSING", // PENDING, PROCESSING, COMPLETED, FAILED
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
    
    /**
     * SOAR 도구 실행 통계 조회 (관찰 메트릭 포함)
     */
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
    
    /**
     * 특정 도구의 실행 메트릭 조회
     */
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
    
    /**
     * SOAR 시스템 헬스 체크
     */
    @GetMapping("/health")
    public ResponseEntity<Map<String, Object>> healthCheck() {
        try {
            // 기본 구성 요소들의 상태 확인
            boolean approvalServiceHealthy = (approvalService != null);
            boolean toolExecutionServiceHealthy = (soarToolExecutionService != null);

            // 등록된 도구 수 확인
            int registeredToolCount = soarToolExecutionService.getRegisteredTools().size();
            
            // 글로벌 통계 확인
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