package io.contexa.contexacore.soar.controller;

import io.contexa.contexacore.soar.approval.ToolApprovalService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.Map;

/**
 * Tool Approval Controller
 * 보안 도구 승인 워크플로우 REST API
 * 관리자가 고위험 도구 실행을 승인/거부
 */
@Slf4j
@RestController
@RequestMapping("/api/soar/approval")
@RequiredArgsConstructor
public class ToolApprovalController {
    
    private final ToolApprovalService approvalService;
    
    /**
     * 대기 중인 승인 요청 조회
     */
    @GetMapping("/pending")
    public ResponseEntity<List<ToolApprovalService.ApprovalRequest>> getPendingApprovals() {
        List<ToolApprovalService.ApprovalRequest> pending = approvalService.getPendingApprovals();
        log.info("대기 중인 승인 요청 조회: {} 건", pending.size());
        return ResponseEntity.ok(pending);
    }
    
    /**
     * 승인 이력 조회
     */
    @GetMapping("/history")
    public ResponseEntity<List<ToolApprovalService.ApprovalResult>> getApprovalHistory(
            @RequestParam(defaultValue = "50") int limit) {
        List<ToolApprovalService.ApprovalResult> history = approvalService.getApprovalHistory(limit);
        return ResponseEntity.ok(history);
    }
    
    /**
     * 도구 실행 승인
     */
    @PostMapping("/{approvalId}/approve")
    public ResponseEntity<Map<String, Object>> approve(
            @PathVariable String approvalId,
            @RequestBody ApprovalDecision decision) {
        
        log.info("승인 요청 처리: ID={}, By={}", approvalId, decision.decidedBy());
        
        boolean success = approvalService.approve(
            approvalId, 
            decision.decidedBy(), 
            decision.reason()
        );
        
        if (success) {
            return ResponseEntity.ok(Map.of(
                "success", true,
                "message", "Tool execution approved",
                "approvalId", approvalId
            ));
        } else {
            return ResponseEntity.badRequest().body(Map.of(
                "success", false,
                "message", "Failed to approve - request not found or already processed",
                "approvalId", approvalId
            ));
        }
    }
    
    /**
     * 도구 실행 거부
     */
    @PostMapping("/{approvalId}/reject")
    public ResponseEntity<Map<String, Object>> reject(
            @PathVariable String approvalId,
            @RequestBody ApprovalDecision decision) {
        
        log.warn("승인 거부 처리: ID={}, By={}, Reason={}", 
            approvalId, decision.decidedBy(), decision.reason());
        
        boolean success = approvalService.reject(
            approvalId, 
            decision.decidedBy(), 
            decision.reason()
        );
        
        if (success) {
            return ResponseEntity.ok(Map.of(
                "success", true,
                "message", "Tool execution rejected",
                "approvalId", approvalId
            ));
        } else {
            return ResponseEntity.badRequest().body(Map.of(
                "success", false,
                "message", "Failed to reject - request not found or already processed",
                "approvalId", approvalId
            ));
        }
    }
    
    /**
     * 승인/거부 결정 DTO
     */
    public record ApprovalDecision(
        String decidedBy,
        String reason
    ) {}
}