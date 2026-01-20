package io.contexa.contexacoreenterprise.soar.controller;

import io.contexa.contexacoreenterprise.soar.approval.ToolApprovalService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.Map;


@Slf4j
@ResponseBody
@RequestMapping("/api/soar/approval")
@RequiredArgsConstructor
public class ToolApprovalController {
    
    private final ToolApprovalService approvalService;
    
    
    @GetMapping("/pending")
    public ResponseEntity<List<ToolApprovalService.ApprovalRequest>> getPendingApprovals() {
        List<ToolApprovalService.ApprovalRequest> pending = approvalService.getPendingApprovals();
        log.info("대기 중인 승인 요청 조회: {} 건", pending.size());
        return ResponseEntity.ok(pending);
    }
    
    
    @GetMapping("/history")
    public ResponseEntity<List<ToolApprovalService.ApprovalResult>> getApprovalHistory(
            @RequestParam(defaultValue = "50") int limit) {
        List<ToolApprovalService.ApprovalResult> history = approvalService.getApprovalHistory(limit);
        return ResponseEntity.ok(history);
    }
    
    
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
    
    
    public record ApprovalDecision(
        String decidedBy,
        String reason
    ) {}
}