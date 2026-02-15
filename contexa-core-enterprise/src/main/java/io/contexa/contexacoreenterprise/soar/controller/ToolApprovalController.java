package io.contexa.contexacoreenterprise.soar.controller;

import io.contexa.contexacoreenterprise.soar.approval.ToolApprovalService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
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
                return ResponseEntity.ok(pending);
    }

    @GetMapping("/history")
    public ResponseEntity<List<ToolApprovalService.ApprovalResult>> getApprovalHistory(
            @RequestParam(defaultValue = "50") int limit) {
        List<ToolApprovalService.ApprovalResult> history = approvalService.getApprovalHistory(limit);
        return ResponseEntity.ok(history);
    }

    @PreAuthorize("isAuthenticated()")
    @PostMapping("/{approvalId}/approve")
    public ResponseEntity<Map<String, Object>> approve(
            @PathVariable String approvalId,
            @RequestBody ApprovalDecision decision) {

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

    @PreAuthorize("isAuthenticated()")
    @PostMapping("/{approvalId}/reject")
    public ResponseEntity<Map<String, Object>> reject(
            @PathVariable String approvalId,
            @RequestBody ApprovalDecision decision) {
        
        log.error("Rejection processed: ID={}, By={}, Reason={}",
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