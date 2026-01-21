package io.contexa.contexacoreenterprise.soar.approval;

import lombok.Builder;
import lombok.Data;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

import java.time.Instant;
import java.util.*;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ConcurrentHashMap;
import java.util.stream.Collectors;

@Slf4j
@RequiredArgsConstructor
public class ToolApprovalService {

    private final Map<String, ApprovalRequest> pendingApprovals = new ConcurrentHashMap<>();
    private final Map<String, ApprovalResult> approvalHistory = new ConcurrentHashMap<>();
    private final Map<String, CompletableFuture<ApprovalResult>> approvalFutures = new ConcurrentHashMap<>();

    public CompletableFuture<ApprovalResult> requestApproval(String toolName, String requestData, 
                                                            String riskLevel, String requestedBy) {
        String approvalId = UUID.randomUUID().toString();
        
        ApprovalRequest request = ApprovalRequest.builder()
            .approvalId(approvalId)
            .toolName(toolName)
            .requestData(requestData)
            .riskLevel(riskLevel)
            .requestedBy(requestedBy)
            .requestedAt(Instant.now())
            .status("PENDING")
            .build();
        
        pendingApprovals.put(approvalId, request);
        
        CompletableFuture<ApprovalResult> future = new CompletableFuture<>();
        approvalFutures.put(approvalId, future);

        CompletableFuture.delayedExecutor(30, java.util.concurrent.TimeUnit.MINUTES)
            .execute(() -> {
                if (!future.isDone()) {
                    expire(approvalId);
                }
            });
        
        return future;
    }

    public boolean approve(String approvalId, String decidedBy, String reason) {
        ApprovalRequest request = pendingApprovals.remove(approvalId);
        if (request == null) {
            log.warn("Approval request not found: {}", approvalId);
            return false;
        }
        
        ApprovalResult result = ApprovalResult.builder()
            .approvalId(approvalId)
            .toolName(request.getToolName())
            .approved(true)
            .decidedBy(decidedBy)
            .decidedAt(Instant.now())
            .reason(reason)
            .build();
        
        approvalHistory.put(approvalId, result);
        
        CompletableFuture<ApprovalResult> future = approvalFutures.remove(approvalId);
        if (future != null) {
            future.complete(result);
        }
        
                return true;
    }

    public boolean reject(String approvalId, String decidedBy, String reason) {
        ApprovalRequest request = pendingApprovals.remove(approvalId);
        if (request == null) {
            log.warn("Approval request not found: {}", approvalId);
            return false;
        }
        
        ApprovalResult result = ApprovalResult.builder()
            .approvalId(approvalId)
            .toolName(request.getToolName())
            .approved(false)
            .decidedBy(decidedBy)
            .decidedAt(Instant.now())
            .reason(reason)
            .build();
        
        approvalHistory.put(approvalId, result);
        
        CompletableFuture<ApprovalResult> future = approvalFutures.remove(approvalId);
        if (future != null) {
            future.complete(result);
        }
        
        log.warn("Tool execution rejected: {} by {}", request.getToolName(), decidedBy);
        return true;
    }

    private void expire(String approvalId) {
        ApprovalRequest request = pendingApprovals.remove(approvalId);
        if (request != null) {
            ApprovalResult result = ApprovalResult.builder()
                .approvalId(approvalId)
                .toolName(request.getToolName())
                .approved(false)
                .decidedBy("SYSTEM")
                .decidedAt(Instant.now())
                .reason("Request expired after 30 minutes")
                .build();
            
            approvalHistory.put(approvalId, result);
            
            CompletableFuture<ApprovalResult> future = approvalFutures.remove(approvalId);
            if (future != null) {
                future.complete(result);
            }
            
            log.warn("⏰ Approval request expired: {}", approvalId);
        }
    }

    public List<ApprovalRequest> getPendingApprovals() {
        return new ArrayList<>(pendingApprovals.values());
    }

    public List<ApprovalResult> getApprovalHistory(int limit) {
        return approvalHistory.values().stream()
            .sorted((a, b) -> b.getDecidedAt().compareTo(a.getDecidedAt()))
            .limit(limit)
            .collect(Collectors.toList());
    }

    @Data
    @Builder
    public static class ApprovalRequest {
        private String approvalId;
        private String toolName;
        private String requestData;
        private String riskLevel;
        private String requestedBy;
        private Instant requestedAt;
        private String status;
    }

    @Data
    @Builder
    public static class ApprovalResult {
        private String approvalId;
        private String toolName;
        private boolean approved;
        private String decidedBy;
        private Instant decidedAt;
        private String reason;
        
        public boolean isApproved() {
            return approved;
        }
        
        public String getReason() {
            return reason;
        }
    }
}