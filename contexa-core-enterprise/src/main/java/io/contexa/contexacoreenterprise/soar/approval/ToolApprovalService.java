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

/**
 * Tool Approval Service
 * SOAR 도구 실행에 대한 승인 관리 (Client 측 구현)
 * 고위험 도구는 실행 전 승인 필요
 */
@Slf4j
@RequiredArgsConstructor
public class ToolApprovalService {
    
    // 메모리 기반 승인 요청 저장
    private final Map<String, ApprovalRequest> pendingApprovals = new ConcurrentHashMap<>();
    private final Map<String, ApprovalResult> approvalHistory = new ConcurrentHashMap<>();
    private final Map<String, CompletableFuture<ApprovalResult>> approvalFutures = new ConcurrentHashMap<>();
    
    /**
     * 승인 요청 생성
     */
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
        
        log.info("Approval request created: {} for tool {} (Risk: {})", 
            approvalId, toolName, riskLevel);
        
        // 타임아웃 처리 (30분)
        CompletableFuture.delayedExecutor(30, java.util.concurrent.TimeUnit.MINUTES)
            .execute(() -> {
                if (!future.isDone()) {
                    expire(approvalId);
                }
            });
        
        return future;
    }
    
    /**
     * 승인 처리
     */
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
        
        log.info("Tool execution approved: {} by {}", request.getToolName(), decidedBy);
        return true;
    }
    
    /**
     * 거부 처리
     */
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
    
    /**
     * 만료 처리
     */
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
    
    /**
     * 대기 중인 승인 요청 조회
     */
    public List<ApprovalRequest> getPendingApprovals() {
        return new ArrayList<>(pendingApprovals.values());
    }
    
    /**
     * 승인 이력 조회
     */
    public List<ApprovalResult> getApprovalHistory(int limit) {
        return approvalHistory.values().stream()
            .sorted((a, b) -> b.getDecidedAt().compareTo(a.getDecidedAt()))
            .limit(limit)
            .collect(Collectors.toList());
    }
    
    /**
     * Approval Request DTO
     */
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
    
    /**
     * Approval Result DTO
     */
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