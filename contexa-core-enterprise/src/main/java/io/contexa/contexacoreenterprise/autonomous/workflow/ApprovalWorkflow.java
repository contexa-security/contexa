package io.contexa.contexacoreenterprise.autonomous.workflow;

import io.contexa.contexacoreenterprise.mcp.tool.execution.ToolExecutor;
import io.contexa.contexacoreenterprise.tool.authorization.ToolAuthorizationService;
import lombok.Builder;
import lombok.Data;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.scheduling.annotation.Async;

import java.time.Duration;
import java.time.Instant;
import java.util.*;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;

@Slf4j
@RequiredArgsConstructor
public class ApprovalWorkflow {
    
    private final RedisTemplate<String, Object> redisTemplate;
    private final ToolAuthorizationService authService;
    
    @Value("${approval.timeout:60}")
    private long approvalTimeoutSeconds;
    
    @Value("${approval.auto-approve.enabled:false}")
    private boolean autoApproveEnabled;

    private final Map<String, ApprovalRequest> pendingApprovals = new ConcurrentHashMap<>();
    private final Map<String, CompletableFuture<ApprovalResult>> approvalFutures = new ConcurrentHashMap<>();

    public ApprovalResult requestApproval(
            String toolName,
            ToolExecutor.ToolRequest request,
            ToolExecutor.ExecutionContext context,
            RiskLevel riskLevel) {
        
        String approvalId = generateApprovalId(toolName, context);
        
        ApprovalRequest approvalRequest = ApprovalRequest.builder()
            .id(approvalId)
            .toolName(toolName)
            .request(request)
            .context(context)
            .riskLevel(riskLevel)
            .requestTime(Instant.now())
            .status(ApprovalStatus.PENDING)
            .build();

        saveApprovalRequest(approvalRequest);

        pendingApprovals.put(approvalId, approvalRequest);

        if (shouldAutoApprove(approvalRequest)) {
            return autoApprove(approvalRequest);
        }

        try {
            return waitForApproval(approvalRequest);
        } catch (Exception e) {
            log.error("승인 대기 중 오류: {}", e.getMessage());
            return ApprovalResult.denied("승인 처리 중 오류 발생");
        }
    }

    @Async
    public CompletableFuture<ApprovalResult> requestApprovalAsync(
            String toolName,
            ToolExecutor.ToolRequest request,
            ToolExecutor.ExecutionContext context,
            RiskLevel riskLevel) {
        
        return CompletableFuture.supplyAsync(() -> 
            requestApproval(toolName, request, context, riskLevel)
        );
    }

    public void approve(String approvalId, String approver, String reason) {
        ApprovalRequest request = pendingApprovals.get(approvalId);
        if (request == null) {
            log.warn("승인 요청을 찾을 수 없음: {}", approvalId);
            return;
        }
        
        request.setStatus(ApprovalStatus.APPROVED);
        request.setApprover(approver);
        request.setApprovalTime(Instant.now());
        request.setReason(reason);

        saveApprovalRequest(request);

        CompletableFuture<ApprovalResult> future = approvalFutures.get(approvalId);
        if (future != null) {
            future.complete(ApprovalResult.approved(approver, reason));
        }

        cleanup(approvalId);
    }

    public void deny(String approvalId, String denier, String reason) {
        ApprovalRequest request = pendingApprovals.get(approvalId);
        if (request == null) {
            log.warn("승인 요청을 찾을 수 없음: {}", approvalId);
            return;
        }
        
        request.setStatus(ApprovalStatus.DENIED);
        request.setApprover(denier);
        request.setApprovalTime(Instant.now());
        request.setReason(reason);

        saveApprovalRequest(request);

        CompletableFuture<ApprovalResult> future = approvalFutures.get(approvalId);
        if (future != null) {
            future.complete(ApprovalResult.denied(reason));
        }

        cleanup(approvalId);
    }

    public List<ApprovalRequest> getPendingApprovals() {
        return new ArrayList<>(pendingApprovals.values());
    }

    public List<ApprovalRequest> getPendingApprovalsForUser(String userId) {
        return pendingApprovals.values().stream()
            .filter(req -> req.getContext().getUserId().equals(userId))
            .toList();
    }

    public ApprovalStatus getApprovalStatus(String approvalId) {
        ApprovalRequest request = getApprovalRequest(approvalId);
        return request != null ? request.getStatus() : null;
    }

    private ApprovalResult waitForApproval(ApprovalRequest request) throws TimeoutException {
        CompletableFuture<ApprovalResult> future = new CompletableFuture<>();
        approvalFutures.put(request.getId(), future);
        
        try {
            return future.get(approvalTimeoutSeconds, TimeUnit.SECONDS);
        } catch (TimeoutException e) {
            log.warn("승인 타임아웃: {}", request.getId());
            request.setStatus(ApprovalStatus.TIMEOUT);
            saveApprovalRequest(request);
            cleanup(request.getId());
            throw new TimeoutException("승인 대기 시간 초과");
        } catch (Exception e) {
            log.error("승인 대기 중 오류: {}", e.getMessage());
            cleanup(request.getId());
            return ApprovalResult.denied("승인 처리 중 오류 발생");
        }
    }

    private boolean shouldAutoApprove(ApprovalRequest request) {
        if (!autoApproveEnabled) {
            return false;
        }

        if (request.getRiskLevel() == RiskLevel.LOW) {
            return true;
        }

        if (request.getRiskLevel() == RiskLevel.MEDIUM) {
            Set<String> permissions = authService.getUserPermissions(
                request.getContext().getUserId()
            );
            return permissions.contains("tool.approve.all");
        }
        
        return false;
    }

    private ApprovalResult autoApprove(ApprovalRequest request) {
                
        request.setStatus(ApprovalStatus.AUTO_APPROVED);
        request.setApprover("SYSTEM");
        request.setApprovalTime(Instant.now());
        request.setReason("자동 승인 정책에 의해 승인됨");
        
        saveApprovalRequest(request);
        cleanup(request.getId());
        
        return ApprovalResult.approved("SYSTEM", "자동 승인");
    }

    private void saveApprovalRequest(ApprovalRequest request) {
        String key = "approval:" + request.getId();
        redisTemplate.opsForValue().set(key, request, Duration.ofHours(24));
    }

    private ApprovalRequest getApprovalRequest(String approvalId) {
        String key = "approval:" + approvalId;
        Object obj = redisTemplate.opsForValue().get(key);
        return obj instanceof ApprovalRequest ? (ApprovalRequest) obj : null;
    }

    private String generateApprovalId(String toolName, ToolExecutor.ExecutionContext context) {
        return String.format("%s-%s-%d-%s",
            toolName,
            context.getUserId(),
            System.currentTimeMillis(),
            UUID.randomUUID().toString().substring(0, 8)
        );
    }

    private void cleanup(String approvalId) {
        pendingApprovals.remove(approvalId);
        approvalFutures.remove(approvalId);
    }

    @Data
    @Builder
    public static class ApprovalRequest {
        private String id;
        private String toolName;
        private ToolExecutor.ToolRequest request;
        private ToolExecutor.ExecutionContext context;
        private RiskLevel riskLevel;
        private Instant requestTime;
        private Instant approvalTime;
        private String approver;
        private String reason;
        private ApprovalStatus status;
    }

    @Data
    @Builder
    public static class ApprovalResult {
        private boolean approved;
        private String approver;
        private String reason;
        private Instant timestamp;
        
        public static ApprovalResult approved(String approver, String reason) {
            return ApprovalResult.builder()
                .approved(true)
                .approver(approver)
                .reason(reason)
                .timestamp(Instant.now())
                .build();
        }
        
        public static ApprovalResult denied(String reason) {
            return ApprovalResult.builder()
                .approved(false)
                .reason(reason)
                .timestamp(Instant.now())
                .build();
        }
    }

    public enum ApprovalStatus {
        PENDING,        
        APPROVED,       
        DENIED,         
        AUTO_APPROVED,  
        TIMEOUT,        
        CANCELLED       
    }

    public enum RiskLevel {
        LOW,      
        MEDIUM,   
        HIGH,     
        CRITICAL  
    }
}