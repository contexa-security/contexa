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

/**
 * ApprovalWorkflow
 * 
 * 고위험 도구 실행에 대한 승인 워크플로우를 관리합니다.
 * Redis를 사용하여 승인 요청을 저장하고 처리합니다.
 */
@Slf4j
@RequiredArgsConstructor
public class ApprovalWorkflow {
    
    private final RedisTemplate<String, Object> redisTemplate;
    private final ToolAuthorizationService authService;
    
    @Value("${approval.timeout:60}")
    private long approvalTimeoutSeconds;
    
    @Value("${approval.auto-approve.enabled:false}")
    private boolean autoApproveEnabled;
    
    // 승인 대기 중인 요청들
    private final Map<String, ApprovalRequest> pendingApprovals = new ConcurrentHashMap<>();
    private final Map<String, CompletableFuture<ApprovalResult>> approvalFutures = new ConcurrentHashMap<>();
    
    /**
     * 승인 요청 생성 및 대기
     */
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
        
        log.info("승인 요청 생성: id={}, tool={}, risk={}", 
            approvalId, toolName, riskLevel);
        
        // Redis에 저장
        saveApprovalRequest(approvalRequest);
        
        // 로컬 맵에도 저장
        pendingApprovals.put(approvalId, approvalRequest);
        
        // 자동 승인 확인
        if (shouldAutoApprove(approvalRequest)) {
            return autoApprove(approvalRequest);
        }
        
        // 승인 대기
        try {
            return waitForApproval(approvalRequest);
        } catch (Exception e) {
            log.error("승인 대기 중 오류: {}", e.getMessage());
            return ApprovalResult.denied("승인 처리 중 오류 발생");
        }
    }
    
    /**
     * 비동기 승인 요청
     */
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
    
    /**
     * 승인 처리
     */
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
        
        // Redis 업데이트
        saveApprovalRequest(request);
        
        // Future 완료
        CompletableFuture<ApprovalResult> future = approvalFutures.get(approvalId);
        if (future != null) {
            future.complete(ApprovalResult.approved(approver, reason));
        }
        
        log.info("승인 완료: id={}, approver={}", approvalId, approver);
        
        // 정리
        cleanup(approvalId);
    }
    
    /**
     * 거부 처리
     */
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
        
        // Redis 업데이트
        saveApprovalRequest(request);
        
        // Future 완료
        CompletableFuture<ApprovalResult> future = approvalFutures.get(approvalId);
        if (future != null) {
            future.complete(ApprovalResult.denied(reason));
        }
        
        log.info("거부 완료: id={}, denier={}, reason={}", approvalId, denier, reason);
        
        // 정리
        cleanup(approvalId);
    }
    
    /**
     * 대기 중인 승인 요청 목록
     */
    public List<ApprovalRequest> getPendingApprovals() {
        return new ArrayList<>(pendingApprovals.values());
    }
    
    /**
     * 특정 사용자의 대기 중인 승인 요청
     */
    public List<ApprovalRequest> getPendingApprovalsForUser(String userId) {
        return pendingApprovals.values().stream()
            .filter(req -> req.getContext().getUserId().equals(userId))
            .toList();
    }
    
    /**
     * 승인 요청 상태 확인
     */
    public ApprovalStatus getApprovalStatus(String approvalId) {
        ApprovalRequest request = getApprovalRequest(approvalId);
        return request != null ? request.getStatus() : null;
    }
    
    // Private 메서드들
    
    /**
     * 승인 대기
     */
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
    
    /**
     * 자동 승인 여부 확인
     */
    private boolean shouldAutoApprove(ApprovalRequest request) {
        if (!autoApproveEnabled) {
            return false;
        }
        
        // 낮은 위험도는 자동 승인
        if (request.getRiskLevel() == RiskLevel.LOW) {
            return true;
        }
        
        // 관리자는 중간 위험도까지 자동 승인
        if (request.getRiskLevel() == RiskLevel.MEDIUM) {
            Set<String> permissions = authService.getUserPermissions(
                request.getContext().getUserId()
            );
            return permissions.contains("tool.approve.all");
        }
        
        return false;
    }
    
    /**
     * 자동 승인
     */
    private ApprovalResult autoApprove(ApprovalRequest request) {
        log.info("자동 승인: id={}, tool={}", request.getId(), request.getToolName());
        
        request.setStatus(ApprovalStatus.AUTO_APPROVED);
        request.setApprover("SYSTEM");
        request.setApprovalTime(Instant.now());
        request.setReason("자동 승인 정책에 의해 승인됨");
        
        saveApprovalRequest(request);
        cleanup(request.getId());
        
        return ApprovalResult.approved("SYSTEM", "자동 승인");
    }
    
    /**
     * Redis에 승인 요청 저장
     */
    private void saveApprovalRequest(ApprovalRequest request) {
        String key = "approval:" + request.getId();
        redisTemplate.opsForValue().set(key, request, Duration.ofHours(24));
    }
    
    /**
     * Redis에서 승인 요청 조회
     */
    private ApprovalRequest getApprovalRequest(String approvalId) {
        String key = "approval:" + approvalId;
        Object obj = redisTemplate.opsForValue().get(key);
        return obj instanceof ApprovalRequest ? (ApprovalRequest) obj : null;
    }
    
    /**
     * 승인 ID 생성
     */
    private String generateApprovalId(String toolName, ToolExecutor.ExecutionContext context) {
        return String.format("%s-%s-%d-%s",
            toolName,
            context.getUserId(),
            System.currentTimeMillis(),
            UUID.randomUUID().toString().substring(0, 8)
        );
    }
    
    /**
     * 정리
     */
    private void cleanup(String approvalId) {
        pendingApprovals.remove(approvalId);
        approvalFutures.remove(approvalId);
    }
    
    /**
     * 승인 요청
     */
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
    
    /**
     * 승인 결과
     */
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
    
    /**
     * 승인 상태
     */
    public enum ApprovalStatus {
        PENDING,        // 대기 중
        APPROVED,       // 승인됨
        DENIED,         // 거부됨
        AUTO_APPROVED,  // 자동 승인
        TIMEOUT,        // 타임아웃
        CANCELLED       // 취소됨
    }
    
    /**
     * 위험도 레벨
     */
    public enum RiskLevel {
        LOW,      // 낮음
        MEDIUM,   // 중간
        HIGH,     // 높음
        CRITICAL  // 매우 높음
    }
}