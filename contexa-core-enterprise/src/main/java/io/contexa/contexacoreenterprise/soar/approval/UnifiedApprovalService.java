package io.contexa.contexacoreenterprise.soar.approval;

import io.contexa.contexacore.domain.*;
import io.contexa.contexacore.domain.entity.SoarApprovalRequest;
import io.contexa.contexacore.soar.approval.ApprovalService;
import io.contexa.contexacore.soar.approval.ApprovalRequestDetails;
import io.contexa.contexacoreenterprise.domain.entity.ToolExecutionContext;
import io.contexa.contexacore.repository.SoarApprovalRequestRepository;
import io.contexa.contexacore.repository.ApprovalPolicyRepository;
import io.contexa.contexacoreenterprise.repository.ToolExecutionContextRepository;
import io.contexa.contexacoreenterprise.soar.event.ApprovalEvent;
import jakarta.annotation.PreDestroy;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.transaction.annotation.Transactional;

import reactor.core.publisher.Sinks;

import java.time.Duration;
import java.time.LocalDateTime;
import java.util.*;
import java.util.concurrent.*;

@Slf4j
@RequiredArgsConstructor
public class UnifiedApprovalService implements ApprovalService {

    private final SoarApprovalRequestRepository repository;
    private final ApprovalRequestFactory approvalRequestFactory;
    private final ToolExecutionContextRepository executionContextRepository;
    private final ApprovalPolicyRepository policyRepository;
    private final ApplicationEventPublisher eventPublisher;
    private final StringRedisTemplate redisTemplate;

    private final Map<String, CompletableFuture<Boolean>> pendingApprovals = new ConcurrentHashMap<>();

    private final Map<String, Sinks.One<Boolean>> pendingSinks = new ConcurrentHashMap<>();

    private final ScheduledExecutorService scheduler = Executors.newScheduledThreadPool(2);

    private static final Duration TIMEOUT_CRITICAL = Duration.ofSeconds(30);
    private static final Duration TIMEOUT_HIGH = Duration.ofMinutes(1);
    private static final Duration TIMEOUT_MEDIUM = Duration.ofMinutes(2);
    private static final Duration TIMEOUT_LOW = Duration.ofMinutes(3);
    private static final Duration TIMEOUT_DEFAULT = Duration.ofMinutes(2);

    @Override
    @Transactional
    public CompletableFuture<Boolean> requestApproval(ApprovalRequest request) {
        
        if (request.getRequestId() == null || request.getRequestId().isEmpty()) {
            request.setRequestId(UUID.randomUUID().toString());
        }

        String requestId = request.getRequestId();

        // Use putIfAbsent to prevent race condition between containsKey and put
        CompletableFuture<Boolean> future = new CompletableFuture<>();
        CompletableFuture<Boolean> existing = pendingApprovals.putIfAbsent(requestId, future);
        if (existing != null) {
            log.error("Duplicate approval request rejected: {}", requestId);
            return existing;
        }

        saveApprovalRequest(request);

        try {
            
            eventPublisher.publishEvent(ApprovalEvent.requested(this, request));
                    } catch (Exception e) {
            log.error("Failed to publish notification event (approval process continues): {}", requestId, e);
        }

        Duration timeout = getTimeout(request.getRiskLevel());
        scheduleTimeout(requestId, future, timeout);

        future.whenComplete((result, error) -> {
            pendingApprovals.remove(requestId);

            if (error != null) {
                log.error("Approval processing error: {}", requestId, error);
                updateApprovalStatus(requestId, ApprovalRequest.ApprovalStatus.EXPIRED, null, "Timeout or error");
            }
        });

        return future;
    }

    @Override
    @Transactional
    public void handleApprovalResponse(String approvalId, boolean isApproved, String comment, String reviewer) {
        
        processApprovalResponse(approvalId, isApproved, reviewer, comment);
    }

    @Override
    @Transactional
    public void processApprovalResponse(String requestId, boolean approved, String reviewer, String comment) {

        CompletableFuture<Boolean> future = pendingApprovals.remove(requestId);
        if (future != null && !future.isDone()) {
            future.complete(approved);
                    } else if (future != null && future.isDone()) {
            log.error("Already completed approval request: {}", requestId);
            return;
        } else {
            log.error("Pending approval request not found: {}", requestId);
            return;
        }

        ApprovalRequest.ApprovalStatus status = approved ?
                ApprovalRequest.ApprovalStatus.APPROVED :
                ApprovalRequest.ApprovalStatus.REJECTED;
        updateApprovalStatus(requestId, status, reviewer, comment);

        try {
            
            if (approved) {
                eventPublisher.publishEvent(ApprovalEvent.granted(this, requestId, reviewer));
            } else {
                eventPublisher.publishEvent(ApprovalEvent.denied(this, requestId, reviewer, "User rejected"));
            }
        } catch (Exception e) {
            log.error("Failed to send completion notification: {}", requestId, e);
        }

        publishApprovalResult(requestId, approved);

        Sinks.One<Boolean> sink = pendingSinks.remove(requestId);
        if (sink != null) {
            Sinks.EmitResult result = sink.tryEmitValue(approved);
            if (result.isSuccess()) {
                log.error("Approval sink completed: requestId={}, approved={}", requestId, approved);
            }
        }
    }

    @Override
    public boolean waitForApprovalSync(ApprovalRequest request) {
        try {
            CompletableFuture<Boolean> future = requestApproval(request);
            Duration timeout = getTimeout(request.getRiskLevel());

            return future.get(timeout.toSeconds(), TimeUnit.SECONDS);

        } catch (TimeoutException e) {
            log.error("Approval timeout: {}", request.getRequestId());
            return false;
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            log.error("Approval wait interrupted: {}", request.getRequestId(), e);
            return false;
        } catch (ExecutionException e) {
            log.error("Approval processing failed: {}", request.getRequestId(), e);
            return false;
        }
    }

    @Override
    public ApprovalRequest saveApprovalRequest(ApprovalRequest request) {
        SoarApprovalRequest entity = saveApprovalRequestEntity(request);
        
        request.setId(entity.getId());
        request.setRequestId(entity.getRequestId());
        return request;
    }

    private SoarApprovalRequest saveApprovalRequestEntity(ApprovalRequest request) {
        
        ApprovalRequest completeRequest = approvalRequestFactory.completeFromEvent(request);

        SoarApprovalRequest entity = new SoarApprovalRequest();

        entity.setRequestId(completeRequest.getRequestId());
        entity.setPlaybookInstanceId(completeRequest.getIncidentId());
        entity.setIncidentId(completeRequest.getIncidentId());
        entity.setSessionId(completeRequest.getSessionId());
        entity.setToolName(completeRequest.getToolName());
        entity.setActionName(completeRequest.getToolName()); 
        entity.setDescription(completeRequest.getToolDescription());
        entity.setParameters(completeRequest.getParameters());
        entity.setStatus(ApprovalRequest.ApprovalStatus.PENDING.name());
        entity.setRiskLevel(completeRequest.getRiskLevel() != null ?
                completeRequest.getRiskLevel().name() : "MEDIUM");
        
        entity.setRequestedBy(completeRequest.getRequestedBy() != null ?
                completeRequest.getRequestedBy() : "system");
        entity.setOrganizationId(completeRequest.getOrganizationId() != null ?
                completeRequest.getOrganizationId() : "default-org");

        if (completeRequest.getRequiredApprovers() != null) {
            entity.setRequiredApprovers(completeRequest.getRequiredApprovers());
        }
        if (completeRequest.getRequiredRoles() != null && !completeRequest.getRequiredRoles().isEmpty()) {
            entity.setRequiredRoles(new java.util.ArrayList<>(completeRequest.getRequiredRoles()));
        }

        return repository.save(entity);
    }

    @Transactional
    public void updateApprovalStatus(String requestId, ApprovalRequest.ApprovalStatus status,
                                     String reviewer, String comment) {
        try {
            
            SoarApprovalRequest entity = repository.findByRequestId(requestId);

            if (entity == null) {
                
                if (requestId.matches("\\d+")) {
                    entity = repository.findById(Long.parseLong(requestId)).orElse(null);
                }
            }

            if (entity == null) {
                log.error("Approval request not found: {}", requestId);
                return;
            }

            entity.setStatus(status.name());
            entity.setReviewerId(reviewer);
            entity.setReviewerComment(comment);
            
            if (status == ApprovalRequest.ApprovalStatus.APPROVED
                    || status == ApprovalRequest.ApprovalStatus.REJECTED) {
                entity.setApprovedAt(LocalDateTime.now());
            }

            repository.save(entity);
            
        } catch (Exception e) {
            log.error("Failed to update approval status: {}", requestId, e);
        }
    }

    private void scheduleTimeout(String requestId, CompletableFuture<Boolean> future, Duration timeout) {
        scheduler.schedule(() -> {
            if (!future.isDone()) {
                log.error("Approval timeout occurred: {} ({}s)", requestId, timeout.getSeconds());

                future.complete(false);

                updateApprovalStatus(requestId, ApprovalRequest.ApprovalStatus.EXPIRED, null, "Timeout");

                try {
                    eventPublisher.publishEvent(ApprovalEvent.timeout(this, requestId));
                } catch (Exception e) {
                    log.error("Failed to send timeout notification: {}", requestId, e);
                }
            }
        }, timeout.getSeconds(), TimeUnit.SECONDS);
    }

    private Duration getTimeout(ApprovalRequest.RiskLevel riskLevel) {
        if (riskLevel == null) {
            return TIMEOUT_DEFAULT;
        }

        return switch (riskLevel) {
            case CRITICAL -> TIMEOUT_CRITICAL;
            case HIGH -> TIMEOUT_HIGH;
            case MEDIUM -> TIMEOUT_MEDIUM;
            case LOW -> TIMEOUT_LOW;
            default -> TIMEOUT_DEFAULT;
        };
    }

    public int getPendingApprovalCount() {
        return pendingApprovals.size();
    }

    @Override
    public ApprovalRequest.ApprovalStatus getApprovalStatus(String approvalId) {
        try {
            
            SoarApprovalRequest entity = repository.findByRequestId(approvalId);

            if (entity == null) {
                
                if (approvalId.matches("\\d+")) {
                    entity = repository.findById(Long.parseLong(approvalId)).orElse(null);
                }
            }

            if (entity == null) {
                log.error("Approval request not found: {}", approvalId);
                return ApprovalRequest.ApprovalStatus.EXPIRED;
            }

            return ApprovalRequest.ApprovalStatus.valueOf(entity.getStatus());

        } catch (Exception e) {
            log.error("Failed to query approval status: {}", approvalId, e);
            throw new RuntimeException("Failed to query approval status: " + approvalId, e);
        }
    }

    @Override
    @Transactional
    public String requestApproval(SoarContext soarContext, ApprovalRequestDetails requestDetails) {

        ApprovalRequest approvalRequest = convertToApprovalRequest(soarContext, requestDetails);

        CompletableFuture<Boolean> future = requestApproval(approvalRequest);

        if (soarContext != null) {
            Sinks.One<Boolean> sink = Sinks.one();
            pendingSinks.put(approvalRequest.getRequestId(), sink);

            future.whenComplete((result, error) -> {
                Sinks.One<Boolean> pendingSink = pendingSinks.remove(approvalRequest.getRequestId());
                if (pendingSink != null) {
                    if (error != null) {
                        pendingSink.tryEmitError(error);
                    } else {
                        pendingSink.tryEmitValue(result);
                    }
                }
            });
        }

        return approvalRequest.getRequestId();
    }

    private ApprovalRequest convertToApprovalRequest(SoarContext soarContext, ApprovalRequestDetails requestDetails) {
        ApprovalRequest request = new ApprovalRequest();

        request.setRequestId(UUID.randomUUID().toString());
        request.setToolName(requestDetails.actionName());
        request.setToolDescription(requestDetails.description());
        request.setParameters(requestDetails.parameters());
        request.setActionDescription(requestDetails.description());

        if (soarContext != null) {
            request.setIncidentId(soarContext.getIncidentId() != null ?
                    soarContext.getIncidentId() : "INC-" + UUID.randomUUID());
            request.setOrganizationId(soarContext.getOrganizationId() != null ?
                    soarContext.getOrganizationId() : "default-org");
            request.setSessionId(soarContext.getSessionId() != null ?
                    soarContext.getSessionId() : soarContext.getIncidentId());

            String severity = soarContext.getSeverity() != null ? soarContext.getSeverity() : "MEDIUM";
            request.setRiskLevel(mapSeverityToRiskLevel(severity));
        }

        if (policyRepository != null) {
            String severity = soarContext != null && soarContext.getSeverity() != null ?
                    soarContext.getSeverity() : "LOW";
            ApprovalPolicy policy = policyRepository.findPolicyFor(requestDetails.actionName(), severity);

            if (policy != null) {
                request.setRequiredApprovers(policy.requiredApprovers());
                request.setRequiredRoles(new HashSet<>(policy.requiredRoles()));
            }
        }

        request.setRequestedBy("system");
        request.setRequestedAt(LocalDateTime.now());
        request.setStatus(ApprovalRequest.ApprovalStatus.PENDING);

        return request;
    }

    private ApprovalRequest.RiskLevel mapSeverityToRiskLevel(String severity) {
        if (severity == null) {
            return ApprovalRequest.RiskLevel.MEDIUM;
        }

        return switch (severity.toUpperCase()) {
            case "CRITICAL" -> ApprovalRequest.RiskLevel.CRITICAL;
            case "HIGH" -> ApprovalRequest.RiskLevel.HIGH;
            case "MEDIUM" -> ApprovalRequest.RiskLevel.MEDIUM;
            case "LOW" -> ApprovalRequest.RiskLevel.LOW;
            default -> ApprovalRequest.RiskLevel.MEDIUM;
        };
    }

    private void publishApprovalResult(String approvalId, boolean approved) {
        if (redisTemplate != null) {
            try {
                String channel = "approval:" + approvalId;
                String message = approved ? "APPROVED" : "REJECTED";
                redisTemplate.convertAndSend(channel, message);
                            } catch (Exception e) {
                log.error("Redis Pub/Sub publish failed: {}", approvalId, e);
            }
        }
    }

    public boolean isPending(String approvalId) {
        CompletableFuture<Boolean> future = pendingApprovals.get(approvalId);
        return future != null && !future.isDone();
    }

    public boolean isCompleted(String approvalId) {
        CompletableFuture<Boolean> future = pendingApprovals.get(approvalId);
        if (future != null && future.isDone() && !future.isCancelled()) {
            return true;
        }

        SoarApprovalRequest entity = repository.findByRequestId(approvalId);
        if (entity != null) {
            String status = entity.getStatus();
            return "APPROVED".equals(status) || "REJECTED".equals(status);
        }

        return false;
    }

    public boolean isCancelled(String approvalId) {
        CompletableFuture<Boolean> future = pendingApprovals.get(approvalId);
        if (future != null && future.isCancelled()) {
            return true;
        }

        SoarApprovalRequest entity = repository.findByRequestId(approvalId);
        if (entity != null) {
            String status = entity.getStatus();
            return "CANCELLED".equals(status) || "EXPIRED".equals(status);
        }

        return false;
    }

    public java.util.Set<String> getPendingApprovalIds() {
        java.util.Set<String> pendingIds = new HashSet<>();

        pendingApprovals.forEach((id, future) -> {
            if (!future.isDone()) {
                pendingIds.add(id);
            }
        });

        return pendingIds;
    }

    public int getPendingCount() {
        return (int) pendingApprovals.entrySet().stream()
                .filter(entry -> !entry.getValue().isDone())
                .count();
    }

    public void cancelApproval(String approvalId, String reason) {

        CompletableFuture<Boolean> future = pendingApprovals.remove(approvalId);
        if (future != null && !future.isDone()) {
            future.cancel(true);
        }

        updateApprovalStatus(approvalId, ApprovalRequest.ApprovalStatus.CANCELLED, "system", reason);

        try {
            eventPublisher.publishEvent(ApprovalEvent.cancelled(this, approvalId, reason));
        } catch (Exception e) {
            log.error("Failed to publish cancellation event: {}", approvalId, e);
        }
    }

    public Map<String, Object> getStatistics() {
        int pendingCount = getPendingCount();
        int totalCount = pendingApprovals.size() + pendingSinks.size();

        long approvedCount = 0;
        long rejectedCount = 0;
        long expiredCount = 0;

        try {
            LocalDateTime since = LocalDateTime.now().minusDays(1);

            approvedCount = repository.findByStatusOrderByCreatedAtDesc("APPROVED")
                    .stream().filter(r -> r.getCreatedAt() != null && r.getCreatedAt().isAfter(since)).count();
            rejectedCount = repository.findByStatusOrderByCreatedAtDesc("REJECTED")
                    .stream().filter(r -> r.getCreatedAt() != null && r.getCreatedAt().isAfter(since)).count();
            expiredCount = repository.findByStatusOrderByCreatedAtDesc("EXPIRED")
                    .stream().filter(r -> r.getCreatedAt() != null && r.getCreatedAt().isAfter(since)).count();
        } catch (Exception e) {
            log.error("Failed to query statistics", e);
        }

        return new HashMap<>(Map.of(
                "pending", pendingCount,
                "total", totalCount,
                "approved24h", approvedCount,
                "rejected24h", rejectedCount,
                "expired24h", expiredCount,
                "timestamp", LocalDateTime.now()
        ));
    }

    @Transactional
    public void registerAsyncApproval(ApprovalRequest request, ToolExecutionContext executionContext) {
        
        try {
            
            if (request.getId() == null) {
                saveApprovalRequest(request);
            }

            if (executionContext != null && executionContextRepository != null) {
                executionContext.setStatus("PENDING_APPROVAL");
                executionContextRepository.save(executionContext);
                            }

            CompletableFuture<Boolean> future = new CompletableFuture<>();
            pendingApprovals.put(request.getRequestId(), future);

            Duration timeout = getTimeout(request.getRiskLevel());
            scheduleAsyncTimeout(request.getRequestId(), future, timeout, executionContext);

        } catch (Exception e) {
            log.error("Async approval registration failed: {}", request.getRequestId(), e);

            if (executionContext != null && executionContextRepository != null) {
                executionContext.setStatus("FAILED");
                executionContext.setExecutionError("Approval registration failed: " + e.getMessage());
                executionContextRepository.save(executionContext);
            }
        }
    }

    private void scheduleAsyncTimeout(String requestId, CompletableFuture<Boolean> future,
                                      Duration timeout, ToolExecutionContext executionContext) {
        scheduler.schedule(() -> {
            if (!future.isDone()) {
                log.error("Async approval timeout occurred: {} ({}min)", requestId, timeout.toMinutes());

                future.complete(false);

                if (executionContext != null && executionContextRepository != null) {
                    executionContext.setStatus("TIMEOUT");
                    executionContext.setExecutionError("Approval timeout");
                    executionContextRepository.save(executionContext);
                }

                updateApprovalStatus(requestId, ApprovalRequest.ApprovalStatus.EXPIRED,
                        "system", "Timeout");

                try {
                    
                    eventPublisher.publishEvent(ApprovalEvent.timeout(this, requestId));
                } catch (Exception e) {
                    log.error("Failed to send timeout notification: {}", requestId, e);
                }
            }
        }, timeout.getSeconds(), TimeUnit.SECONDS);
    }

    @PreDestroy
    public void shutdown() {

        pendingApprovals.forEach((id, future) -> {
            if (!future.isDone()) {
                future.cancel(true);
            }
        });
        pendingApprovals.clear();

        pendingSinks.forEach((id, sink) -> {
            sink.tryEmitError(new InterruptedException("Service shutting down"));
        });
        pendingSinks.clear();

        scheduler.shutdown();
        try {
            if (!scheduler.awaitTermination(5, TimeUnit.SECONDS)) {
                scheduler.shutdownNow();
            }
        } catch (InterruptedException e) {
            scheduler.shutdownNow();
            Thread.currentThread().interrupt();
        }
    }
}