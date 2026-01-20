package io.contexa.contexacoreenterprise.soar.approval;

import io.contexa.contexacore.domain.ApprovalRequest;
import io.contexa.contexacore.domain.ApprovalRequest.ApprovalStatus;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.ApplicationEventPublisher;

import java.time.LocalDateTime;
import java.util.*;


@Slf4j
@RequiredArgsConstructor
public class ApprovalStateManager {
    
    private final ApplicationEventPublisher eventPublisher;
    
    
    private static final Map<ApprovalStatus, Set<ApprovalStatus>> TRANSITION_RULES;
    
    static {
        TRANSITION_RULES = new HashMap<>();
        
        
        Set<ApprovalStatus> fromPending = new HashSet<>();
        fromPending.add(ApprovalStatus.APPROVED);
        fromPending.add(ApprovalStatus.REJECTED);
        fromPending.add(ApprovalStatus.EXPIRED);
        fromPending.add(ApprovalStatus.CANCELLED);
        TRANSITION_RULES.put(ApprovalStatus.PENDING, fromPending);
        
        
        TRANSITION_RULES.put(ApprovalStatus.APPROVED, Collections.emptySet());
        
        
        TRANSITION_RULES.put(ApprovalStatus.REJECTED, Collections.emptySet());
        
        
        TRANSITION_RULES.put(ApprovalStatus.EXPIRED, Collections.emptySet());
        
        
        TRANSITION_RULES.put(ApprovalStatus.CANCELLED, Collections.emptySet());
    }
    
    
    public void transitionTo(
            ApprovalRequest request, 
            ApprovalStatus newStatus,
            String reviewer,
            String comment) {
        
        if (request == null) {
            throw new IllegalArgumentException("ApprovalRequest cannot be null");
        }
        
        if (newStatus == null) {
            throw new IllegalArgumentException("New status cannot be null");
        }
        
        ApprovalStatus currentStatus = request.getStatus();
        
        
        if (currentStatus == null) {
            log.warn("Current status is null for request: {}, setting to PENDING", 
                request.getRequestId());
            currentStatus = ApprovalStatus.PENDING;
            request.setStatus(currentStatus);
        }
        
        
        validateTransition(currentStatus, newStatus, request.getRequestId());
        
        
        Map<String, Object> metadata = request.getMetadata();
        if (metadata == null) {
            metadata = new HashMap<>();
            request.setMetadata(metadata);
        }
        metadata.put("previousStatus", currentStatus.name());
        metadata.put("statusChangedAt", LocalDateTime.now().toString());
        
        
        request.setStatus(newStatus);
        
        
        handleStateSpecificActions(request, newStatus, reviewer, comment);
        
        
        publishStateChangeEvent(request, currentStatus, newStatus, reviewer, comment);
        
        log.info("State transition completed: {} -> {} for request: {}", 
            currentStatus, newStatus, request.getRequestId());
    }
    
    
    public void approve(ApprovalRequest request, String approver, String comment) {
        log.info("Processing approval for request: {} by {}", 
            request.getRequestId(), approver);
        
        transitionTo(request, ApprovalStatus.APPROVED, approver, comment);
        
        
        request.setApproved(true);
        request.setApprovedAt(LocalDateTime.now());
        request.setApprovedBy(approver);
        if (comment != null && !comment.isEmpty()) {
            request.setReason(comment);
        }
    }
    
    
    public void reject(ApprovalRequest request, String reviewer, String reason) {
        log.info("Processing rejection for request: {} by {}", 
            request.getRequestId(), reviewer);
        
        transitionTo(request, ApprovalStatus.REJECTED, reviewer, reason);
        
        
        request.setApproved(false);
        request.setApprovedAt(LocalDateTime.now());
        request.setApprovedBy(reviewer);
        request.setRejectionReason(reason);
    }
    
    
    public void expire(ApprovalRequest request, String reason) {
        log.info("Processing expiration for request: {}", request.getRequestId());
        
        transitionTo(request, ApprovalStatus.EXPIRED, "system", reason);
        
        
        request.setApproved(false);
        request.setRejectionReason("Expired: " + reason);
        
        Map<String, Object> metadata = request.getMetadata();
        if (metadata != null) {
            metadata.put("expiredAt", LocalDateTime.now().toString());
            metadata.put("expirationReason", reason);
        }
    }
    
    
    public void cancel(ApprovalRequest request, String cancelledBy, String reason) {
        log.info("Processing cancellation for request: {} by {}", 
            request.getRequestId(), cancelledBy);
        
        transitionTo(request, ApprovalStatus.CANCELLED, cancelledBy, reason);
        
        
        request.setApproved(false);
        request.setRejectionReason("Cancelled: " + reason);
        
        Map<String, Object> metadata = request.getMetadata();
        if (metadata != null) {
            metadata.put("cancelledAt", LocalDateTime.now().toString());
            metadata.put("cancelledBy", cancelledBy);
            metadata.put("cancellationReason", reason);
        }
    }
    
    
    public boolean canTransition(ApprovalStatus fromStatus, ApprovalStatus toStatus) {
        if (fromStatus == null || toStatus == null) {
            return false;
        }
        
        Set<ApprovalStatus> allowedTransitions = TRANSITION_RULES.get(fromStatus);
        return allowedTransitions != null && allowedTransitions.contains(toStatus);
    }
    
    
    public Set<ApprovalStatus> getNextAllowedStates(ApprovalStatus currentStatus) {
        if (currentStatus == null) {
            return TRANSITION_RULES.get(ApprovalStatus.PENDING);
        }
        
        Set<ApprovalStatus> allowed = TRANSITION_RULES.get(currentStatus);
        return allowed != null ? new HashSet<>(allowed) : Collections.emptySet();
    }
    
    
    public boolean isFinalState(ApprovalStatus status) {
        if (status == null) {
            return false;
        }
        
        Set<ApprovalStatus> nextStates = TRANSITION_RULES.get(status);
        return nextStates == null || nextStates.isEmpty();
    }
    
    
    private void validateTransition(
            ApprovalStatus fromStatus, 
            ApprovalStatus toStatus,
            String requestId) {
        
        
        if (fromStatus == toStatus) {
            log.debug("Same state transition ignored: {} for request: {}", 
                fromStatus, requestId);
            return;
        }
        
        
        if (!canTransition(fromStatus, toStatus)) {
            String errorMsg = String.format(
                "Invalid state transition: %s -> %s for request: %s", 
                fromStatus, toStatus, requestId
            );
            log.error(errorMsg);
            
            
            Set<ApprovalStatus> allowed = getNextAllowedStates(fromStatus);
            log.error("Allowed transitions from {}: {}", fromStatus, allowed);
            
            throw new IllegalStateException(errorMsg);
        }
    }
    
    
    private void handleStateSpecificActions(
            ApprovalRequest request,
            ApprovalStatus newStatus,
            String actor,
            String comment) {
        
        switch (newStatus) {
            case APPROVED:
                log.info("Approval granted for request: {} by {}", 
                    request.getRequestId(), actor);
                break;
                
            case REJECTED:
                log.info("Approval rejected for request: {} by {} - Reason: {}", 
                    request.getRequestId(), actor, comment);
                break;
                
            case EXPIRED:
                log.warn("Approval expired for request: {} - Reason: {}", 
                    request.getRequestId(), comment);
                break;
                
            case CANCELLED:
                log.info("Approval cancelled for request: {} by {} - Reason: {}", 
                    request.getRequestId(), actor, comment);
                break;
                
            case PENDING:
                
                log.warn("Unusual transition to PENDING for request: {}", 
                    request.getRequestId());
                break;
                
            default:
                log.warn("Unknown status: {} for request: {}", 
                    newStatus, request.getRequestId());
        }
    }
    
    
    private void publishStateChangeEvent(
            ApprovalRequest request,
            ApprovalStatus fromStatus,
            ApprovalStatus toStatus,
            String actor,
            String comment) {
        
        
        Map<String, Object> eventData = new HashMap<>();
        eventData.put("requestId", request.getRequestId());
        eventData.put("fromStatus", fromStatus.name());
        eventData.put("toStatus", toStatus.name());
        eventData.put("actor", actor);
        eventData.put("comment", comment);
        eventData.put("timestamp", LocalDateTime.now());
        
        log.debug("Publishing state change event: {}", eventData);
        
        
        
    }
    
    
    public boolean validateCurrentState(ApprovalRequest request) {
        if (request == null || request.getStatus() == null) {
            return false;
        }
        
        ApprovalStatus status = request.getStatus();
        
        
        if (isFinalState(status)) {
            switch (status) {
                case APPROVED:
                    
                    return request.getApprovedBy() != null && 
                           request.getApprovedAt() != null;
                           
                case REJECTED:
                    
                    return request.getRejectionReason() != null;
                    
                case EXPIRED:
                case CANCELLED:
                    
                    return request.getRejectionReason() != null ||
                           (request.getMetadata() != null && 
                            request.getMetadata().containsKey("reason"));
                            
                default:
                    return true;
            }
        }
        
        return true;
    }
}