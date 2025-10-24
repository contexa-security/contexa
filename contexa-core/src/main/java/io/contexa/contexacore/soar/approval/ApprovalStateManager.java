package io.contexa.contexacore.soar.approval;

import io.contexa.contexacore.domain.ApprovalRequest;
import io.contexa.contexacore.domain.ApprovalRequest.ApprovalStatus;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.stereotype.Component;

import java.time.LocalDateTime;
import java.util.*;

/**
 * 승인 요청의 상태 전이를 관리하는 클래스
 * 
 * 상태 전이 규칙을 정의하고 검증하며, 유효하지 않은 상태 전이를 방지합니다.
 * State Machine 패턴을 구현하여 일관된 상태 관리를 보장합니다.
 */
@Slf4j
@Component
@RequiredArgsConstructor
public class ApprovalStateManager {
    
    private final ApplicationEventPublisher eventPublisher;
    
    /**
     * 상태 전이 규칙 정의
     * Key: 현재 상태, Value: 전이 가능한 상태들
     */
    private static final Map<ApprovalStatus, Set<ApprovalStatus>> TRANSITION_RULES;
    
    static {
        TRANSITION_RULES = new HashMap<>();
        
        // PENDING 상태에서 가능한 전이
        Set<ApprovalStatus> fromPending = new HashSet<>();
        fromPending.add(ApprovalStatus.APPROVED);
        fromPending.add(ApprovalStatus.REJECTED);
        fromPending.add(ApprovalStatus.EXPIRED);
        fromPending.add(ApprovalStatus.CANCELLED);
        TRANSITION_RULES.put(ApprovalStatus.PENDING, fromPending);
        
        // APPROVED 상태에서는 전이 불가 (최종 상태)
        TRANSITION_RULES.put(ApprovalStatus.APPROVED, Collections.emptySet());
        
        // REJECTED 상태에서는 전이 불가 (최종 상태)
        TRANSITION_RULES.put(ApprovalStatus.REJECTED, Collections.emptySet());
        
        // EXPIRED 상태에서는 전이 불가 (최종 상태)
        TRANSITION_RULES.put(ApprovalStatus.EXPIRED, Collections.emptySet());
        
        // CANCELLED 상태에서는 전이 불가 (최종 상태)
        TRANSITION_RULES.put(ApprovalStatus.CANCELLED, Collections.emptySet());
    }
    
    /**
     * 상태 전이 수행
     * 
     * @param request 승인 요청
     * @param newStatus 새로운 상태
     * @param reviewer 검토자 (승인/거부 시)
     * @param comment 코멘트
     * @throws IllegalStateException 유효하지 않은 상태 전이인 경우
     */
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
        
        // 현재 상태가 null인 경우 PENDING으로 초기화
        if (currentStatus == null) {
            log.warn("Current status is null for request: {}, setting to PENDING", 
                request.getRequestId());
            currentStatus = ApprovalStatus.PENDING;
            request.setStatus(currentStatus);
        }
        
        // 상태 전이 검증
        validateTransition(currentStatus, newStatus, request.getRequestId());
        
        // 이전 상태 저장 (메타데이터에)
        Map<String, Object> metadata = request.getMetadata();
        if (metadata == null) {
            metadata = new HashMap<>();
            request.setMetadata(metadata);
        }
        metadata.put("previousStatus", currentStatus.name());
        metadata.put("statusChangedAt", LocalDateTime.now().toString());
        
        // 상태 변경
        request.setStatus(newStatus);
        
        // 상태별 추가 처리
        handleStateSpecificActions(request, newStatus, reviewer, comment);
        
        // 상태 변경 이벤트 발행
        publishStateChangeEvent(request, currentStatus, newStatus, reviewer, comment);
        
        log.info("State transition completed: {} -> {} for request: {}", 
            currentStatus, newStatus, request.getRequestId());
    }
    
    /**
     * 승인 처리
     * 
     * @param request 승인 요청
     * @param approver 승인자
     * @param comment 승인 코멘트
     */
    public void approve(ApprovalRequest request, String approver, String comment) {
        log.info("Processing approval for request: {} by {}", 
            request.getRequestId(), approver);
        
        transitionTo(request, ApprovalStatus.APPROVED, approver, comment);
        
        // 승인 관련 필드 설정
        request.setApproved(true);
        request.setApprovedAt(LocalDateTime.now());
        request.setApprovedBy(approver);
        if (comment != null && !comment.isEmpty()) {
            request.setReason(comment);
        }
    }
    
    /**
     * 거부 처리
     * 
     * @param request 승인 요청
     * @param reviewer 검토자
     * @param reason 거부 사유
     */
    public void reject(ApprovalRequest request, String reviewer, String reason) {
        log.info("Processing rejection for request: {} by {}", 
            request.getRequestId(), reviewer);
        
        transitionTo(request, ApprovalStatus.REJECTED, reviewer, reason);
        
        // 거부 관련 필드 설정
        request.setApproved(false);
        request.setApprovedAt(LocalDateTime.now());
        request.setApprovedBy(reviewer);
        request.setRejectionReason(reason);
    }
    
    /**
     * 만료 처리
     * 
     * @param request 승인 요청
     * @param reason 만료 사유
     */
    public void expire(ApprovalRequest request, String reason) {
        log.info("Processing expiration for request: {}", request.getRequestId());
        
        transitionTo(request, ApprovalStatus.EXPIRED, "system", reason);
        
        // 만료 관련 필드 설정
        request.setApproved(false);
        request.setRejectionReason("Expired: " + reason);
        
        Map<String, Object> metadata = request.getMetadata();
        if (metadata != null) {
            metadata.put("expiredAt", LocalDateTime.now().toString());
            metadata.put("expirationReason", reason);
        }
    }
    
    /**
     * 취소 처리
     * 
     * @param request 승인 요청
     * @param cancelledBy 취소자
     * @param reason 취소 사유
     */
    public void cancel(ApprovalRequest request, String cancelledBy, String reason) {
        log.info("Processing cancellation for request: {} by {}", 
            request.getRequestId(), cancelledBy);
        
        transitionTo(request, ApprovalStatus.CANCELLED, cancelledBy, reason);
        
        // 취소 관련 필드 설정
        request.setApproved(false);
        request.setRejectionReason("Cancelled: " + reason);
        
        Map<String, Object> metadata = request.getMetadata();
        if (metadata != null) {
            metadata.put("cancelledAt", LocalDateTime.now().toString());
            metadata.put("cancelledBy", cancelledBy);
            metadata.put("cancellationReason", reason);
        }
    }
    
    /**
     * 상태 전이 가능 여부 확인
     * 
     * @param fromStatus 현재 상태
     * @param toStatus 목표 상태
     * @return 전이 가능 여부
     */
    public boolean canTransition(ApprovalStatus fromStatus, ApprovalStatus toStatus) {
        if (fromStatus == null || toStatus == null) {
            return false;
        }
        
        Set<ApprovalStatus> allowedTransitions = TRANSITION_RULES.get(fromStatus);
        return allowedTransitions != null && allowedTransitions.contains(toStatus);
    }
    
    /**
     * 현재 상태에서 가능한 다음 상태들 조회
     * 
     * @param currentStatus 현재 상태
     * @return 가능한 다음 상태들
     */
    public Set<ApprovalStatus> getNextAllowedStates(ApprovalStatus currentStatus) {
        if (currentStatus == null) {
            return TRANSITION_RULES.get(ApprovalStatus.PENDING);
        }
        
        Set<ApprovalStatus> allowed = TRANSITION_RULES.get(currentStatus);
        return allowed != null ? new HashSet<>(allowed) : Collections.emptySet();
    }
    
    /**
     * 최종 상태인지 확인
     * 
     * @param status 확인할 상태
     * @return 최종 상태 여부
     */
    public boolean isFinalState(ApprovalStatus status) {
        if (status == null) {
            return false;
        }
        
        Set<ApprovalStatus> nextStates = TRANSITION_RULES.get(status);
        return nextStates == null || nextStates.isEmpty();
    }
    
    /**
     * 상태 전이 검증
     * 
     * @param fromStatus 현재 상태
     * @param toStatus 목표 상태
     * @param requestId 요청 ID (로깅용)
     * @throws IllegalStateException 유효하지 않은 전이인 경우
     */
    private void validateTransition(
            ApprovalStatus fromStatus, 
            ApprovalStatus toStatus,
            String requestId) {
        
        // 동일한 상태로의 전이는 무시
        if (fromStatus == toStatus) {
            log.debug("Same state transition ignored: {} for request: {}", 
                fromStatus, requestId);
            return;
        }
        
        // 전이 가능 여부 확인
        if (!canTransition(fromStatus, toStatus)) {
            String errorMsg = String.format(
                "Invalid state transition: %s -> %s for request: %s", 
                fromStatus, toStatus, requestId
            );
            log.error(errorMsg);
            
            // 상세 정보 로깅
            Set<ApprovalStatus> allowed = getNextAllowedStates(fromStatus);
            log.error("Allowed transitions from {}: {}", fromStatus, allowed);
            
            throw new IllegalStateException(errorMsg);
        }
    }
    
    /**
     * 상태별 특수 처리
     * 
     * @param request 승인 요청
     * @param newStatus 새로운 상태
     * @param actor 행위자
     * @param comment 코멘트
     */
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
                // PENDING으로의 전이는 일반적으로 발생하지 않음
                log.warn("Unusual transition to PENDING for request: {}", 
                    request.getRequestId());
                break;
                
            default:
                log.warn("Unknown status: {} for request: {}", 
                    newStatus, request.getRequestId());
        }
    }
    
    /**
     * 상태 변경 이벤트 발행
     * 
     * @param request 승인 요청
     * @param fromStatus 이전 상태
     * @param toStatus 새로운 상태
     * @param actor 행위자
     * @param comment 코멘트
     */
    private void publishStateChangeEvent(
            ApprovalRequest request,
            ApprovalStatus fromStatus,
            ApprovalStatus toStatus,
            String actor,
            String comment) {
        
        // ApprovalStateChangedEvent 생성 및 발행
        Map<String, Object> eventData = new HashMap<>();
        eventData.put("requestId", request.getRequestId());
        eventData.put("fromStatus", fromStatus.name());
        eventData.put("toStatus", toStatus.name());
        eventData.put("actor", actor);
        eventData.put("comment", comment);
        eventData.put("timestamp", LocalDateTime.now());
        
        log.debug("Publishing state change event: {}", eventData);
        
        // 실제 이벤트 발행은 ApprovalEvent를 사용
        // eventPublisher.publishEvent(new ApprovalStateChangedEvent(...));
    }
    
    /**
     * 승인 요청의 현재 상태 검증
     * 
     * @param request 검증할 승인 요청
     * @return 상태가 유효한지 여부
     */
    public boolean validateCurrentState(ApprovalRequest request) {
        if (request == null || request.getStatus() == null) {
            return false;
        }
        
        ApprovalStatus status = request.getStatus();
        
        // 최종 상태인 경우 추가 검증
        if (isFinalState(status)) {
            switch (status) {
                case APPROVED:
                    // 승인된 경우 승인자와 승인 시간이 있어야 함
                    return request.getApprovedBy() != null && 
                           request.getApprovedAt() != null;
                           
                case REJECTED:
                    // 거부된 경우 거부 사유가 있어야 함
                    return request.getRejectionReason() != null;
                    
                case EXPIRED:
                case CANCELLED:
                    // 만료/취소된 경우 사유가 있어야 함
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