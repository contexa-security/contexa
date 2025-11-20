package io.contexa.contexacoreenterprise.soar.event;

import io.contexa.contexacore.domain.ApprovalRequest;
import io.contexa.contexacore.domain.ApprovalRequest.ApprovalStatus;
import io.contexa.contexacore.soar.approval.ApprovalService;
import io.contexa.contexacoreenterprise.soar.approval.ApprovalRequestFactory;
import io.contexa.contexacoreenterprise.soar.approval.ApprovalRequestValidator;
import io.contexa.contexacoreenterprise.soar.event.ApprovalEvent;
import io.contexa.contexacoreenterprise.soar.event.ApprovalEvent.EventType;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.event.EventListener;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Transactional;

/**
 * 승인 이벤트 리스너
 * 
 * ApprovalEventBus에서 발행하는 이벤트를 처리하여
 * 실제 데이터베이스 저장 및 알림 전송을 담당합니다.
 */
@Slf4j
@Component
@RequiredArgsConstructor
public class ApprovalEventListener {
    
    private final ApprovalService approvalService;
    
    @Autowired
    private ApprovalRequestFactory approvalRequestFactory;
    
    @Autowired
    private ApprovalRequestValidator approvalRequestValidator;
    
    /**
     * 승인 요청 이벤트 처리
     * 
     * ApprovalEvent를 받아서 데이터베이스에 저장하고
     * 사용자에게 알림을 전송합니다.
     * 
     * @param event 승인 이벤트
     */
    @EventListener
    @Transactional
    public void handleApprovalRequested(ApprovalEvent event) {
        if (event.getEventType() != EventType.APPROVAL_REQUESTED) {
            return;
        }
        log.info("ApprovalEvent(APPROVAL_REQUESTED) 수신: {}", event.getRequestId());
        
        try {
            ApprovalRequest request = event.getApprovalRequest();
            
            // Factory를 사용하여 필수 필드 완성
            request = approvalRequestFactory.completeFromEvent(request);
            
            // Validator를 사용하여 검증
            ApprovalRequestValidator.ValidationResult validationResult = 
                approvalRequestValidator.validateAndSanitize(request);
            
            if (!validationResult.isValid()) {
                log.error("ApprovalRequest validation failed: {}", validationResult.getErrors());
                throw new IllegalArgumentException("Invalid ApprovalRequest: " + 
                    String.join(", ", validationResult.getErrors()));
            }
            
            if (validationResult.hasWarnings()) {
                log.warn("ApprovalRequest validation warnings: {}", validationResult.getWarnings());
            }
            
            // DB에 승인 요청 저장
            ApprovalRequest savedRequest = approvalService.saveApprovalRequest(request);
            log.info("승인 요청 DB 저장 완료: requestId={}, dbId={}, status={}",
                savedRequest.getRequestId(), savedRequest.getId(), savedRequest.getStatus());
            
            // 알림 전송
            approvalService.sendApprovalNotification(savedRequest);
            log.info("📤 승인 알림 전송 완료: {}", savedRequest.getRequestId());
            
        } catch (Exception e) {
            log.error("승인 요청 처리 실패: {}", event.getRequestId(), e);
            // 예외를 다시 던져서 트랜잭션 롤백
            throw new RuntimeException("Failed to process approval request: " + event.getRequestId(), e);
        }
    }
    
    /**
     * 승인 완료 이벤트 처리 (승인/거부)
     * 
     * @param event 승인 이벤트
     */
    @EventListener
    public void handleApprovalCompleted(ApprovalEvent event) {
        if (event.getEventType() != EventType.APPROVAL_GRANTED && 
            event.getEventType() != EventType.APPROVAL_DENIED) {
            return;
        }
        
        boolean isApproved = event.getEventType() == EventType.APPROVAL_GRANTED;
        log.info("ApprovalEvent({}) 수신: {}",
            event.getEventType(), 
            event.getRequestId());
        
        // 추가 처리가 필요한 경우 여기에 구현
        // 예: 감사 로그 기록, 메트릭 업데이트 등
    }
    
    /**
     * 승인 타임아웃 이벤트 처리
     * 
     * @param event 타임아웃 이벤트
     */
    @EventListener
    public void handleApprovalTimeout(ApprovalEvent event) {
        if (event.getEventType() != EventType.APPROVAL_TIMEOUT) {
            return;
        }
        
        log.warn("승인 타임아웃 발생: {}", event.getRequestId());
        
        try {
            // 타임아웃된 요청을 자동 거부 처리
            String approvalId = event.getRequestId();
            approvalService.handleApprovalResponse(
                approvalId, 
                false,  // 거부
                "자동 거부: 승인 타임아웃",
                "system"
            );
            log.info("타임아웃된 승인 요청 자동 거부 처리: {}", approvalId);
        } catch (Exception e) {
            log.error("타임아웃 처리 중 오류: {}", event.getRequestId(), e);
        }
    }
    
    /**
     * 승인 취소 이벤트 처리
     * 
     * @param event 취소 이벤트
     */
    @EventListener
    public void handleApprovalCancelled(ApprovalEvent event) {
        if (event.getEventType() != EventType.APPROVAL_CANCELLED) {
            return;
        }
        
        log.info("🚫 승인 취소: {} - 사유: {}", event.getRequestId(), event.getMessage());
        
        try {
            // 취소된 요청 처리
            String approvalId = event.getRequestId();
            String reason = event.getMessage() != null ? event.getMessage() : "사용자 취소";
            approvalService.handleApprovalResponse(
                approvalId,
                false,  // 거부
                "승인 취소: " + reason,
                "system"
            );
            log.info("취소된 승인 요청 처리 완료: {}", approvalId);
        } catch (Exception e) {
            // 이미 처리된 요청이거나 찾을 수 없는 경우 무시
            log.debug("취소 처리 중 예외 (무시됨): {}", e.getMessage());
        }
    }
    
    /**
     * 대량 취소 이벤트 처리 (현재는 구현 생략)
     * 필요시 추가 구현 가능
     */
    // 대량 취소는 현재 ApprovalEvent에 정의되지 않음
    // 필요하면 추후 추가 가능
    /*
    @EventListener
    public void handleBulkCancelled(ApprovalEvent event) {
        // 구현 필요시 추가
        
        // 시스템 종료나 리셋 시 처리할 로직
        // 예: 모든 PENDING 상태 요청들을 CANCELLED로 변경
    }
    */
}