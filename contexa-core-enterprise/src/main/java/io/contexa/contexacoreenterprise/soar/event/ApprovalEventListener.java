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
import org.springframework.transaction.annotation.Transactional;


@Slf4j
@RequiredArgsConstructor
public class ApprovalEventListener {
    
    private final ApprovalService approvalService;
    
    @Autowired
    private ApprovalRequestFactory approvalRequestFactory;
    
    @Autowired
    private ApprovalRequestValidator approvalRequestValidator;
    
    
    @EventListener
    @Transactional
    public void handleApprovalRequested(ApprovalEvent event) {
        if (event.getEventType() != EventType.APPROVAL_REQUESTED) {
            return;
        }
        log.info("ApprovalEvent(APPROVAL_REQUESTED) 수신: {}", event.getRequestId());
        
        try {
            ApprovalRequest request = event.getApprovalRequest();
            
            
            request = approvalRequestFactory.completeFromEvent(request);
            
            
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
            
            
            ApprovalRequest savedRequest = approvalService.saveApprovalRequest(request);
            log.info("승인 요청 DB 저장 완료: requestId={}, dbId={}, status={}",
                savedRequest.getRequestId(), savedRequest.getId(), savedRequest.getStatus());
            
            
            approvalService.sendApprovalNotification(savedRequest);
            log.info("📤 승인 알림 전송 완료: {}", savedRequest.getRequestId());
            
        } catch (Exception e) {
            log.error("승인 요청 처리 실패: {}", event.getRequestId(), e);
            
            throw new RuntimeException("Failed to process approval request: " + event.getRequestId(), e);
        }
    }
    
    
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
        
        
        
    }
    
    
    @EventListener
    public void handleApprovalTimeout(ApprovalEvent event) {
        if (event.getEventType() != EventType.APPROVAL_TIMEOUT) {
            return;
        }
        
        log.warn("승인 타임아웃 발생: {}", event.getRequestId());
        
        try {
            
            String approvalId = event.getRequestId();
            approvalService.handleApprovalResponse(
                approvalId, 
                false,  
                "자동 거부: 승인 타임아웃",
                "system"
            );
            log.info("타임아웃된 승인 요청 자동 거부 처리: {}", approvalId);
        } catch (Exception e) {
            log.error("타임아웃 처리 중 오류: {}", event.getRequestId(), e);
        }
    }
    
    
    @EventListener
    public void handleApprovalCancelled(ApprovalEvent event) {
        if (event.getEventType() != EventType.APPROVAL_CANCELLED) {
            return;
        }
        
        log.info("🚫 승인 취소: {} - 사유: {}", event.getRequestId(), event.getMessage());
        
        try {
            
            String approvalId = event.getRequestId();
            String reason = event.getMessage() != null ? event.getMessage() : "사용자 취소";
            approvalService.handleApprovalResponse(
                approvalId,
                false,  
                "승인 취소: " + reason,
                "system"
            );
            log.info("취소된 승인 요청 처리 완료: {}", approvalId);
        } catch (Exception e) {
            
            log.debug("취소 처리 중 예외 (무시됨): {}", e.getMessage());
        }
    }
    
    
    
    
    
}