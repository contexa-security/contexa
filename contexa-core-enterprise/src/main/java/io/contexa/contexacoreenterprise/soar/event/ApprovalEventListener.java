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

            approvalService.sendApprovalNotification(savedRequest);
                        
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
                    } catch (Exception e) {
            log.error("타임아웃 처리 중 오류: {}", event.getRequestId(), e);
        }
    }

    @EventListener
    public void handleApprovalCancelled(ApprovalEvent event) {
        if (event.getEventType() != EventType.APPROVAL_CANCELLED) {
            return;
        }

        try {
            
            String approvalId = event.getRequestId();
            String reason = event.getMessage() != null ? event.getMessage() : "사용자 취소";
            approvalService.handleApprovalResponse(
                approvalId,
                false,  
                "승인 취소: " + reason,
                "system"
            );
                    } catch (Exception e) {
            
                    }
    }

}