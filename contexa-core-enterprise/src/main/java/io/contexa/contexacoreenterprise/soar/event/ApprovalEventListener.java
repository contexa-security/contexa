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
                log.error("ApprovalRequest validation warnings: {}", validationResult.getWarnings());
            }

            approvalService.saveApprovalRequest(request);
            // Notification is handled by McpApprovalNotificationService event listener
                        
        } catch (Exception e) {
            log.error("Approval request processing failed: {}", event.getRequestId(), e);
            
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
        
        log.error("Approval timeout occurred: {}", event.getRequestId());
        
        try {
            
            String approvalId = event.getRequestId();
            approvalService.handleApprovalResponse(
                approvalId, 
                false,  
                "Auto rejected: approval timeout",
                "system"
            );
                    } catch (Exception e) {
            log.error("Error during timeout processing: {}", event.getRequestId(), e);
        }
    }

    @EventListener
    public void handleApprovalCancelled(ApprovalEvent event) {
        if (event.getEventType() != EventType.APPROVAL_CANCELLED) {
            return;
        }

        try {
            
            String approvalId = event.getRequestId();
            String reason = event.getMessage() != null ? event.getMessage() : "User cancelled";
            approvalService.handleApprovalResponse(
                approvalId,
                false,  
                "Approval cancelled: " + reason,
                "system"
            );
                    } catch (Exception e) {
            
                    }
    }

}