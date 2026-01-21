package io.contexa.contexacoreenterprise.soar.event;

import io.contexa.contexacore.domain.ApprovalRequest;
import lombok.Getter;
import org.springframework.context.ApplicationEvent;

import java.util.HashMap;
import java.util.Map;

@Getter
public class ApprovalEvent extends ApplicationEvent {

    public enum EventType {
        APPROVAL_REQUESTED,    
        APPROVAL_GRANTED,      
        APPROVAL_DENIED,       
        APPROVAL_TIMEOUT,      
        APPROVAL_CANCELLED,    
        TOOL_EXECUTED,         
        TOOL_FAILED           
    }
    
    private final EventType eventType;
    private final ApprovalRequest approvalRequest;
    private final String requestId;
    private final String message;
    private final String userId;
    private final Map<String, Object> metadata;

    public ApprovalEvent(Object source, EventType eventType, ApprovalRequest approvalRequest) {
        super(source);
        this.eventType = eventType;
        this.approvalRequest = approvalRequest;
        this.requestId = approvalRequest != null ? approvalRequest.getRequestId() : null;
        this.message = null;
        this.userId = null;
        this.metadata = new HashMap<>();
    }

    public ApprovalEvent(Object source, EventType eventType, String requestId, 
                        String message, String userId, Map<String, Object> metadata) {
        super(source);
        this.eventType = eventType;
        this.approvalRequest = null;
        this.requestId = requestId;
        this.message = message;
        this.userId = userId;
        this.metadata = metadata != null ? metadata : new HashMap<>();
    }

    public static ApprovalEvent requested(Object source, ApprovalRequest request) {
        return new ApprovalEvent(source, EventType.APPROVAL_REQUESTED, request);
    }

    public static ApprovalEvent granted(Object source, String requestId, String userId) {
        return new ApprovalEvent(source, EventType.APPROVAL_GRANTED, requestId, 
            "Approval granted", userId, null);
    }

    public static ApprovalEvent denied(Object source, String requestId, String userId, String reason) {
        return new ApprovalEvent(source, EventType.APPROVAL_DENIED, requestId, 
            reason, userId, null);
    }

    public static ApprovalEvent timeout(Object source, String requestId) {
        return new ApprovalEvent(source, EventType.APPROVAL_TIMEOUT, requestId, 
            "Approval request timeout", null, null);
    }

    public static ApprovalEvent toolExecuted(Object source, String requestId, Map<String, Object> result) {
        return new ApprovalEvent(source, EventType.TOOL_EXECUTED, requestId, 
            "Tool executed successfully", null, result);
    }

    public static ApprovalEvent toolFailed(Object source, String requestId, String error) {
        Map<String, Object> metadata = new HashMap<>();
        metadata.put("error", error);
        return new ApprovalEvent(source, EventType.TOOL_FAILED, requestId, 
            "Tool execution failed", null, metadata);
    }
}