package io.contexa.contexacoreenterprise.soar.event;

import io.contexa.contexacore.domain.ApprovalRequest;
import lombok.Getter;
import org.springframework.context.ApplicationEvent;

import java.util.HashMap;
import java.util.Map;

/**
 * 승인 이벤트
 * 
 * 승인 요청, 승인/거부, 타임아웃 등의 이벤트를 나타냅니다.
 * 순환 참조를 방지하기 위해 이벤트 기반 통신을 사용합니다.
 */
@Getter
public class ApprovalEvent extends ApplicationEvent {
    
    /**
     * 이벤트 타입
     */
    public enum EventType {
        APPROVAL_REQUESTED,    // 승인 요청됨
        APPROVAL_GRANTED,      // 승인됨
        APPROVAL_DENIED,       // 거부됨
        APPROVAL_TIMEOUT,      // 타임아웃
        APPROVAL_CANCELLED,    // 취소됨
        TOOL_EXECUTED,         // 도구 실행됨
        TOOL_FAILED           // 도구 실행 실패
    }
    
    private final EventType eventType;
    private final ApprovalRequest approvalRequest;
    private final String requestId;
    private final String message;
    private final String userId;
    private final Map<String, Object> metadata;
    
    /**
     * 기본 생성자
     */
    public ApprovalEvent(Object source, EventType eventType, ApprovalRequest approvalRequest) {
        super(source);
        this.eventType = eventType;
        this.approvalRequest = approvalRequest;
        this.requestId = approvalRequest != null ? approvalRequest.getRequestId() : null;
        this.message = null;
        this.userId = null;
        this.metadata = new HashMap<>();
    }
    
    /**
     * 전체 생성자
     */
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
    
    /**
     * 승인 요청 이벤트 생성
     */
    public static ApprovalEvent requested(Object source, ApprovalRequest request) {
        return new ApprovalEvent(source, EventType.APPROVAL_REQUESTED, request);
    }
    
    /**
     * 승인 이벤트 생성
     */
    public static ApprovalEvent granted(Object source, String requestId, String userId) {
        return new ApprovalEvent(source, EventType.APPROVAL_GRANTED, requestId, 
            "Approval granted", userId, null);
    }
    
    /**
     * 거부 이벤트 생성
     */
    public static ApprovalEvent denied(Object source, String requestId, String userId, String reason) {
        return new ApprovalEvent(source, EventType.APPROVAL_DENIED, requestId, 
            reason, userId, null);
    }
    
    /**
     * 타임아웃 이벤트 생성
     */
    public static ApprovalEvent timeout(Object source, String requestId) {
        return new ApprovalEvent(source, EventType.APPROVAL_TIMEOUT, requestId, 
            "Approval request timeout", null, null);
    }
    
    /**
     * 도구 실행 이벤트 생성
     */
    public static ApprovalEvent toolExecuted(Object source, String requestId, Map<String, Object> result) {
        return new ApprovalEvent(source, EventType.TOOL_EXECUTED, requestId, 
            "Tool executed successfully", null, result);
    }
    
    /**
     * 도구 실패 이벤트 생성
     */
    public static ApprovalEvent toolFailed(Object source, String requestId, String error) {
        Map<String, Object> metadata = new HashMap<>();
        metadata.put("error", error);
        return new ApprovalEvent(source, EventType.TOOL_FAILED, requestId, 
            "Tool execution failed", null, metadata);
    }
}