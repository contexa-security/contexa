package io.contexa.contexacore.soar.tool.model;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

/**
 * SOAR Tool Call
 * AI 모델이 요청한 도구 호출 정보
 */
@Getter
@Setter
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class SoarToolCall {
    
    /**
     * 도구 호출 ID (고유 식별자)
     */
    private String id;
    
    /**
     * 도구 이름
     */
    private String name;
    
    /**
     * 도구 인자 (JSON 문자열)
     */
    private String arguments;
    
    /**
     * 도구 타입 (function, method 등)
     */
    @Builder.Default
    private String type = "function";
    
    /**
     * 도구 설명
     */
    private String description;
    
    /**
     * 위험도 레벨
     */
    @Builder.Default
    private String riskLevel = "MEDIUM";
    
    /**
     * 승인 필요 여부
     */
    @Builder.Default
    private boolean approvalRequired = false;
    
    /**
     * 실행 상태
     */
    @Builder.Default
    private ToolCallStatus status = ToolCallStatus.PENDING;
    
    /**
     * 실행 결과
     */
    private String result;
    
    /**
     * 오류 메시지
     */
    private String error;
    
    /**
     * Tool Call 상태
     */
    public enum ToolCallStatus {
        PENDING,       // 대기 중
        APPROVED,      // 승인됨
        REJECTED,      // 거부됨
        EXECUTING,     // 실행 중
        COMPLETED,     // 완료
        FAILED         // 실패
    }
    
    /**
     * 성공 여부 확인
     */
    public boolean isSuccess() {
        return status == ToolCallStatus.COMPLETED && error == null;
    }
    
    /**
     * 실행 가능 여부 확인
     */
    public boolean isExecutable() {
        return status == ToolCallStatus.APPROVED || 
               (status == ToolCallStatus.PENDING && !approvalRequired);
    }
}