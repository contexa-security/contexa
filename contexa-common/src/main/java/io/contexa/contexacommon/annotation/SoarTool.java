package io.contexa.contexacommon.annotation;

import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

/**
 * SOAR 도구를 위한 확장 어노테이션
 * Spring AI의 @Tool 어노테이션을 확장하여 SOAR 특화 메타데이터를 추가합니다.
 */
@Target({ElementType.TYPE, ElementType.METHOD})
@Retention(RetentionPolicy.RUNTIME)
public @interface SoarTool {
    /**
     * 도구 이름 (선택적 - 클래스 레벨에서는 사용하지 않음)
     */
    String name() default "";
    
    /**
     * 도구 설명 (선택적 - 클래스 레벨에서는 사용하지 않음)
     */
    String description() default "";
    
    /**
     * 위험도 수준
     */
    RiskLevel riskLevel() default RiskLevel.MEDIUM;
    
    /**
     * 승인 요구사항
     */
    ApprovalRequirement approval() default ApprovalRequirement.AUTO;
    
    /**
     * 필요한 권한 목록
     */
    String[] requiredPermissions() default {};
    
    /**
     * 허용된 환경 목록
     */
    String[] allowedEnvironments() default {"dev", "staging", "prod"};
    
    /**
     * 시간당 최대 실행 횟수
     */
    int maxExecutionsPerHour() default 100;
    
    /**
     * 감사 로깅 필요 여부
     */
    boolean auditRequired() default true;
    
    /**
     * 재시도 가능 여부
     */
    boolean retryable() default true;
    
    /**
     * 최대 재시도 횟수
     */
    int maxRetries() default 3;
    
    /**
     * 타임아웃 (밀리초)
     */
    long timeoutMs() default 30000;
    
    /**
     * 위험도 수준 열거형
     */
    enum RiskLevel {
        LOW(0.2),
        MEDIUM(0.5),
        HIGH(0.7),
        CRITICAL(0.9);
        
        private final double score;
        
        RiskLevel(double score) {
            this.score = score;
        }
        
        public double getScore() {
            return score;
        }
    }
    
    /**
     * 승인 요구사항 열거형
     */
    enum ApprovalRequirement {
        NONE,           // 승인 불필요
        AUTO,           // 자동 승인 가능
        NOTIFICATION,   // 알림만
        REQUIRED,       // 승인 필수
        MULTI_APPROVAL  // 다중 승인 필요
    }
}