package io.contexa.contexacore.autonomous.domain;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.LocalDateTime;
import java.util.HashMap;
import java.util.Map;

/**
 * 학습 메타데이터
 * 
 * SecurityEvent에 추가되는 학습 관련 메타데이터입니다.
 * 이벤트가 학습 가능한지, 어떤 유형의 학습인지, 신뢰도는 얼마인지 등을 포함합니다.
 * 
 * @author contexa
 * @since 1.0.0
 */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class LearningMetadata {
    
    /**
     * 학습 가능 여부
     */
    private boolean isLearnable;
    
    /**
     * 학습 유형
     */
    private LearningType learningType;
    
    /**
     * 학습 컨텍스트
     * 이벤트와 관련된 추가 정보 (예: 대응 조치, 결과, 영향도 등)
     */
    @Builder.Default
    private Map<String, Object> learningContext = new HashMap<>();
    
    /**
     * 신뢰도 점수 (0.0 ~ 1.0)
     * 이 이벤트로부터 학습한 내용의 신뢰도
     */
    private double confidenceScore;
    
    /**
     * 생성한 Lab의 ID
     * 어느 Lab에서 이 메타데이터를 생성했는지 추적
     */
    private String sourceLabId;
    
    /**
     * 학습 우선순위 (1-10)
     * 높을수록 우선적으로 학습
     */
    @Builder.Default
    private int priority = 5;
    
    /**
     * 생성 시간
     */
    @Builder.Default
    private LocalDateTime createdAt = LocalDateTime.now();
    
    /**
     * 관련 인시던트 ID
     */
    private String incidentId;
    
    /**
     * 학습 상태
     */
    @Builder.Default
    private LearningStatus status = LearningStatus.PENDING;
    
    /**
     * 학습 결과 요약
     */
    private String learningSummary;

    /**
     * 이벤트 타입 (문자열 형식)
     */
    private String eventType;

    /**
     * 학습 완료 시간
     */
    private LocalDateTime completedAt;

    /**
     * 패턴 정보 저장
     */
    @Builder.Default
    private Map<String, String> patterns = new HashMap<>();

    /**
     * 결과 정보 저장
     */
    @Builder.Default
    private Map<String, Object> outcomes = new HashMap<>();

    /**
     * 패턴 추가 메소드
     */
    public void addPattern(String key, String value) {
        if (patterns == null) {
            patterns = new HashMap<>();
        }
        patterns.put(key, value);
    }

    /**
     * 결과 추가 메소드
     */
    public void addOutcome(String key, Object value) {
        if (outcomes == null) {
            outcomes = new HashMap<>();
        }
        outcomes.put(key, value);
    }
    
    /**
     * 학습 유형 열거형
     */
    public enum LearningType {
        /**
         * 위협 대응 학습
         * 실시간 위협에 대한 대응 패턴 학습
         */
        THREAT_RESPONSE,
        
        /**
         * 접근 패턴 학습
         * 사용자 접근 패턴 및 권한 사용 학습
         */
        ACCESS_PATTERN,
        
        /**
         * 정책 피드백 학습
         * 정책 적용 후 효과성 피드백 학습
         */
        POLICY_FEEDBACK,
        
        /**
         * 오탐 학습
         * False Positive/Negative 패턴 학습
         */
        FALSE_POSITIVE_LEARNING,
        
        /**
         * 성능 최적화 학습
         * 시스템 성능 패턴 학습
         */
        PERFORMANCE_OPTIMIZATION,
        
        /**
         * 컴플라이언스 학습
         * 규정 준수 패턴 학습
         */
        COMPLIANCE_LEARNING
    }
    
    /**
     * 학습 상태 열거형
     */
    public enum LearningStatus {
        /**
         * 대기 중
         */
        PENDING,
        
        /**
         * 학습 중
         */
        IN_PROGRESS,
        
        /**
         * 학습 완료
         */
        COMPLETED,
        
        /**
         * 학습 실패
         */
        FAILED,
        
        /**
         * 학습 건너뜀
         */
        SKIPPED
    }
    
    /**
     * 학습 가능 여부 판단
     */
    public boolean canLearn() {
        return isLearnable && 
               confidenceScore >= 0.7 && 
               status == LearningStatus.PENDING;
    }
    
    /**
     * 고우선순위 학습 여부
     */
    public boolean isHighPriority() {
        return priority >= 8;
    }
    
    /**
     * 학습 컨텍스트에 값 추가
     */
    public void addContext(String key, Object value) {
        if (learningContext == null) {
            learningContext = new HashMap<>();
        }
        learningContext.put(key, value);
    }
    
    /**
     * 학습 완료 처리
     */
    public void markAsCompleted(String summary) {
        this.status = LearningStatus.COMPLETED;
        this.learningSummary = summary;
    }
    
    /**
     * 학습 실패 처리
     */
    public void markAsFailed(String reason) {
        this.status = LearningStatus.FAILED;
        this.learningSummary = reason;
    }
}