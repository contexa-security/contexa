package io.contexa.contexacore.autonomous.domain;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.LocalDateTime;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * Security Event Context
 *
 * SecurityEvent와 관련된 추가 컨텍스트 정보를 캡슐화하는 도메인 객체입니다.
 * AI 보안 분석 및 자율 학습에 필요한 모든 컨텍스트 정보를 포함합니다.
 *
 * @author contexa
 * @since 3.1.0
 */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class SecurityEventContext {

    /**
     * 원본 보안 이벤트
     */
    private SecurityEvent securityEvent;

    /**
     * 이벤트가 발생한 사용자의 보안 컨텍스트
     */
    private SecurityContext userContext;

    /**
     * 이벤트와 관련된 SOAR 인시던트 ID
     */
    private String incidentId;

    /**
     * 이벤트 처리 상태
     */
    @Builder.Default
    private ProcessingStatus processingStatus = ProcessingStatus.PENDING;

    /**
     * AI 분석 결과
     */
    private AIAnalysisResult aiAnalysisResult;

    /**
     * 이벤트 대응 조치
     */
    @Builder.Default
    private Map<String, Object> responseActions = new HashMap<>();

    /**
     * 학습 메타데이터
     */
    private LearningMetadata learningMetadata;

    /**
     * 이벤트 처리 메트릭
     */
    @Builder.Default
    private ProcessingMetrics processingMetrics = new ProcessingMetrics();

    /**
     * 추가 메타데이터
     */
    @Builder.Default
    private Map<String, Object> metadata = new HashMap<>();

    /**
     * 컨텍스트 생성 시간
     */
    @Builder.Default
    private LocalDateTime createdAt = LocalDateTime.now();

    /**
     * 컨텍스트 업데이트 시간
     */
    @Builder.Default
    private LocalDateTime updatedAt = LocalDateTime.now();

    /**
     * 이벤트 처리 상태 열거형
     */
    public enum ProcessingStatus {
        /**
         * 대기 중
         */
        PENDING,

        /**
         * AI 분석 중
         */
        ANALYZING,

        /**
         * 대응 조치 실행 중
         */
        RESPONDING,

        /**
         * 승인 대기 중
         */
        AWAITING_APPROVAL,

        /**
         * 처리 완료
         */
        COMPLETED,

        /**
         * 처리 실패
         */
        FAILED,

        /**
         * 건너뜀
         */
        SKIPPED
    }

    /**
     * AI 분석 결과
     */
    @Data
    @Builder
    @NoArgsConstructor
    @AllArgsConstructor
    public static class AIAnalysisResult {
        /**
         * 위협 레벨 (0.0 ~ 1.0)
         */
        private double threatLevel;

        /**
         * 신뢰도 점수 (0.0 ~ 1.0)
         */
        private double confidenceScore;

        /**
         * 분석 요약
         */
        private String summary;

        /**
         * 권장 조치
         */
        @Builder.Default
        private Map<String, String> recommendedActions = new HashMap<>();

        /**
         * 탐지된 패턴
         */
        @Builder.Default
        private Map<String, String> detectedPatterns = new HashMap<>();

        /**
         * MITRE ATT&CK 매핑
         */
        @Builder.Default
        private Map<String, String> mitreMapping = new HashMap<>();

        /**
         * 분석 시간 (ms)
         */
        private long analysisTimeMs;

        /**
         * 분석에 사용된 AI 모델
         */
        private String aiModel;

        /**
         * 분석 완료 시간
         */
        @Builder.Default
        private LocalDateTime analyzedAt = LocalDateTime.now();

        /**
         * 신뢰도 점수 getter (호환성)
         */
        public double getConfidence() {
            return confidenceScore;
        }

        /**
         * 분석 타임스탬프 (호환성)
         */
        @Builder.Default
        private LocalDateTime analysisTimestamp = LocalDateTime.now();

        /**
         * 패턴 타입 목록 (호환성)
         */
        private List<String> patternTypes;
    }

    /**
     * 처리 메트릭
     */
    @Data
    @Builder
    @NoArgsConstructor
    @AllArgsConstructor
    public static class ProcessingMetrics {
        /**
         * 탐지 시간 (이벤트 발생 ~ 탐지)
         */
        private Long detectionTimeMs;

        /**
         * 분석 시간 (탐지 ~ AI 분석 완료)
         */
        private Long analysisTimeMs;

        /**
         * 대응 시간 (분석 완료 ~ 대응 조치)
         */
        private Long responseTimeMs;

        /**
         * 전체 처리 시간
         */
        private Long totalTimeMs;

        /**
         * 재시도 횟수
         */
        @Builder.Default
        private int retryCount = 0;

        /**
         * 에러 발생 여부
         */
        @Builder.Default
        private boolean hasError = false;

        /**
         * 에러 메시지
         */
        private String errorMessage;

        /**
         * 처리 노드 ID (분산 환경)
         */
        private String processingNode;
    }

    // === 비즈니스 메서드 ===

    /**
     * 메타데이터 추가
     */
    public void addMetadata(String key, Object value) {
        if (metadata == null) {
            metadata = new HashMap<>();
        }
        metadata.put(key, value);
        updateTimestamp();
    }

    /**
     * 대응 조치 추가
     */
    public void addResponseAction(String action, Object details) {
        if (responseActions == null) {
            responseActions = new HashMap<>();
        }
        responseActions.put(action, details);
        updateTimestamp();
    }

    /**
     * AI 분석 결과 설정
     */
    public void setAiAnalysisResult(AIAnalysisResult result) {
        this.aiAnalysisResult = result;
        if (result != null) {
            this.processingStatus = ProcessingStatus.ANALYZING;
            if (processingMetrics == null) {
                processingMetrics = new ProcessingMetrics();
            }
            processingMetrics.setAnalysisTimeMs(result.getAnalysisTimeMs());
        }
        updateTimestamp();
    }

    /**
     * 처리 상태 업데이트
     */
    public void updateProcessingStatus(ProcessingStatus status) {
        this.processingStatus = status;
        updateTimestamp();
    }

    /**
     * 처리 완료 처리
     */
    public void markAsCompleted() {
        this.processingStatus = ProcessingStatus.COMPLETED;
        if (processingMetrics != null && createdAt != null) {
            processingMetrics.setTotalTimeMs(
                java.time.Duration.between(createdAt, LocalDateTime.now()).toMillis()
            );
        }
        updateTimestamp();
    }

    /**
     * 처리 실패 처리
     */
    public void markAsFailed(String errorMessage) {
        this.processingStatus = ProcessingStatus.FAILED;
        if (processingMetrics == null) {
            processingMetrics = new ProcessingMetrics();
        }
        processingMetrics.setHasError(true);
        processingMetrics.setErrorMessage(errorMessage);
        updateTimestamp();
    }

    /**
     * 고위험 이벤트 여부
     *
     * AI Native: AI 분석 결과 우선 사용
     * securityEvent.isHighRisk() 호출 제거 (deprecated 메서드)
     */
    public boolean isHighRisk() {
        // AI Native: AI 분석 결과 우선 (LLM 판단 결과)
        if (aiAnalysisResult != null) {
            return aiAnalysisResult.getThreatLevel() >= 0.7;
        }
        // Fallback: 사용자 컨텍스트의 RiskLevel 사용
        if (userContext != null) {
            return userContext.getCurrentRiskLevel() == UserSecurityContext.RiskLevel.HIGH ||
                   userContext.getCurrentRiskLevel() == UserSecurityContext.RiskLevel.CRITICAL;
        }
        return false;
    }

    /**
     * 학습 가능 여부
     */
    public boolean isLearnable() {
        return learningMetadata != null && learningMetadata.isLearnable() &&
               processingStatus == ProcessingStatus.COMPLETED &&
               aiAnalysisResult != null && aiAnalysisResult.getConfidenceScore() > 0.7;
    }

    /**
     * 승인 필요 여부
     */
    public boolean requiresApproval() {
        return isHighRisk() &&
               (processingStatus == ProcessingStatus.AWAITING_APPROVAL ||
                processingStatus == ProcessingStatus.ANALYZING);
    }

    /**
     * 이벤트 요약 정보 생성
     */
    public Map<String, Object> getSummary() {
        Map<String, Object> summary = new HashMap<>();

        // 기본 정보
        if (securityEvent != null) {
            summary.put("eventId", securityEvent.getEventId());
            summary.put("eventType", securityEvent.getEventType());
            summary.put("severity", securityEvent.getSeverity());
            summary.put("timestamp", securityEvent.getTimestamp());
        }

        summary.put("incidentId", incidentId);
        summary.put("processingStatus", processingStatus);
        summary.put("isHighRisk", isHighRisk());
        summary.put("requiresApproval", requiresApproval());

        // AI 분석 결과
        if (aiAnalysisResult != null) {
            Map<String, Object> aiSummary = new HashMap<>();
            aiSummary.put("threatLevel", aiAnalysisResult.getThreatLevel());
            aiSummary.put("confidenceScore", aiAnalysisResult.getConfidenceScore());
            aiSummary.put("summary", aiAnalysisResult.getSummary());
            summary.put("aiAnalysis", aiSummary);
        }

        // 처리 메트릭
        if (processingMetrics != null) {
            Map<String, Object> metrics = new HashMap<>();
            metrics.put("totalTimeMs", processingMetrics.getTotalTimeMs());
            metrics.put("hasError", processingMetrics.isHasError());
            metrics.put("retryCount", processingMetrics.getRetryCount());
            summary.put("metrics", metrics);
        }

        // 대응 조치
        if (responseActions != null && !responseActions.isEmpty()) {
            summary.put("responseActionCount", responseActions.size());
        }

        summary.put("createdAt", createdAt);
        summary.put("updatedAt", updatedAt);

        return summary;
    }

    /**
     * 타임스탬프 업데이트
     */
    private void updateTimestamp() {
        this.updatedAt = LocalDateTime.now();
    }

    /**
     * 컨텍스트 병합
     * 다른 컨텍스트의 정보를 현재 컨텍스트에 병합
     */
    public void merge(SecurityEventContext other) {
        if (other == null) {
            return;
        }

        // AI 분석 결과는 최신 것으로 교체
        if (other.getAiAnalysisResult() != null) {
            this.aiAnalysisResult = other.getAiAnalysisResult();
        }

        // 대응 조치 병합
        if (other.getResponseActions() != null) {
            this.responseActions.putAll(other.getResponseActions());
        }

        // 메타데이터 병합
        if (other.getMetadata() != null) {
            this.metadata.putAll(other.getMetadata());
        }

        // 학습 메타데이터는 최신 것으로 교체
        if (other.getLearningMetadata() != null) {
            this.learningMetadata = other.getLearningMetadata();
        }

        updateTimestamp();
    }
}