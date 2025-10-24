package io.contexa.contexacore.autonomous.domain;

import lombok.Builder;
import lombok.Getter;

import java.time.LocalDateTime;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Security Event AI Request
 *
 * 보안 이벤트에 대한 AI 분석 및 처리 요청을 나타내는 도메인 객체입니다.
 * 자율 보안 시스템의 AI 엔진으로 전달되는 요청을 캡슐화합니다.
 *
 * @author AI3Security
 * @since 3.1.0
 */
@Getter
@Builder
public class SecurityEventAIRequest {

    /**
     * 요청 ID
     */
    @Builder.Default
    private final String requestId = UUID.randomUUID().toString();

    /**
     * 요청 생성 시간
     */
    @Builder.Default
    private final LocalDateTime timestamp = LocalDateTime.now();

    /**
     * 보안 이벤트 컨텍스트
     */
    private final SecurityEventContext eventContext;

    /**
     * 사용자 보안 컨텍스트
     */
    private final SecurityContext userContext;

    /**
     * 요청 타입
     */
    @Builder.Default
    private final RequestType requestType = RequestType.ANALYSIS;

    /**
     * 우선순위
     */
    @Builder.Default
    private final RequestPriority priority = RequestPriority.NORMAL;

    /**
     * 분석 목적
     */
    @Builder.Default
    private final AnalysisPurpose analysisPurpose = AnalysisPurpose.THREAT_DETECTION;

    /**
     * AI 모델 선호도
     */
    private final String preferredModel;

    /**
     * 프롬프트 템플릿
     */
    private final String promptTemplate;

    /**
     * 추가 파라미터
     */
    @Builder.Default
    private final Map<String, Object> parameters = new ConcurrentHashMap<>();

    /**
     * 도구 제공자 목록
     */
    @Builder.Default
    private final List<Object> toolProviders = new ArrayList<>();

    /**
     * 스트리밍 필요 여부
     */
    @Builder.Default
    private final boolean streamingRequired = false;

    /**
     * 비동기 처리 여부
     */
    @Builder.Default
    private final boolean asyncProcessing = true;

    /**
     * 타임아웃 (초)
     */
    @Builder.Default
    private final int timeoutSeconds = 300;

    /**
     * 재시도 정책
     */
    @Builder.Default
    private final RetryPolicy retryPolicy = RetryPolicy.builder().build();

    /**
     * 메타데이터
     */
    @Builder.Default
    private final Map<String, Object> metadata = new ConcurrentHashMap<>();

    /**
     * 조직 ID
     */
    private final String organizationId;

    /**
     * 테넌트 ID
     */
    private final String tenantId;

    /**
     * 요청 타입
     */
    public enum RequestType {
        /**
         * 분석 요청
         */
        ANALYSIS("Security event analysis"),

        /**
         * 대응 생성 요청
         */
        RESPONSE_GENERATION("Generate response actions"),

        /**
         * 정책 진화 요청
         */
        POLICY_EVOLUTION("Evolve security policies"),

        /**
         * 학습 요청
         */
        LEARNING("Learning from event"),

        /**
         * 검증 요청
         */
        VALIDATION("Validate security measures"),

        /**
         * 예측 요청
         */
        PREDICTION("Predict future threats"),

        /**
         * 조사 요청
         */
        INVESTIGATION("Deep investigation");

        private final String description;

        RequestType(String description) {
            this.description = description;
        }

        public String getDescription() {
            return description;
        }
    }

    /**
     * 요청 우선순위
     */
    public enum RequestPriority {
        LOW(1, 600),      // 10분 타임아웃
        NORMAL(5, 300),   // 5분 타임아웃
        HIGH(8, 120),     // 2분 타임아웃
        CRITICAL(10, 60); // 1분 타임아웃

        private final int level;
        private final int defaultTimeoutSeconds;

        RequestPriority(int level, int defaultTimeoutSeconds) {
            this.level = level;
            this.defaultTimeoutSeconds = defaultTimeoutSeconds;
        }

        public int getLevel() {
            return level;
        }

        public int getDefaultTimeoutSeconds() {
            return defaultTimeoutSeconds;
        }
    }

    /**
     * 분석 목적
     */
    public enum AnalysisPurpose {
        /**
         * 위협 탐지
         */
        THREAT_DETECTION,

        /**
         * 이상 탐지
         */
        ANOMALY_DETECTION,

        /**
         * 취약점 평가
         */
        VULNERABILITY_ASSESSMENT,

        /**
         * 컴플라이언스 검사
         */
        COMPLIANCE_CHECK,

        /**
         * 포렌식 분석
         */
        FORENSIC_ANALYSIS,

        /**
         * 행동 분석
         */
        BEHAVIORAL_ANALYSIS,

        /**
         * 위험 평가
         */
        RISK_ASSESSMENT,

        /**
         * 패턴 인식
         */
        PATTERN_RECOGNITION
    }

    /**
     * 재시도 정책
     */
    @Getter
    @Builder
    public static class RetryPolicy {
        /**
         * 최대 재시도 횟수
         */
        @Builder.Default
        private final int maxRetries = 3;

        /**
         * 재시도 간격 (밀리초)
         */
        @Builder.Default
        private final long retryIntervalMs = 1000;

        /**
         * 지수 백오프 사용 여부
         */
        @Builder.Default
        private final boolean exponentialBackoff = true;

        /**
         * 최대 재시도 간격 (밀리초)
         */
        @Builder.Default
        private final long maxRetryIntervalMs = 30000;

        /**
         * 재시도 가능한 예외 타입
         */
        @Builder.Default
        private final Set<Class<? extends Exception>> retryableExceptions = new HashSet<>(
            Arrays.asList(
                java.net.SocketTimeoutException.class,
                java.io.IOException.class,
                java.util.concurrent.TimeoutException.class
            )
        );
    }

    // === 비즈니스 메서드 ===

    /**
     * 파라미터 추가
     */
    public SecurityEventAIRequest withParameter(String key, Object value) {
        this.parameters.put(key, value);
        return this;
    }

    /**
     * 파라미터를 타입 안전하게 조회
     */
    public <T> T getParameter(String key, Class<T> type) {
        Object value = parameters.get(key);
        return type.isInstance(value) ? type.cast(value) : null;
    }

    /**
     * 메타데이터 추가
     */
    public SecurityEventAIRequest withMetadata(String key, Object value) {
        this.metadata.put(key, value);
        return this;
    }

    /**
     * 도구 제공자 추가
     */
    public SecurityEventAIRequest withToolProvider(Object toolProvider) {
        this.toolProviders.add(toolProvider);
        return this;
    }

    /**
     * 도구 제공자 목록 추가
     */
    public SecurityEventAIRequest withToolProviders(List<Object> providers) {
        this.toolProviders.addAll(providers);
        return this;
    }

    /**
     * 도구 제공자 존재 여부
     */
    public boolean hasToolProviders() {
        return !toolProviders.isEmpty();
    }

    /**
     * 고위험 요청 여부
     */
    public boolean isHighPriority() {
        return priority == RequestPriority.HIGH || priority == RequestPriority.CRITICAL;
    }

    /**
     * 긴급 요청 여부
     */
    public boolean isCritical() {
        return priority == RequestPriority.CRITICAL;
    }

    /**
     * 실시간 처리 필요 여부
     */
    public boolean requiresRealTimeProcessing() {
        return isCritical() ||
               (eventContext != null && eventContext.isHighRisk()) ||
               analysisPurpose == AnalysisPurpose.THREAT_DETECTION;
    }

    /**
     * 학습 가능 여부
     */
    public boolean isLearnable() {
        return requestType == RequestType.LEARNING ||
               (eventContext != null && eventContext.isLearnable());
    }

    /**
     * 승인 필요 여부
     */
    public boolean requiresApproval() {
        return eventContext != null && eventContext.requiresApproval();
    }

    /**
     * 요청 검증
     */
    public boolean isValid() {
        // 필수 필드 검증
        if (eventContext == null || eventContext.getSecurityEvent() == null) {
            return false;
        }

        // 타임아웃 검증
        if (timeoutSeconds <= 0 || timeoutSeconds > 3600) {
            return false;
        }

        // 재시도 정책 검증
        if (retryPolicy != null && retryPolicy.getMaxRetries() < 0) {
            return false;
        }

        return true;
    }

    /**
     * 요청 요약 정보 생성
     */
    public Map<String, Object> getSummary() {
        Map<String, Object> summary = new HashMap<>();

        summary.put("requestId", requestId);
        summary.put("timestamp", timestamp);
        summary.put("requestType", requestType);
        summary.put("priority", priority);
        summary.put("analysisPurpose", analysisPurpose);

        // 이벤트 정보
        if (eventContext != null) {
            summary.put("eventContext", eventContext.getSummary());
        }

        // 처리 옵션
        Map<String, Object> processingOptions = new HashMap<>();
        processingOptions.put("streamingRequired", streamingRequired);
        processingOptions.put("asyncProcessing", asyncProcessing);
        processingOptions.put("timeoutSeconds", timeoutSeconds);
        processingOptions.put("hasToolProviders", hasToolProviders());
        summary.put("processingOptions", processingOptions);

        // 재시도 정책
        if (retryPolicy != null) {
            Map<String, Object> retryInfo = new HashMap<>();
            retryInfo.put("maxRetries", retryPolicy.getMaxRetries());
            retryInfo.put("exponentialBackoff", retryPolicy.isExponentialBackoff());
            summary.put("retryPolicy", retryInfo);
        }

        summary.put("isHighPriority", isHighPriority());
        summary.put("requiresRealTimeProcessing", requiresRealTimeProcessing());
        summary.put("requiresApproval", requiresApproval());

        return summary;
    }

    /**
     * 실행 컨텍스트 생성
     * AI 엔진 실행에 필요한 모든 컨텍스트 정보를 생성
     */
    public Map<String, Object> buildExecutionContext() {
        Map<String, Object> context = new HashMap<>();

        // 기본 정보
        context.put("requestId", requestId);
        context.put("timestamp", timestamp);
        context.put("organizationId", organizationId);
        context.put("tenantId", tenantId);

        // 이벤트 정보
        if (eventContext != null && eventContext.getSecurityEvent() != null) {
            SecurityEvent event = eventContext.getSecurityEvent();
            Map<String, Object> eventInfo = new HashMap<>();
            eventInfo.put("eventId", event.getEventId());
            eventInfo.put("eventType", event.getEventType());
            eventInfo.put("severity", event.getSeverity());
            eventInfo.put("source", event.getSource());
            eventInfo.put("metadata", event.getMetadata());
            context.put("event", eventInfo);
        }

        // 사용자 컨텍스트
        if (userContext != null) {
            context.put("userContext", userContext.getSummary());
        }

        // AI 분석 컨텍스트
        Map<String, Object> aiContext = new HashMap<>();
        aiContext.put("requestType", requestType);
        aiContext.put("analysisPurpose", analysisPurpose);
        aiContext.put("preferredModel", preferredModel);
        aiContext.put("promptTemplate", promptTemplate);
        context.put("aiContext", aiContext);

        // 파라미터 병합
        context.putAll(parameters);

        // 메타데이터 병합
        if (!metadata.isEmpty()) {
            context.put("metadata", metadata);
        }

        return context;
    }

    @Override
    public String toString() {
        return String.format(
            "SecurityEventAIRequest{id='%s', type=%s, priority=%s, purpose=%s, streaming=%s}",
            requestId, requestType, priority, analysisPurpose, streamingRequired
        );
    }
}