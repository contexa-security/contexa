package io.contexa.contexacore.std.llm.model;

import lombok.Builder;
import lombok.Data;

import java.util.Map;

/**
 * LLM 모델의 메타데이터를 정의하는 디스크립터
 *
 * 각 모델의 특성, 성능 프로파일, 비용 정보 등을 포함하여
 * 동적 모델 선택과 관리를 지원합니다.
 */
@Data
@Builder
public class ModelDescriptor {

    /**
     * 모델 고유 식별자
     * 예: tinyllama:latest, llama3.1:8b-20240229
     */
    private String modelId;

    /**
     * 모델 표시명
     * 예: TinyLlama 1.1B, Claude 3 Opus
     */
    private String displayName;

    /**
     * 모델 제공자
     * 예: ollama, anthropic, openai, huggingface
     */
    private String provider;

    /**
     * 모델이 속하는 계층 (1, 2, 3)
     * 3계층 시스템에서의 위치
     */
    private Integer tier;

    /**
     * 모델 버전
     * 예: 1.1b, 3.5-sonnet, 4.0
     */
    private String version;

    /**
     * 모델 크기 (파라미터 수)
     * 예: 1.1B, 8B, 175B
     */
    private String modelSize;

    /**
     * 모델 기능 및 제한사항
     */
    @Builder.Default
    private ModelCapabilities capabilities = ModelCapabilities.builder().build();

    /**
     * 성능 프로파일
     */
    @Builder.Default
    private PerformanceProfile performance = PerformanceProfile.builder().build();

    /**
     * 비용 프로파일
     */
    @Builder.Default
    private CostProfile cost = CostProfile.builder().build();

    /**
     * 모델별 설정 옵션
     */
    @Builder.Default
    private ModelOptions options = ModelOptions.builder().build();

    /**
     * 추가 메타데이터
     */
    private Map<String, Object> metadata;

    /**
     * 모델 상태
     */
    @Builder.Default
    private ModelStatus status = ModelStatus.AVAILABLE;

    /**
     * 모델 기능 정의
     */
    @Data
    @Builder
    public static class ModelCapabilities {
        @Builder.Default
        private boolean streaming = true;

        @Builder.Default
        private boolean toolCalling = false;

        @Builder.Default
        private boolean functionCalling = false;

        @Builder.Default
        private boolean vision = false;

        @Builder.Default
        private boolean multiModal = false;

        @Builder.Default
        private int maxTokens = 4096;

        @Builder.Default
        private int contextWindow = 4096;

        @Builder.Default
        private boolean supportsSystemMessage = true;

        @Builder.Default
        private int maxOutputTokens = 4096;
    }

    /**
     * 성능 프로파일
     */
    @Data
    @Builder
    public static class PerformanceProfile {
        /**
         * 평균 응답 지연시간 (ms)
         */
        @Builder.Default
        private Integer latency = 1000;

        /**
         * 처리량 레벨 (LOW, MEDIUM, HIGH, VERY_HIGH)
         */
        @Builder.Default
        private ThroughputLevel throughput = ThroughputLevel.MEDIUM;

        /**
         * 최대 동시 요청 수
         */
        @Builder.Default
        private Integer concurrency = 10;

        /**
         * 초당 토큰 처리 속도
         */
        @Builder.Default
        private Integer tokensPerSecond = 100;

        /**
         * 권장 타임아웃 (ms)
         */
        @Builder.Default
        private Integer recommendedTimeout = 30000;

        /**
         * 성능 점수 (0-100)
         */
        @Builder.Default
        private Double performanceScore = 50.0;
    }

    /**
     * 비용 프로파일
     */
    @Data
    @Builder
    public static class CostProfile {
        /**
         * 입력 토큰당 비용 (USD)
         */
        @Builder.Default
        private Double costPerInputToken = 0.0;

        /**
         * 출력 토큰당 비용 (USD)
         */
        @Builder.Default
        private Double costPerOutputToken = 0.0;

        /**
         * 요청당 기본 비용 (USD)
         */
        @Builder.Default
        private Double costPerRequest = 0.0;

        /**
         * 월 구독 비용 (USD)
         */
        private Double monthlySubscription;

        /**
         * 비용 효율성 점수 (0-100)
         */
        @Builder.Default
        private Double costEfficiency = 50.0;
    }

    /**
     * 모델 옵션
     */
    @Data
    @Builder
    public static class ModelOptions {
        /**
         * 기본 Temperature
         */
        @Builder.Default
        private Double temperature = 0.7;

        /**
         * 기본 Top-P
         */
        @Builder.Default
        private Double topP = 0.9;

        /**
         * 기본 Top-K
         */
        private Integer topK;

        /**
         * 반복 패널티
         */
        @Builder.Default
        private Double repetitionPenalty = 1.0;

        /**
         * 시드 (재현성을 위한)
         */
        private Integer seed;

        /**
         * 커스텀 옵션
         */
        private Map<String, Object> customOptions;
    }

    /**
     * 처리량 레벨
     */
    public enum ThroughputLevel {
        LOW(10),           // < 10 requests/sec
        MEDIUM(100),       // 10-100 requests/sec
        HIGH(1000),        // 100-1000 requests/sec
        VERY_HIGH(10000);  // > 1000 requests/sec

        private final int maxRequestsPerSecond;

        ThroughputLevel(int maxRequestsPerSecond) {
            this.maxRequestsPerSecond = maxRequestsPerSecond;
        }

        public int getMaxRequestsPerSecond() {
            return maxRequestsPerSecond;
        }
    }

    /**
     * 모델 상태
     */
    public enum ModelStatus {
        AVAILABLE,      // 사용 가능
        UNAVAILABLE,    // 사용 불가
        LOADING,        // 로딩 중
        ERROR,          // 오류 상태
        MAINTENANCE,    // 유지보수 중
        DEPRECATED      // 폐기 예정
    }

    /**
     * 모델이 특정 tier에 적합한지 확인
     */
    public boolean isSuitableForTier(int tier) {
        return this.tier != null && this.tier == tier;
    }

    /**
     * 모델이 빠른 응답에 적합한지 확인
     */
    public boolean isFastResponse() {
        return performance != null &&
               performance.getLatency() != null &&
               performance.getLatency() < 100;
    }

    /**
     * 모델이 비용 효율적인지 확인
     */
    public boolean isCostEffective() {
        if (cost == null) return true; // 비용 정보가 없으면 무료로 간주

        // 로컬 모델이거나 비용이 매우 낮은 경우
        return (cost.getCostPerInputToken() == 0.0 && cost.getCostPerOutputToken() == 0.0) ||
               (cost.getCostEfficiency() != null && cost.getCostEfficiency() > 70);
    }

    /**
     * 모델이 고급 기능을 지원하는지 확인
     */
    public boolean supportsAdvancedFeatures() {
        return capabilities != null &&
               (capabilities.isToolCalling() ||
                capabilities.isFunctionCalling() ||
                capabilities.isMultiModal());
    }
}