package io.contexa.autoconfigure.properties;

import lombok.Data;
import org.springframework.boot.context.properties.ConfigurationProperties;

/**
 * Contexa 통합 설정 Properties
 *
 * <p>
 * Contexa 프레임워크의 모든 설정을 통합 관리하는 클래스입니다.
 * IDE 자동완성을 지원하며, 계층적 구조로 설정을 관리합니다.
 * </p>
 *
 * @since 0.1.0-ALPHA
 */
@Data
@ConfigurationProperties(prefix = "contexa")
public class ContextaProperties {

    /**
     * Contexa 기능 전체 활성화 여부
     */
    private boolean enabled = true;

    /**
     * HCAD (Hybrid Contextual Anomaly Detection) 설정
     */
    private Hcad hcad = new Hcad();

    /**
     * LLM (Large Language Model) 설정
     */
    private Llm llm = new Llm();

    /**
     * RAG (Retrieval-Augmented Generation) 설정
     */
    private Rag rag = new Rag();

    /**
     * Autonomous Security Plane 설정
     */
    private Autonomous autonomous = new Autonomous();

    /**
     * Simulation 설정
     */
    private Simulation simulation = new Simulation();

    /**
     * Feedback 설정
     */
    private Feedback feedback = new Feedback();

    /**
     * Infrastructure 설정
     */
    private Infrastructure infrastructure = new Infrastructure();

    // ========================================
    // Inner Classes
    // ========================================

    /**
     * HCAD 설정
     */
    @Data
    public static class Hcad {
        /**
         * HCAD 기능 활성화 여부
         */
        private boolean enabled = true;

        /**
         * 유사도 설정
         */
        private Similarity similarity = new Similarity();

        /**
         * 기준선 학습 설정
         */
        private Baseline baseline = new Baseline();

        @Data
        public static class Similarity {
            /**
             * Hot Path 임계값 (기본값: 0.7)
             */
            private double hotPathThreshold = 0.7;

            /**
             * 최소 유사도 임계값
             */
            private double minimalThreshold = 0.8;

            /**
             * 낮은 위험 임계값
             */
            private double lowThreshold = 0.6;

            /**
             * 중간 위험 임계값
             */
            private double mediumThreshold = 0.4;

            /**
             * 높은 위험 임계값
             */
            private double highThreshold = 0.2;
        }

        @Data
        public static class Baseline {
            /**
             * 최소 학습 샘플 수
             */
            private int minSamples = 10;

            /**
             * 기준선 캐시 TTL (초)
             */
            private int cacheTtl = 3600;

            /**
             * 자동 학습 활성화
             */
            private boolean autoLearning = true;
        }
    }

    /**
     * LLM 설정
     */
    @Data
    public static class Llm {
        /**
         * LLM 기능 활성화 여부
         */
        private boolean enabled = true;

        /**
         * Tiered LLM 전략 활성화
         */
        private boolean tieredEnabled = true;

        /**
         * Advisor 활성화
         */
        private boolean advisorEnabled = true;

        /**
         * Pipeline 활성화
         */
        private boolean pipelineEnabled = true;
    }

    /**
     * RAG 설정
     */
    @Data
    public static class Rag {
        /**
         * RAG 기능 활성화 여부
         */
        private boolean enabled = true;

        /**
         * Vector Store 설정
         */
        private VectorStore vectorStore = new VectorStore();

        @Data
        public static class VectorStore {
            /**
             * Vector Store 타입 (pgvector, redis, etc.)
             */
            private String type = "pgvector";

            /**
             * 기본 topK
             */
            private int defaultTopK = 5;

            /**
             * 기본 유사도 임계값
             */
            private double defaultSimilarityThreshold = 0.7;
        }
    }

    /**
     * Autonomous Security Plane 설정
     */
    @Data
    public static class Autonomous {
        /**
         * Autonomous 기능 활성화 여부
         */
        private boolean enabled = true;

        /**
         * 전략 선택 모드 (dynamic, fixed)
         */
        private String strategyMode = "dynamic";

        /**
         * 이벤트 처리 타임아웃 (ms)
         */
        private long eventTimeout = 30000;
    }

    /**
     * Simulation 설정
     */
    @Data
    public static class Simulation {
        /**
         * Simulation 기능 활성화 여부 (기본값: false)
         */
        private boolean enabled = false;

        /**
         * 시뮬레이션 데이터 초기화
         */
        private SimulationData data = new SimulationData();

        @lombok.Data
        public static class SimulationData {
            /**
             * 시뮬레이션 데이터 활성화
             */
            private boolean enabled = false;

            /**
             * 기존 데이터 클리어
             */
            private boolean clearExisting = false;
        }
    }

    /**
     * Feedback 설정
     */
    @Data
    public static class Feedback {
        /**
         * Feedback 기능 활성화 여부
         */
        private boolean enabled = true;

        /**
         * 피드백 수집 간격 (ms)
         */
        private long collectionInterval = 60000;
    }

    /**
     * Infrastructure 설정
     */
    @Data
    public static class Infrastructure {
        /**
         * Redis 설정
         */
        private Redis redis = new Redis();

        /**
         * Kafka 설정
         */
        private Kafka kafka = new Kafka();

        /**
         * OpenTelemetry 설정
         */
        private Observability observability = new Observability();

        @Data
        public static class Redis {
            /**
             * Redis 활성화 여부 (자동 감지)
             */
            private boolean enabled = true;

            /**
             * Redisson 활성화
             */
            private boolean redissonEnabled = false;
        }

        @Data
        public static class Kafka {
            /**
             * Kafka 활성화 여부 (자동 감지)
             */
            private boolean enabled = true;
        }

        @Data
        public static class Observability {
            /**
             * 관찰성 기능 활성화
             */
            private boolean enabled = true;

            /**
             * OpenTelemetry 활성화
             */
            private boolean openTelemetryEnabled = true;
        }
    }
}
