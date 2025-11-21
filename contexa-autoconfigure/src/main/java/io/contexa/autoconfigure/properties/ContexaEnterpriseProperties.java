package io.contexa.autoconfigure.properties;

import lombok.Data;
import org.springframework.boot.context.properties.ConfigurationProperties;

/**
 * Contexa Enterprise 설정 Properties
 *
 * <p>
 * Enterprise 기능에 대한 설정을 관리합니다.
 * Enterprise Starter 사용 시에만 활성화됩니다.
 * </p>
 *
 * @since 0.1.0-ALPHA
 */
@Data
@ConfigurationProperties(prefix = "contexa.enterprise")
public class ContexaEnterpriseProperties {

    /**
     * Enterprise 기능 전체 활성화 여부 (기본값: false)
     */
    private boolean enabled = false;

    /**
     * Policy Evolution 설정
     */
    private Evolution evolution = new Evolution();

    /**
     * AI Intelligence 설정
     */
    private Intelligence intelligence = new Intelligence();

    /**
     * MCP (Model Context Protocol) 설정
     */
    private Mcp mcp = new Mcp();

    /**
     * SOAR (Security Orchestration, Automation and Response) 설정
     */
    private Soar soar = new Soar();

    /**
     * Dashboard & Metrics 설정
     */
    private Dashboard dashboard = new Dashboard();

    /**
     * Notification 설정
     */
    private Notification notification = new Notification();

    /**
     * Scheduler 설정
     */
    private Scheduler scheduler = new Scheduler();

    // ========================================
    // Inner Classes
    // ========================================

    /**
     * Policy Evolution 설정
     */
    @Data
    public static class Evolution {
        /**
         * Policy Evolution 활성화
         */
        private boolean enabled = true;

        /**
         * 진화 임계값
         */
        private double threshold = 0.75;

        /**
         * 최소 학습 샘플 수
         */
        private int minSamples = 10;

        /**
         * 정책 보존 기간 (일)
         */
        private int retentionDays = 90;
    }

    /**
     * AI Intelligence 설정
     */
    @Data
    public static class Intelligence {
        /**
         * AI Tuning 활성화
         */
        private boolean tuningEnabled = true;

        /**
         * XAI Reporting 활성화
         */
        private boolean xaiReportingEnabled = true;
    }

    /**
     * MCP 설정
     */
    @Data
    public static class Mcp {
        /**
         * MCP 통합 활성화
         */
        private boolean enabled = true;

        /**
         * Tool Execution 설정
         */
        private ToolExecution toolExecution = new ToolExecution();

        @Data
        public static class ToolExecution {
            /**
             * Tool Execution 활성화
             */
            private boolean enabled = true;

            /**
             * 타임아웃 (ms)
             */
            private long timeout = 30000;

            /**
             * 재시도 횟수
             */
            private int retryCount = 3;
        }
    }

    /**
     * SOAR 설정
     */
    @Data
    public static class Soar {
        /**
         * SOAR 기능 활성화
         */
        private boolean enabled = true;

        /**
         * Approval 설정
         */
        private Approval approval = new Approval();

        @Data
        public static class Approval {
            /**
             * 승인 기능 활성화
             */
            private boolean enabled = true;

            /**
             * 승인 타임아웃 (ms)
             */
            private long timeout = 300000;

            /**
             * 자동 승인 활성화
             */
            private boolean autoApprove = false;
        }
    }

    /**
     * Dashboard 설정
     */
    @Data
    public static class Dashboard {
        /**
         * Dashboard 활성화
         */
        private boolean enabled = true;

        /**
         * 메트릭 수집 간격 (ms)
         */
        private long metricsInterval = 60000;

        /**
         * 이벤트 기록 활성화
         */
        private boolean eventRecordingEnabled = true;
    }

    /**
     * Notification 설정
     */
    @Data
    public static class Notification {
        /**
         * Notification 활성화
         */
        private boolean enabled = true;

        /**
         * Slack 알림 활성화
         */
        private boolean slackEnabled = false;

        /**
         * SMS 알림 활성화
         */
        private boolean smsEnabled = false;

        /**
         * Email 알림 활성화
         */
        private boolean emailEnabled = true;
    }

    /**
     * Scheduler 설정
     */
    @Data
    public static class Scheduler {
        /**
         * Scheduler 활성화
         */
        private boolean enabled = true;

        /**
         * Policy Evolution Scheduler 활성화
         */
        private boolean policyEvolutionEnabled = true;

        /**
         * Static Analysis Scheduler 활성화
         */
        private boolean staticAnalysisEnabled = true;

        /**
         * Vector Learning Scheduler 활성화
         */
        private boolean vectorLearningEnabled = true;
    }
}
