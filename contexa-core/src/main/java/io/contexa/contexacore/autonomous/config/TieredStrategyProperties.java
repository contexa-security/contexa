package io.contexa.contexacore.autonomous.config;

import lombok.Data;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Configuration;

/**
 * Tiered Strategy 설정 Properties
 *
 * Layer1/Layer2/Layer3 전략에서 사용하는 하드코딩된 값들을 설정으로 분리합니다.
 * AI Native 원칙에 따라 플랫폼이 임계값을 강제하지 않으며,
 * 이 값들은 모니터링/로깅/캐시 관리 목적으로만 사용됩니다.
 *
 * @author contexa
 * @since 1.0
 */
@Data
@Configuration
@ConfigurationProperties(prefix = "spring.ai.security.tiered")
public class TieredStrategyProperties {

    private Layer1 layer1 = new Layer1();
    private Layer2 layer2 = new Layer2();
    private Layer3 layer3 = new Layer3();
    private Truncation truncation = new Truncation();

    /**
     * Truncation 정책 설정 (Phase 2-6)
     *
     * LLM 분석에 영향을 주는 데이터 잘림 정책입니다.
     * Layer별로 성능과 정확도의 균형을 고려하여 설정합니다.
     * - Layer1: 성능 우선 (짧은 길이)
     * - Layer2: 균형
     * - Layer3: 정확도 우선 (긴 길이)
     */
    @Data
    public static class Truncation {
        private Layer1Truncation layer1 = new Layer1Truncation();
        private Layer2Truncation layer2 = new Layer2Truncation();
        private Layer3Truncation layer3 = new Layer3Truncation();

        @Data
        public static class Layer1Truncation {
            private int userAgent = 150;
            private int payload = 200;
            private int authzReason = 80;
            private int baselineContext = 150;
        }

        @Data
        public static class Layer2Truncation {
            private int userAgent = 150;
            private int payload = 1000;
            private int ragDocument = 500;
            private int reasoning = 100;
            private int source = 20;
        }

        @Data
        public static class Layer3Truncation {
            private int userAgent = 200;
            private int payload = 500;
            private int iocMatches = 256;
            private int campaigns = 100;
            private int vulnerabilities = 150;
            private int reasoning = 100;
            private int compliance = 50;
        }
    }

    @Data
    public static class Layer1 {
        private Monitoring monitoring = new Monitoring();
        private Rag rag = new Rag();

        @Data
        public static class Monitoring {
            /**
             * 높은 위험도 임계값 (모니터링 로그용, 의사결정에 사용 금지)
             * validateDataConsistency()에서 경고 로그 출력 기준
             */
            private double highRiskThreshold = 0.7;

            /**
             * 낮은 신뢰도 임계값 (모니터링 로그용, 의사결정에 사용 금지)
             * validateDataConsistency()에서 경고 로그 출력 기준
             */
            private double lowConfidenceThreshold = 0.3;

            /**
             * 낮은 위험도 임계값 (모니터링 로그용, 의사결정에 사용 금지)
             * validateDataConsistency()에서 경고 로그 출력 기준
             */
            private double lowRiskThreshold = 0.3;
        }

        @Data
        public static class Rag {
            // 기존 @Value로 설정된 값들은 유지 (중복 방지)
            // spring.ai.security.tiered.layer1.rag.top-k
            // spring.ai.security.tiered.layer1.rag.similarity-threshold
        }
    }

    @Data
    public static class Layer2 {
        private Session session = new Session();
        private Rag rag = new Rag();
        private Cache cache = new Cache();

        @Data
        public static class Session {
            /**
             * 세션 내 최대 액션 수 (캐시 관리용)
             * recentActions 리스트 크기 제한
             */
            private int maxRecentActions = 100;
        }

        @Data
        public static class Cache {
            /**
             * 세션 컨텍스트 캐시 최대 크기
             */
            private int maxSize = 1000;

            /**
             * 세션 컨텍스트 캐시 TTL (분)
             * 마지막 접근 후 이 시간이 지나면 자동 제거
             */
            private int ttlMinutes = 30;
        }

        @Data
        public static class Rag {
            /**
             * 관련 컨텍스트 검색 유사도 임계값
             * searchRelatedContext()에서 사용
             */
            private double similarityThreshold = 0.0;
        }
    }

    @Data
    public static class Layer3 {
        private Rag rag = new Rag();

        @Data
        public static class Rag {
            /**
             * 위협 액터 검색 결과 최대 개수
             * findKnownThreatActors()에서 사용
             */
            private int threatActorLimit = 5;

            /**
             * 캠페인 검색 결과 최대 개수
             * identifyRelatedCampaigns()에서 사용
             */
            private int campaignLimit = 5;

            // 기존 @Value로 설정된 값들은 유지 (중복 방지)
            // spring.ai.security.tiered.layer3.rag.top-k
            // spring.ai.security.tiered.layer3.rag.threat-actor-similarity-threshold
            // spring.ai.security.tiered.layer3.rag.campaign-similarity-threshold
        }
    }
}
