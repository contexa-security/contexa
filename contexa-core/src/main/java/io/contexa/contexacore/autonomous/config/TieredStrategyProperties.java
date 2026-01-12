package io.contexa.contexacore.autonomous.config;

import lombok.Data;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Configuration;

/**
 * Tiered Strategy 설정 Properties
 *
 * AI Native v5.1.0: 2-Tier 구조 (Layer1 Contextual + Layer2 Expert)
 * Layer1/Layer2 전략에서 사용하는 하드코딩된 값들을 설정으로 분리합니다.
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
    // AI Native v5.1.0: layer3 필드 삭제 - 시스템은 2-Tier 구조
    private Truncation truncation = new Truncation();
    private Security security = new Security();

    /**
     * Zero Trust 보안 설정 (D1: IP 주소 검증)
     *
     * X-Forwarded-For 헤더 스푸핑 방지를 위한 신뢰 프록시 목록.
     * 이 목록에 있는 IP에서 온 요청만 X-Forwarded-For 헤더를 신뢰합니다.
     *
     * 문제:
     * - X-Forwarded-For는 클라이언트가 임의로 설정 가능
     * - 프록시 체인 검증 없이 첫 번째 IP를 신뢰하면 스푸핑 가능
     *
     * 해결:
     * - request.getRemoteAddr()가 trustedProxies에 있을 때만 X-Forwarded-For 사용
     * - 그 외에는 request.getRemoteAddr() 직접 사용
     */
    @Data
    public static class Security {
        /**
         * 신뢰할 수 있는 프록시 IP 목록
         *
         * 예: ["127.0.0.1", "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"]
         * - 로드 밸런서, 리버스 프록시, API Gateway 등
         * - CIDR 표기법 지원 (예: "10.0.0.0/8")
         *
         * 빈 목록이면 X-Forwarded-For를 사용하지 않음 (가장 안전)
         */
        private java.util.List<String> trustedProxies = java.util.Collections.emptyList();

        /**
         * 신뢰 프록시 검증 활성화 여부
         *
         * - true (기본값): trustedProxies 목록 기반 검증 수행
         * - false: 기존 동작 유지 (X-Forwarded-For 무조건 신뢰) - 개발 환경용
         *
         * 프로덕션에서는 반드시 true로 설정해야 합니다.
         */
        private boolean trustedProxyValidationEnabled = true;
    }

    /**
     * Truncation 정책 설정 (Phase 2-6)
     *
     * LLM 분석에 영향을 주는 데이터 잘림 정책입니다.
     * AI Native v5.1.0: 2-Tier 구조 (Layer1 + Layer2)
     * - Layer1: 성능 우선 (짧은 길이)
     * - Layer2: 균형 (전문가 분석)
     */
    @Data
    public static class Truncation {
        private Layer1Truncation layer1 = new Layer1Truncation();
        private Layer2Truncation layer2 = new Layer2Truncation();
        // AI Native v5.1.0: layer3 삭제 - 시스템은 2-Tier 구조

        @Data
        public static class Layer1Truncation {
            private int userAgent = 150;
            private int payload = 200;
            private int authzReason = 80;
            private int baselineContext = 150;
            private int ragDocument = 300;  // RAG 문서 내용 길이 제한
            // AI Native v5.1.0: source 필드 삭제 - 파일 경로는 LLM 보안 분석에 불필요
        }

        @Data
        public static class Layer2Truncation {
            private int userAgent = 150;
            private int payload = 1000;
            private int ragDocument = 500;
            private int reasoning = 100;
            // AI Native v5.1.0: source 필드 삭제 - 파일 경로는 LLM 보안 분석에 불필요
        }

        // AI Native v5.1.0: Layer3Truncation 삭제 - 시스템은 2-Tier 구조
    }

    @Data
    public static class Layer1 {
        private Monitoring monitoring = new Monitoring();
        private Rag rag = new Rag();
        private Session session = new Session();
        private Cache cache = new Cache();
        private Timeout timeout = new Timeout();
        private Prompt prompt = new Prompt();

        /**
         * AI Native v6.1: 프롬프트 구성 설정
         *
         * Layer1PromptTemplate에서 사용하는 제한값들을 설정으로 분리합니다.
         * 하드코딩된 값들을 외부 설정으로 관리하여 유연성을 확보합니다.
         */
        @Data
        public static class Prompt {
            /**
             * 프롬프트에 포함할 유사 이벤트 최대 수
             * BehaviorAnalysis.similarEvents에서 추출
             */
            private int maxSimilarEvents = 3;

            /**
             * 프롬프트에 포함할 RAG 문서 최대 수
             * relatedDocuments에서 추출
             */
            private int maxRagDocuments = 5;

            /**
             * 이벤트 설명(description) 최대 길이
             * SecurityEvent.description truncation
             */
            private int maxDescriptionLength = 200;

            /**
             * 프롬프트에 포함할 최근 액션 수
             * SessionContext.recentActions에서 추출
             */
            private int maxRecentActions = 5;
        }

        /**
         * AI Native v4.3.0: 타임아웃 설정
         *
         * 259초 처리 시간 문제 해결을 위한 개별 작업 타임아웃.
         * LLM 호출뿐 아니라 Redis, Vector 검색 등 블로킹 가능 작업에도 타임아웃 적용.
         *
         * 기존 문제:
         * - LLM 호출에만 타임아웃 (10초) 적용
         * - Redis SCAN, Vector 검색 등에서 무한 대기 가능
         *
         * 해결:
         * - 전체 분석에 상위 타임아웃 적용
         * - 개별 작업에 하위 타임아웃 적용
         */
        @Data
        public static class Timeout {
            /**
             * 전체 분석 타임아웃 (ms)
             * analyzeWithContext() 전체 실행 시간 제한
             */
            private long totalMs = 15000;

            /**
             * LLM 호출 타임아웃 (ms)
             */
            private long llmMs = 30000;

            /**
             * 벡터 검색 타임아웃 (ms)
             */
            private long vectorSearchMs = 3000;

            /**
             * Redis 작업 타임아웃 (ms)
             */
            private long redisMs = 1000;

            /**
             * Baseline 서비스 타임아웃 (ms)
             */
            private long baselineMs = 2000;
        }

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
            /**
             * 관련 컨텍스트 검색 유사도 임계값
             * searchRelatedContext()에서 사용
             */
            private double similarityThreshold = 0.0;
        }

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

            // AI Native v5.1.0: threatActorLimit, campaignLimit 삭제
            // - findKnownThreatActors(), identifyRelatedCampaigns() 메서드 제거됨
            // - 플랫폼 핵심: "인증된 사용자가 진짜인가?" 검증
            // - 익명 공격자 탐지 (APT, 캠페인)는 플랫폼 역할이 아님
        }
    }

    // AI Native v5.1.0: Layer3 클래스 삭제
    // - 시스템은 현재 2-Tier 구조: Layer1 Contextual + Layer2 Expert
    // - Layer3ExpertStrategy, Layer3PromptTemplate 존재하지 않음
    // - 이 클래스는 데드 코드였음
}
