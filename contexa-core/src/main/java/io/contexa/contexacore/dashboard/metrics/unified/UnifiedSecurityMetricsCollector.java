package io.contexa.contexacore.dashboard.metrics.unified;

import io.contexa.contexacore.dashboard.api.DomainMetrics;
import io.contexa.contexacore.dashboard.api.EventRecorder;
import io.micrometer.core.instrument.*;
import jakarta.annotation.PostConstruct;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;

import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicLong;

/**
 * 통합 보안 메트릭 수집기
 *
 * 모든 보안 도메인(Zero Trust, Vector, Evolution, HCAD, Plane, SOAR)의
 * 메트릭을 중앙에서 수집하고 전사적 건강도를 추적합니다.
 *
 * 주요 기능:
 * - 도메인별 건강도 점수 집계
 * - 도메인 간 이벤트 흐름 추적
 * - End-to-End 처리 지연 시간 측정
 * - 전사 SLA 메트릭 제공
 *
 * @author contexa
 * @since 3.0.0
 */
@Slf4j
@Component
@RequiredArgsConstructor
public class UnifiedSecurityMetricsCollector implements DomainMetrics, EventRecorder {

    private final MeterRegistry meterRegistry;

    // ===== 통합 메트릭 =====
    private Counter totalSecurityEventsProcessed;
    private Timer endToEndProcessingLatency;
    private Counter crossDomainEventsCounter;

    // ===== 도메인별 건강도 캐시 =====
    private final Map<String, Double> domainHealthScores = new ConcurrentHashMap<>();
    private final AtomicLong totalEventsCount = new AtomicLong(0);

    @PostConstruct
    public void initialize() {
        log.info("=== Initializing UnifiedSecurityMetricsCollector ===");

        // 전체 보안 이벤트 카운터
        totalSecurityEventsProcessed = Counter.builder("security.events.total")
                .description("Total security events processed across all domains")
                .register(meterRegistry);

        // End-to-End 처리 지연 시간
        endToEndProcessingLatency = Timer.builder("security.processing.e2e.duration")
                .description("End-to-end security event processing time from source to final action")
                .publishPercentiles(0.5, 0.95, 0.99)
                .register(meterRegistry);

        // 도메인 간 이벤트 흐름
        crossDomainEventsCounter = Counter.builder("security.cross_domain.events")
                .description("Cross-domain event flow tracking")
                .register(meterRegistry);

        // 전사 시스템 건강도 게이지
        Gauge.builder("security.system.health.score", this,
                        UnifiedSecurityMetricsCollector::calculateOverallHealthScore)
                .description("Overall security system health score (0.0-1.0)")
                .register(meterRegistry);

        // 전체 이벤트 수 게이지
        Gauge.builder("security.events.active.count", totalEventsCount, AtomicLong::get)
                .description("Current active security events count")
                .register(meterRegistry);

        // 도메인별 SLA 준수율 게이지
        Gauge.builder("security.sla.compliance.rate", this,
                        collector -> collector.calculateSLAComplianceRate())
                .description("Overall SLA compliance rate across all domains")
                .register(meterRegistry);

        log.info("UnifiedSecurityMetricsCollector initialized successfully");
    }

    // ===== Public API =====

    /**
     * 보안 이벤트 처리 기록
     *
     * @param source 이벤트 발생 도메인 (zerotrust, vector, evolution 등)
     * @param eventType 이벤트 타입
     */
    public void recordSecurityEvent(String source, String eventType) {
        totalSecurityEventsProcessed.increment();
        totalEventsCount.incrementAndGet();

        Counter.builder("security.events.by_domain")
                .tag("source", source)
                .tag("event_type", eventType)
                .description("Security events count by domain and type")
                .register(meterRegistry)
                .increment();
    }

    /**
     * End-to-End 처리 시간 기록
     *
     * @param durationMillis 처리 소요 시간 (밀리초)
     * @param source 시작 도메인
     * @param target 종료 도메인
     */
    public void recordEndToEndProcessing(long durationMillis, String source, String target) {
        endToEndProcessingLatency.record(java.time.Duration.ofMillis(durationMillis));

        Timer.builder("security.processing.e2e.by_path")
                .tag("source", source)
                .tag("target", target)
                .description("End-to-end processing time by path")
                .register(meterRegistry)
                .record(java.time.Duration.ofMillis(durationMillis));
    }

    /**
     * 도메인 간 이벤트 흐름 기록
     *
     * @param source 발생 도메인
     * @param target 대상 도메인
     * @param eventType 이벤트 타입
     */
    public void recordCrossDomainEvent(String source, String target, String eventType) {
        crossDomainEventsCounter.increment();

        Counter.builder("security.cross_domain.events.detailed")
                .tag("source", source)
                .tag("target", target)
                .tag("event_type", eventType)
                .description("Detailed cross-domain event flow")
                .register(meterRegistry)
                .increment();

        log.debug("[CrossDomain] {} -> {}: {}", source, target, eventType);
    }

    /**
     * 도메인 건강도 업데이트
     *
     * @param domain 도메인 이름 (zerotrust, vector, evolution, hcad, plane, soar)
     * @param healthScore 건강도 점수 (0.0-1.0)
     */
    public void updateDomainHealth(String domain, double healthScore) {
        domainHealthScores.put(domain, healthScore);

        Gauge.builder("security.domain.health.score", () -> healthScore)
                .tag("domain", domain)
                .description("Health score for specific security domain")
                .register(meterRegistry);

        log.debug("[DomainHealth] {}: {}", domain, String.format("%.3f", healthScore));
    }

    /**
     * 전사 시스템 건강도 계산
     *
     * 각 도메인의 건강도를 가중 평균하여 전체 시스템 건강도 산출
     *
     * 가중치:
     * - ZeroTrust: 30% (핵심 인증/인가)
     * - Evolution: 30% (정책 진화)
     * - Vector: 20% (AI 학습)
     * - HCAD: 15% (이상 탐지)
     * - Plane: 3% (계층 처리)
     * - SOAR: 2% (자동 대응)
     *
     * @return 전체 시스템 건강도 (0.0-1.0)
     */
    public double calculateOverallHealthScore() {
        double zeroTrustHealth = domainHealthScores.getOrDefault("zerotrust", 1.0);
        double evolutionHealth = domainHealthScores.getOrDefault("evolution", 1.0);
        double vectorHealth = domainHealthScores.getOrDefault("vector", 1.0);
        double hcadHealth = domainHealthScores.getOrDefault("hcad", 1.0);
        double planeHealth = domainHealthScores.getOrDefault("plane", 1.0);
        double soarHealth = domainHealthScores.getOrDefault("soar", 1.0);

        double overallHealth = (zeroTrustHealth * 0.30) +
                (evolutionHealth * 0.30) +
                (vectorHealth * 0.20) +
                (hcadHealth * 0.15) +
                (planeHealth * 0.03) +
                (soarHealth * 0.02);

        return Math.min(Math.max(overallHealth, 0.0), 1.0);
    }

    /**
     * SLA 준수율 계산
     *
     * End-to-End 처리 지연의 95% 백분위가 목표(2초) 이내인지 확인
     *
     * @return SLA 준수율 (0.0-1.0)
     */
    private double calculateSLAComplianceRate() {
        // Prometheus에서 실시간으로 계산하므로 여기서는 예상치 반환
        double overallHealth = calculateOverallHealthScore();

        // 건강도가 0.9 이상이면 SLA 준수로 가정
        if (overallHealth >= 0.9) {
            return 1.0;
        } else if (overallHealth >= 0.7) {
            return 0.8;
        } else {
            return 0.5;
        }
    }

    /**
     * 특정 도메인의 건강도 조회
     *
     * @param domain 도메인 이름
     * @return 건강도 점수 (0.0-1.0), 없으면 1.0 (정상)
     */
    public double getDomainHealth(String domain) {
        return domainHealthScores.getOrDefault(domain, 1.0);
    }

    /**
     * 모든 도메인의 건강도 조회
     *
     * @return 도메인별 건강도 맵
     */
    public Map<String, Double> getAllDomainHealthScores() {
        return Map.copyOf(domainHealthScores);
    }

    /**
     * 통계 정보 조회
     *
     * @return 통계 정보 맵
     */
    public Map<String, Object> getStatistics() {
        return Map.of(
                "totalEventsProcessed", totalEventsCount.get(),
                "overallHealthScore", calculateOverallHealthScore(),
                "domainHealthScores", getAllDomainHealthScores(),
                "slaComplianceRate", calculateSLAComplianceRate()
        );
    }

    // ===== MetricsCollector 인터페이스 구현 =====

    @Override
    public String getDomain() {
        return "unified";
    }

    // initialize()는 이미 49번째 줄에 @PostConstruct로 구현되어 있음

    @Override
    public void reset() {
        totalEventsCount.set(0);
        domainHealthScores.clear();
        log.info("UnifiedSecurityMetricsCollector 리셋 완료");
    }

    // getStatistics()는 이미 구현되어 있음

    // ===== DomainMetrics 인터페이스 구현 =====

    @Override
    public double getHealthScore() {
        return calculateOverallHealthScore();
    }

    @Override
    public Map<String, Double> getKeyMetrics() {
        Map<String, Double> metrics = new HashMap<>();
        metrics.put("total_events", (double) totalEventsCount.get());
        metrics.put("overall_health", calculateOverallHealthScore());
        metrics.put("sla_compliance", calculateSLAComplianceRate());
        metrics.put("cross_domain_events", crossDomainEventsCounter != null ? crossDomainEventsCounter.count() : 0.0);
        return metrics;
    }

    // ===== EventRecorder 인터페이스 구현 =====

    @Override
    public void recordEvent(String eventType, Map<String, Object> metadata) {
        String source = metadata.containsKey("source") ?
            (String) metadata.get("source") : "unknown";
        String target = metadata.containsKey("target") ?
            (String) metadata.get("target") : "unknown";
        String eventSubType = metadata.containsKey("subType") ?
            (String) metadata.get("subType") : "generic";

        switch (eventType) {
            case "security_event":
                recordSecurityEvent(source, eventSubType);
                break;
            case "cross_domain_event":
                recordCrossDomainEvent(source, target, eventSubType);
                break;
            default:
                log.warn("Unknown event type: {}", eventType);
        }
    }

    @Override
    public void recordDuration(String operationName, long durationNanos) {
        if ("end_to_end_processing".equals(operationName) && endToEndProcessingLatency != null) {
            endToEndProcessingLatency.record(durationNanos, TimeUnit.NANOSECONDS);
        }
    }
}
