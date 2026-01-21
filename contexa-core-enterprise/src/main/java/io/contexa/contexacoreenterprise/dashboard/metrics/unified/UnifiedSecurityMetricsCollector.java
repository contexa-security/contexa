package io.contexa.contexacoreenterprise.dashboard.metrics.unified;

import io.contexa.contexacoreenterprise.dashboard.api.DomainMetrics;
import io.contexa.contexacoreenterprise.dashboard.api.EventRecorder;
import io.micrometer.core.instrument.*;
import jakarta.annotation.PostConstruct;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicLong;

@Slf4j
@RequiredArgsConstructor
public class UnifiedSecurityMetricsCollector implements DomainMetrics, EventRecorder {

    private final MeterRegistry meterRegistry;

    private Counter totalSecurityEventsProcessed;
    private Timer endToEndProcessingLatency;
    private Counter crossDomainEventsCounter;

    private final Map<String, Double> domainHealthScores = new ConcurrentHashMap<>();
    private final AtomicLong totalEventsCount = new AtomicLong(0);

    @PostConstruct
    public void initialize() {

        totalSecurityEventsProcessed = Counter.builder("security.events.total")
                .description("Total security events processed across all domains")
                .register(meterRegistry);

        endToEndProcessingLatency = Timer.builder("security.processing.e2e.duration")
                .description("End-to-end security event processing time from source to final action")
                .publishPercentiles(0.5, 0.95, 0.99)
                .register(meterRegistry);

        crossDomainEventsCounter = Counter.builder("security.cross_domain.events")
                .description("Cross-domain event flow tracking")
                .register(meterRegistry);

        Gauge.builder("security.system.health.score", this,
                        UnifiedSecurityMetricsCollector::calculateOverallHealthScore)
                .description("Overall security system health score (0.0-1.0)")
                .register(meterRegistry);

        Gauge.builder("security.events.active.count", totalEventsCount, AtomicLong::get)
                .description("Current active security events count")
                .register(meterRegistry);

        Gauge.builder("security.sla.compliance.rate", this,
                        collector -> collector.calculateSLAComplianceRate())
                .description("Overall SLA compliance rate across all domains")
                .register(meterRegistry);

            }

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

    public void recordEndToEndProcessing(long durationMillis, String source, String target) {
        endToEndProcessingLatency.record(java.time.Duration.ofMillis(durationMillis));

        Timer.builder("security.processing.e2e.by_path")
                .tag("source", source)
                .tag("target", target)
                .description("End-to-end processing time by path")
                .register(meterRegistry)
                .record(java.time.Duration.ofMillis(durationMillis));
    }

    public void recordCrossDomainEvent(String source, String target, String eventType) {
        crossDomainEventsCounter.increment();

        Counter.builder("security.cross_domain.events.detailed")
                .tag("source", source)
                .tag("target", target)
                .tag("event_type", eventType)
                .description("Detailed cross-domain event flow")
                .register(meterRegistry)
                .increment();

            }

    public void updateDomainHealth(String domain, double healthScore) {
        domainHealthScores.put(domain, healthScore);

        Gauge.builder("security.domain.health.score", () -> healthScore)
                .tag("domain", domain)
                .description("Health score for specific security domain")
                .register(meterRegistry);

            }

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

    private double calculateSLAComplianceRate() {
        
        double overallHealth = calculateOverallHealthScore();

        if (overallHealth >= 0.9) {
            return 1.0;
        } else if (overallHealth >= 0.7) {
            return 0.8;
        } else {
            return 0.5;
        }
    }

    public double getDomainHealth(String domain) {
        return domainHealthScores.getOrDefault(domain, 1.0);
    }

    public Map<String, Double> getAllDomainHealthScores() {
        return Map.copyOf(domainHealthScores);
    }

    public Map<String, Object> getStatistics() {
        return Map.of(
                "totalEventsProcessed", totalEventsCount.get(),
                "overallHealthScore", calculateOverallHealthScore(),
                "domainHealthScores", getAllDomainHealthScores(),
                "slaComplianceRate", calculateSLAComplianceRate()
        );
    }

    @Override
    public String getDomain() {
        return "unified";
    }

    @Override
    public void reset() {
        totalEventsCount.set(0);
        domainHealthScores.clear();
            }

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
