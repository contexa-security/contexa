package io.contexa.contexacoreenterprise.dashboard.metrics.unified;

import io.contexa.contexacoreenterprise.dashboard.api.DomainMetrics;
import io.contexa.contexacoreenterprise.dashboard.api.EventRecorder;
import io.contexa.contexacore.domain.entity.SoarIncident;
import io.contexa.contexacore.domain.SoarIncidentStatus;
import io.contexa.contexacore.repository.SoarIncidentRepository;
import io.micrometer.core.instrument.MeterRegistry;
import jakarta.annotation.PostConstruct;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;

import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

@Slf4j
public class SystemMetricsCollector implements DomainMetrics, EventRecorder {

    private final SoarIncidentRepository incidentRepository;
    private final MeterRegistry meterRegistry;

    @Autowired
    public SystemMetricsCollector(SoarIncidentRepository incidentRepository,
                                  @Autowired(required = false) MeterRegistry meterRegistry) {
        this.incidentRepository = incidentRepository;
        this.meterRegistry = meterRegistry;
    }

    @PostConstruct
    public void init() {
        if (meterRegistry != null) {
            
            meterRegistry.gauge("system.health.score", this,
                SystemMetricsCollector::getHealthScore);

            meterRegistry.gauge("system.active.incidents", this,
                metrics -> {
                    Map<String, Object> m = metrics.getSystemMetrics();
                    return ((Number) m.getOrDefault("activeIncidents", 0L)).doubleValue();
                });

            meterRegistry.gauge("system.threat.level", this,
                metrics -> {
                    Map<String, Object> m = metrics.getSystemMetrics();
                    return (double) m.getOrDefault("threatLevel", 0.0);
                });

                    } else {
            log.warn("MeterRegistry가 없어 Prometheus 메트릭 등록을 건너뜁니다");
        }
    }

    public Map<String, Object> getSystemMetrics() {
        Map<String, Object> metrics = new HashMap<>();

        try {
            
            long activeIncidents = countActiveIncidents();
            metrics.put("activeIncidents", activeIncidents);

            double threatLevel = calculateThreatLevel(activeIncidents);
            metrics.put("threatLevel", threatLevel);

            long recentIncidents = countRecentIncidents(24);
            metrics.put("recentIncidents24h", recentIncidents);

            double avgResolutionTime = calculateAverageResolutionTime();
            metrics.put("avgResolutionTimeMinutes", avgResolutionTime);

            Map<String, Double> resourceUsage = getResourceUsage();
            metrics.put("resourceUsage", resourceUsage);

            double eventRate = calculateEventRate();
            metrics.put("eventRatePerMinute", eventRate);

            long failedAuthAttempts = countFailedAuthAttempts();
            metrics.put("failedAuthAttempts", failedAuthAttempts);

            long policyViolations = countPolicyViolations();
            metrics.put("policyViolations", policyViolations);

        } catch (Exception e) {
            log.error("시스템 메트릭 수집 실패", e);
            
            metrics.put("activeIncidents", 0L);
            metrics.put("threatLevel", 0.0);
            metrics.put("error", e.getMessage());
        }

        return metrics;
    }

    private long countActiveIncidents() {
        
        return incidentRepository.findAll().stream()
            .filter(incident -> incident.getStatus() == SoarIncidentStatus.NEW ||
                    incident.getStatus() == SoarIncidentStatus.TRIAGE ||
                    incident.getStatus() == SoarIncidentStatus.INVESTIGATION ||
                    incident.getStatus() == SoarIncidentStatus.PLANNING ||
                    incident.getStatus() == SoarIncidentStatus.PENDING_APPROVAL ||
                    incident.getStatus() == SoarIncidentStatus.EXECUTION ||
                    incident.getStatus() == SoarIncidentStatus.REPORTING)
            .count();
    }

    private long countRecentIncidents(int hours) {
        LocalDateTime since = LocalDateTime.now().minusHours(hours);
        return incidentRepository.findAll().stream()
            .filter(incident -> incident.getCreatedAt() != null &&
                    incident.getCreatedAt().isAfter(since))
            .count();
    }

    private double calculateThreatLevel(long activeIncidents) {
        
        double baseThreat = Math.min(1.0, activeIncidents / 20.0);

        long criticalIncidents = incidentRepository.findAll().stream()
            .filter(incident -> (incident.getStatus() == SoarIncidentStatus.NEW ||
                    incident.getStatus() == SoarIncidentStatus.TRIAGE ||
                    incident.getStatus() == SoarIncidentStatus.INVESTIGATION) &&
                    "CRITICAL".equalsIgnoreCase(incident.getSeverity()))
            .count();

        double criticalWeight = Math.min(0.5, criticalIncidents * 0.1);

        return Math.min(1.0, baseThreat + criticalWeight);
    }

    private double calculateAverageResolutionTime() {
        try {
            
            List<SoarIncident> resolvedIncidents = incidentRepository.findAll().stream()
                .filter(incident -> incident.getStatus() == SoarIncidentStatus.COMPLETED ||
                        incident.getStatus() == SoarIncidentStatus.AUTO_CLOSED ||
                        incident.getStatus() == SoarIncidentStatus.CLOSED_BY_ADMIN)
                .limit(100)
                .toList();

            if (resolvedIncidents.isEmpty()) {
                return 0.0;
            }

            double totalMinutes = resolvedIncidents.stream()
                .filter(incident -> incident.getCreatedAt() != null && incident.getUpdatedAt() != null)
                .mapToDouble(incident -> {
                    long minutes = java.time.Duration.between(
                        incident.getCreatedAt(),
                        incident.getUpdatedAt()
                    ).toMinutes();
                    return minutes;
                })
                .sum();

            return totalMinutes / resolvedIncidents.size();

        } catch (Exception e) {
            log.warn("평균 해결 시간 계산 실패: {}", e.getMessage());
            return 0.0;
        }
    }

    private Map<String, Double> getResourceUsage() {
        Map<String, Double> usage = new HashMap<>();

        Runtime runtime = Runtime.getRuntime();
        long maxMemory = runtime.maxMemory();
        long totalMemory = runtime.totalMemory();
        long freeMemory = runtime.freeMemory();
        long usedMemory = totalMemory - freeMemory;

        double memoryUsage = (double) usedMemory / maxMemory * 100;
        usage.put("memoryUsagePercent", memoryUsage);

        com.sun.management.OperatingSystemMXBean osBean =
            (com.sun.management.OperatingSystemMXBean) java.lang.management.ManagementFactory.getOperatingSystemMXBean();
        double cpuUsage = osBean.getProcessCpuLoad() * 100;
        usage.put("cpuUsagePercent", cpuUsage);

        int threadCount = java.lang.management.ManagementFactory.getThreadMXBean().getThreadCount();
        usage.put("activeThreads", (double) threadCount);

        return usage;
    }

    private double calculateEventRate() {
        try {
            
            LocalDateTime tenMinutesAgo = LocalDateTime.now().minusMinutes(10);
            long eventCount = incidentRepository.findAll().stream()
                .filter(incident -> incident.getCreatedAt() != null &&
                        incident.getCreatedAt().isAfter(tenMinutesAgo))
                .count();

            return eventCount / 10.0;

        } catch (Exception e) {
            log.warn("이벤트 속도 계산 실패: {}", e.getMessage());
            return 0.0;
        }
    }

    private long countFailedAuthAttempts() {
        try {
            LocalDateTime oneHourAgo = LocalDateTime.now().minusHours(1);
            return incidentRepository.findAll().stream()
                .filter(incident -> "AUTHENTICATION_FAILURE".equals(incident.getType()) &&
                        incident.getCreatedAt() != null &&
                        incident.getCreatedAt().isAfter(oneHourAgo))
                .count();
        } catch (Exception e) {
            log.warn("실패한 인증 시도 수 조회 실패: {}", e.getMessage());
            return 0L;
        }
    }

    private long countPolicyViolations() {
        try {
            LocalDateTime oneHourAgo = LocalDateTime.now().minusHours(1);
            return incidentRepository.findAll().stream()
                .filter(incident -> "POLICY_VIOLATION".equals(incident.getType()) &&
                        incident.getCreatedAt() != null &&
                        incident.getCreatedAt().isAfter(oneHourAgo))
                .count();
        } catch (Exception e) {
            log.warn("정책 위반 수 조회 실패: {}", e.getMessage());
            return 0L;
        }
    }

    public Map<String, Object> getMetricsTrend(int hours) {
        Map<String, Object> trend = new HashMap<>();

        try {
            LocalDateTime startTime = LocalDateTime.now().minusHours(hours);

            List<Map<String, Object>> incidentTrend = new ArrayList<>();
            trend.put("incidentTrend", incidentTrend);

            List<Map<String, Object>> threatTrend = calculateThreatTrend(startTime);
            trend.put("threatTrend", threatTrend);

        } catch (Exception e) {
            log.error("메트릭 트렌드 조회 실패", e);
            trend.put("error", e.getMessage());
        }

        return trend;
    }

    private List<Map<String, Object>> calculateThreatTrend(LocalDateTime startTime) {

        return List.of();
    }

    @Override
    public String getDomain() {
        return "system";
    }

    @Override
    public void initialize() {
            }

    @Override
    public Map<String, Object> getStatistics() {
        return getSystemMetrics();
    }

    @Override
    public void reset() {
            }

    @Override
    public double getHealthScore() {
        try {
            
            Map<String, Object> metrics = getSystemMetrics();

            double threatLevel = (double) metrics.getOrDefault("threatLevel", 0.0);
            double healthFromThreat = 1.0 - threatLevel;

            @SuppressWarnings("unchecked")
            Map<String, Double> resourceUsage = (Map<String, Double>)
                metrics.getOrDefault("resourceUsage", new HashMap<String, Double>());
            double memoryUsage = resourceUsage.getOrDefault("memoryUsagePercent", 0.0);
            double resourceAvailability = Math.max(0, 1.0 - (memoryUsage / 100.0));

            long failedAuth = (long) metrics.getOrDefault("failedAuthAttempts", 0L);
            long policyViolations = (long) metrics.getOrDefault("policyViolations", 0L);
            long activeIncidents = (long) metrics.getOrDefault("activeIncidents", 0L);

            double totalIssues = failedAuth + policyViolations + activeIncidents;
            double successRate = totalIssues > 0 ?
                Math.max(0, 1.0 - (totalIssues / 100.0)) : 1.0;

            return healthFromThreat * resourceAvailability * successRate;

        } catch (Exception e) {
            log.warn("시스템 건강도 계산 실패: {}", e.getMessage());
            return 0.5; 
        }
    }

    @Override
    public Map<String, Double> getKeyMetrics() {
        Map<String, Double> keyMetrics = new HashMap<>();

        try {
            Map<String, Object> metrics = getSystemMetrics();

            keyMetrics.put("active_incidents",
                ((Number) metrics.getOrDefault("activeIncidents", 0L)).doubleValue());
            keyMetrics.put("threat_level",
                (double) metrics.getOrDefault("threatLevel", 0.0));
            keyMetrics.put("event_rate_per_minute",
                (double) metrics.getOrDefault("eventRatePerMinute", 0.0));
            keyMetrics.put("avg_resolution_time_minutes",
                (double) metrics.getOrDefault("avgResolutionTimeMinutes", 0.0));

            @SuppressWarnings("unchecked")
            Map<String, Double> resourceUsage = (Map<String, Double>)
                metrics.getOrDefault("resourceUsage", new HashMap<String, Double>());
            keyMetrics.put("memory_usage_percent",
                resourceUsage.getOrDefault("memoryUsagePercent", 0.0));
            keyMetrics.put("cpu_usage_percent",
                resourceUsage.getOrDefault("cpuUsagePercent", 0.0));

            keyMetrics.put("failed_auth_attempts",
                ((Number) metrics.getOrDefault("failedAuthAttempts", 0L)).doubleValue());
            keyMetrics.put("policy_violations",
                ((Number) metrics.getOrDefault("policyViolations", 0L)).doubleValue());

        } catch (Exception e) {
            log.warn("핵심 메트릭 추출 실패: {}", e.getMessage());
        }

        return keyMetrics;
    }

    @Override
    public void recordEvent(String eventType, Map<String, Object> metadata) {
        switch (eventType) {
            case "incident_created":
                                break;
            case "incident_resolved":
                                break;
            case "auth_failure":
                                break;
            case "policy_violation":
                                break;
            case "resource_alert":
                String resourceType = metadata.containsKey("resourceType") ?
                    (String) metadata.get("resourceType") : "unknown";
                double usage = metadata.containsKey("usage") ?
                    ((Number) metadata.get("usage")).doubleValue() : 0.0;
                log.warn("리소스 경고 - {}: {}%", resourceType, usage);
                break;
            default:
                        }
    }

    @Override
    public void recordDuration(String operationName, long durationNanos) {
        if ("metric_collection".equals(operationName)) {
            long durationMs = durationNanos / 1_000_000;
                    } else if ("threat_calculation".equals(operationName)) {
            long durationMs = durationNanos / 1_000_000;
                    }
    }
}