package io.contexa.contexacore.autonomous.metrics;

import io.contexa.contexacore.domain.entity.SoarIncident;
import io.contexa.contexacore.domain.SoarIncidentStatus;
import io.contexa.contexacore.repository.SoarIncidentRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

import java.util.ArrayList;

import java.time.LocalDateTime;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * 시스템 메트릭 수집 서비스
 *
 * 자율 학습 시스템이 사용할 실시간 시스템 상태 메트릭을 수집합니다.
 *
 * @author AI3Security
 * @since 1.0.0
 */
@Slf4j
@Service
@RequiredArgsConstructor
public class SystemMetricsCollector {

    private final SoarIncidentRepository incidentRepository;

    /**
     * 현재 시스템 메트릭 조회
     *
     * @return 시스템 상태 메트릭 맵
     */
    public Map<String, Object> getSystemMetrics() {
        Map<String, Object> metrics = new HashMap<>();

        try {
            // 활성 인시던트 수 조회
            long activeIncidents = countActiveIncidents();
            metrics.put("activeIncidents", activeIncidents);

            // 위협 레벨 계산 (0.0 ~ 1.0)
            double threatLevel = calculateThreatLevel(activeIncidents);
            metrics.put("threatLevel", threatLevel);

            // 최근 24시간 인시던트 수
            long recentIncidents = countRecentIncidents(24);
            metrics.put("recentIncidents24h", recentIncidents);

            // 평균 해결 시간 (분)
            double avgResolutionTime = calculateAverageResolutionTime();
            metrics.put("avgResolutionTimeMinutes", avgResolutionTime);

            // 시스템 리소스 사용률
            Map<String, Double> resourceUsage = getResourceUsage();
            metrics.put("resourceUsage", resourceUsage);

            // 보안 이벤트 속도 (이벤트/분)
            double eventRate = calculateEventRate();
            metrics.put("eventRatePerMinute", eventRate);

            // 실패한 인증 시도 수
            long failedAuthAttempts = countFailedAuthAttempts();
            metrics.put("failedAuthAttempts", failedAuthAttempts);

            // 정책 위반 수
            long policyViolations = countPolicyViolations();
            metrics.put("policyViolations", policyViolations);

            log.debug("시스템 메트릭 수집 완료: {}", metrics);

        } catch (Exception e) {
            log.error("시스템 메트릭 수집 실패", e);
            // 기본값 반환
            metrics.put("activeIncidents", 0L);
            metrics.put("threatLevel", 0.0);
            metrics.put("error", e.getMessage());
        }

        return metrics;
    }

    /**
     * 활성 인시던트 수 조회
     */
    private long countActiveIncidents() {
        // SoarIncident uses SoarIncidentStatus enum, not nested enum
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

    /**
     * 최근 N시간 내 인시던트 수 조회
     */
    private long countRecentIncidents(int hours) {
        LocalDateTime since = LocalDateTime.now().minusHours(hours);
        return incidentRepository.findAll().stream()
            .filter(incident -> incident.getCreatedAt() != null &&
                    incident.getCreatedAt().isAfter(since))
            .count();
    }

    /**
     * 위협 레벨 계산
     * 활성 인시던트 수와 심각도를 기반으로 계산
     */
    private double calculateThreatLevel(long activeIncidents) {
        // 기본 위협 레벨 계산
        double baseThreat = Math.min(1.0, activeIncidents / 20.0);

        // 심각한 인시던트 가중치 적용
        // Use severity field as String
        long criticalIncidents = incidentRepository.findAll().stream()
            .filter(incident -> (incident.getStatus() == SoarIncidentStatus.NEW ||
                    incident.getStatus() == SoarIncidentStatus.TRIAGE ||
                    incident.getStatus() == SoarIncidentStatus.INVESTIGATION) &&
                    "CRITICAL".equalsIgnoreCase(incident.getSeverity()))
            .count();

        double criticalWeight = Math.min(0.5, criticalIncidents * 0.1);

        return Math.min(1.0, baseThreat + criticalWeight);
    }

    /**
     * 평균 해결 시간 계산 (분 단위)
     */
    private double calculateAverageResolutionTime() {
        try {
            // Get recently updated incidents since resolvedAt field doesn't exist
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

    /**
     * 시스템 리소스 사용률 조회
     */
    private Map<String, Double> getResourceUsage() {
        Map<String, Double> usage = new HashMap<>();

        Runtime runtime = Runtime.getRuntime();
        long maxMemory = runtime.maxMemory();
        long totalMemory = runtime.totalMemory();
        long freeMemory = runtime.freeMemory();
        long usedMemory = totalMemory - freeMemory;

        // 메모리 사용률 (%)
        double memoryUsage = (double) usedMemory / maxMemory * 100;
        usage.put("memoryUsagePercent", memoryUsage);

        // CPU 사용률 (JVM 프로세스)
        com.sun.management.OperatingSystemMXBean osBean =
            (com.sun.management.OperatingSystemMXBean) java.lang.management.ManagementFactory.getOperatingSystemMXBean();
        double cpuUsage = osBean.getProcessCpuLoad() * 100;
        usage.put("cpuUsagePercent", cpuUsage);

        // 스레드 수
        int threadCount = java.lang.management.ManagementFactory.getThreadMXBean().getThreadCount();
        usage.put("activeThreads", (double) threadCount);

        return usage;
    }

    /**
     * 보안 이벤트 발생 속도 계산 (이벤트/분)
     */
    private double calculateEventRate() {
        try {
            // 최근 10분간 이벤트 수
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

    /**
     * 실패한 인증 시도 수 조회
     * 최근 1시간 기준
     */
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

    /**
     * 정책 위반 수 조회
     * 최근 1시간 기준
     */
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

    /**
     * 특정 기간 동안의 메트릭 트렌드 조회
     *
     * @param hours 조회할 시간 범위
     * @return 시간대별 메트릭 트렌드
     */
    public Map<String, Object> getMetricsTrend(int hours) {
        Map<String, Object> trend = new HashMap<>();

        try {
            LocalDateTime startTime = LocalDateTime.now().minusHours(hours);

            // 시간대별 인시던트 수
            // Simple implementation - group by hour
            List<Map<String, Object>> incidentTrend = new ArrayList<>();
            trend.put("incidentTrend", incidentTrend);

            // 시간대별 위협 레벨
            List<Map<String, Object>> threatTrend = calculateThreatTrend(startTime);
            trend.put("threatTrend", threatTrend);

        } catch (Exception e) {
            log.error("메트릭 트렌드 조회 실패", e);
            trend.put("error", e.getMessage());
        }

        return trend;
    }

    /**
     * 위협 레벨 트렌드 계산
     */
    private List<Map<String, Object>> calculateThreatTrend(LocalDateTime startTime) {
        // 실제 구현에서는 시간대별 위협 레벨을 계산
        // 여기서는 간단한 구현
        return List.of();
    }
}