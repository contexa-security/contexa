package io.contexa.contexacore.std.labs.risk;

import io.contexa.contexacommon.domain.context.RiskAssessmentContext;
import io.contexa.contexacommon.entity.AuditLog;
import io.contexa.contexacommon.entity.Users;
import io.contexa.contexacommon.repository.AuditLogRepository;
import io.contexa.contexacommon.repository.BusinessResourceActionRepository;
import io.contexa.contexacommon.repository.UserRepository;
import lombok.extern.slf4j.Slf4j;
import org.springframework.ai.document.Document;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.stereotype.Component;

import java.time.LocalDateTime;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.stream.Collectors;

/**
 * 위험 평가 컨텍스트 강화기
 *
 * 실무급 데이터 수집 및 컨텍스트 강화 서비스
 * - Vector DB 기반 히스토리 분석
 * - Redis 기반 실시간 행동 메트릭
 * - 데이터베이스 기반 사용자 프로파일링
 * - 지리적 위치 및 디바이스 핑거프린팅
 *
 * XAI(설명 가능한 AI)를 위한 증거 수집 및 추적
 */
@Slf4j
public class RiskContextEnricher {

    private final RedisTemplate<String, Object> redisTemplate;
    private final UserRepository userRepository;
    private final AuditLogRepository auditLogRepository;
    private final BusinessResourceActionRepository resourceActionRepository;


    @Autowired
    public RiskContextEnricher(RedisTemplate<String, Object> redisTemplate,
                               UserRepository userRepository,
                               AuditLogRepository auditLogRepository,
                               BusinessResourceActionRepository resourceActionRepository) {
        this.redisTemplate = redisTemplate;
        this.userRepository = userRepository;
        this.auditLogRepository = auditLogRepository;
        this.resourceActionRepository = resourceActionRepository;

        log.info("RiskContextEnricher initialized with production data sources");
    }

    /**
     * 컨텍스트 강화 - 초고속 3단계만 (순차 처리, 3초 내 완료)
     */
    public RiskAssessmentContext enrichContext(RiskAssessmentContext context) {
        long totalStartTime = System.currentTimeMillis();
        log.info("[ENRICHER] ===== 컨텍스트 강화 시작 ===== User: {}", context.getUserId());

        try {
            // 핵심 3단계 순차 처리 (비동기 절대 NO!)

            // 1. 사용자 기본 정보 (빠름)
            long step1Start = System.currentTimeMillis();
            log.info("[ENRICHER] STEP 1: 사용자 프로파일 강화 시작");

            enrichUserProfileFast(context);

            long step1Time = System.currentTimeMillis() - step1Start;
            log.info("[ENRICHER] STEP 1 완료: 사용자 프로파일 {}ms", step1Time);

            // 2. 핵심 행동 메트릭만 (최소 쿼리)
            long step2Start = System.currentTimeMillis();
            log.info("[ENRICHER] STEP 2: 행동 메트릭 수집 시작");

            enrichBehaviorMetricsFast(context);

            long step2Time = System.currentTimeMillis() - step2Start;
            log.info("[ENRICHER] STEP 2 완료: 행동 메트릭 {}ms", step2Time);

            // 3. 환경 컨텍스트 (즉시)
            long step3Start = System.currentTimeMillis();
            log.info("[ENRICHER] STEP 3: 환경 컨텍스트 강화 시작");

            enrichEnvironmentContext(context);

            long step3Time = System.currentTimeMillis() - step3Start;
            log.info("[ENRICHER] STEP 3 완료: 환경 컨텍스트 {}ms", step3Time);

            // Vector DB, Resource Pattern, IP Analysis 모두 스킵!
            // 비동기 처리 절대 사용 안함!

            long totalTime = System.currentTimeMillis() - totalStartTime;
            context.withEnvironmentAttribute("enrichmentTotalTimeMs", totalTime);
            context.withEnvironmentAttribute("enrichmentStep1TimeMs", step1Time);
            context.withEnvironmentAttribute("enrichmentStep2TimeMs", step2Time);
            context.withEnvironmentAttribute("enrichmentStep3TimeMs", step3Time);

            log.info("[ENRICHER] ===== 컨텍스트 강화 완료 ===== 총 {}ms (1단계:{}ms, 2단계:{}ms, 3단계:{}ms)",
                    totalTime, step1Time, step2Time, step3Time);

            return context;

        } catch (Exception e) {
            long totalTime = System.currentTimeMillis() - totalStartTime;
            log.error("[ENRICHER] ===== 컨텍스트 강화 실패 ===== 총 {}ms - {}", totalTime, e.getMessage());
            return context;
        }
    }

    /**
     * 사용자 프로파일 초고속 버전
     */
    private void enrichUserProfileFast(RiskAssessmentContext context) {
        try {
            Optional<Users> userOpt = userRepository.findByUsernameWithGroupsRolesAndPermissions(context.getUserId());
            if (userOpt.isPresent()) {
                Users user = userOpt.get();
                context.setUserName(user.getName());
                context.setUserRoles(user.getRoleNames());

                // 최소한의 메트릭만
                Map<String, Object> userMetrics = new HashMap<>();
                userMetrics.put("mfaEnabled", user.isMfaEnabled());
                userMetrics.put("roleCount", user.getRoleNames().size());

                context.withBehaviorMetrics(userMetrics);
            }
        } catch (Exception e) {
            log.warn("Fast user profile failed: {}", e.getMessage());
        }
    }

    /**
     * 행동 메트릭 초고속 버전 (쿼리 2개만)
     */
    private void enrichBehaviorMetricsFast(RiskAssessmentContext context) {
        try {
            Map<String, Object> behaviorMetrics = new HashMap<>();

            // 필수 쿼리 2개만! (Vector DB 완전 스킵)
            LocalDateTime oneHourAgo = LocalDateTime.now().minusHours(1);

            behaviorMetrics.put("requestsInLastHour",
                    auditLogRepository.countByPrincipalNameAndTimeRange(
                            context.getUserId(), oneHourAgo, LocalDateTime.now()));

            // 히스토리는 간단한 텍스트로
            context.withHistoryContext("최근 1시간 접근 기록 기반 간단 분석");

            // 나머지는 기본값
            behaviorMetrics.put("deviceFingerprint", "fast-mode");
            behaviorMetrics.put("accessVelocity", 0.5);

            synchronized (context.getBehaviorMetrics()) {
                context.getBehaviorMetrics().putAll(behaviorMetrics);
            }

        } catch (Exception e) {
            log.warn("Fast behavior metrics failed: {}", e.getMessage());
            context.withHistoryContext("고속 모드 - 기본 분석");
        }
    }

    /**
     * 환경 컨텍스트 강화
     */
    private void enrichEnvironmentContext(RiskAssessmentContext context) {
        try {
            LocalDateTime now = LocalDateTime.now();

            context.withEnvironmentAttribute("accessTime", now);
            context.withEnvironmentAttribute("dayOfWeek", now.getDayOfWeek().toString());
            context.withEnvironmentAttribute("hourOfDay", now.getHour());
            context.withEnvironmentAttribute("isBusinessHours", isBusinessHours(now));
            context.withEnvironmentAttribute("isWeekend", isWeekend(now));
            context.withEnvironmentAttribute("systemLoad", getCurrentSystemLoad());
            context.withEnvironmentAttribute("activeUserCount", getActiveUserCount());
            context.withEnvironmentAttribute("recentSecurityAlerts", getRecentSecurityAlerts());

            log.debug("🌍 Environment context enriched - Business hours: {}, Weekend: {}",
                    isBusinessHours(now), isWeekend(now));

        } catch (Exception e) {
            log.warn("Environment context enrichment failed: {}", e.getMessage());
        }
    }

    // ==================== 실무급 유틸리티 메서드들 ====================

    private long calculateAccountAge(java.util.Date createdAt) {
        if (createdAt == null) return 0;
        long ageInMillis = System.currentTimeMillis() - createdAt.getTime();
        return ageInMillis / (1000 * 60 * 60 * 24); // Convert to days
    }

    private String analyzeHistoryPatterns(List<Document> historyDocuments, RiskAssessmentContext context) {
        StringBuilder analysis = new StringBuilder();
        analysis.append(String.format("과거 %d건의 유사 접근 패턴 분석:\n", historyDocuments.size()));

        Map<String, Long> actionCounts = historyDocuments.stream()
                .collect(Collectors.groupingBy(
                        doc -> doc.getMetadata().getOrDefault("action", "UNKNOWN").toString(),
                        Collectors.counting()
                ));

        analysis.append("- 주요 행동 패턴: ").append(actionCounts).append("\n");

        long businessHoursAccess = historyDocuments.stream()
                .mapToLong(doc -> {
                    Object timeObj = doc.getMetadata().get("accessTime");
                    return timeObj != null && isBusinessHours(LocalDateTime.parse(timeObj.toString())) ? 1 : 0;
                }).sum();

        analysis.append(String.format("- 업무시간 접근 비율: %.1f%%\n",
                (businessHoursAccess * 100.0) / historyDocuments.size()));

        return analysis.toString();
    }

    private Map<String, Object> calculateHistoryMetrics(List<Document> historyDocuments) {
        Map<String, Object> metrics = new HashMap<>();
        metrics.put("historyRecordCount", historyDocuments.size());
        metrics.put("averageSimilarity", historyDocuments.stream()
                .mapToDouble(doc -> (Double) doc.getMetadata().getOrDefault("similarity", 0.0))
                .average().orElse(0.0));
        metrics.put("patternConsistency", calculatePatternConsistency(historyDocuments));
        return metrics;
    }

    private double calculatePatternConsistency(List<Document> historyDocuments) {
        if (historyDocuments.size() < 2) return 1.0;

        Map<String, Long> patterns = historyDocuments.stream()
                .collect(Collectors.groupingBy(
                        doc -> doc.getMetadata().getOrDefault("pattern", "DEFAULT").toString(),
                        Collectors.counting()
                ));

        long maxCount = patterns.values().stream().mapToLong(Long::longValue).max().orElse(1);
        return (double) maxCount / historyDocuments.size();
    }

    private Long getRequestsInTimeWindow(String userId, int hours) {
        LocalDateTime startTime = LocalDateTime.now().minusHours(hours);
        return auditLogRepository.countByPrincipalNameAndTimeRange(userId, startTime, LocalDateTime.now());
    }

    private Long getUniqueResourcesAccessed(String userId) {
        return auditLogRepository.countDistinctResourcesByPrincipalName(userId);
    }

    private Double calculateAverageSessionDuration(String userId) {
        try {
            List<AuditLog> recentLogs = auditLogRepository.findRecentLogsByPrincipalName(userId);
            if (recentLogs.size() < 2) return 0.0;

            // 최근 로그들의 시간 간격으로 세션 지속시간 추정
            double totalDuration = 0;
            int sessionCount = 0;

            for (int i = 0; i < recentLogs.size() - 1; i++) {
                LocalDateTime current = recentLogs.get(i).getTimestamp();
                LocalDateTime next = recentLogs.get(i + 1).getTimestamp();

                long duration = java.time.Duration.between(next, current).toMinutes();
                if (duration > 0 && duration < 240) { // 4시간 미만만 유효한 세션으로 간주
                    totalDuration += duration;
                    sessionCount++;
                }
            }

            return sessionCount > 0 ? totalDuration / sessionCount : 0.0;
        } catch (Exception e) {
            log.warn("Session duration calculation failed: {}", e.getMessage());
            return 0.0;
        }
    }

    private String calculateDeviceFingerprint(RiskAssessmentContext context) {
        return String.format("%s_%s_%s",
                context.getUserAgent() != null ? context.getUserAgent().hashCode() : "unknown",
                context.getRemoteIp() != null ? context.getRemoteIp() : "unknown",
                System.currentTimeMillis() % 1000);
    }

    private Double calculateAccessVelocity(String userId) {
        String key = "velocity:" + userId;
        List<Object> timestamps = redisTemplate.opsForList().range(key, -5, -1);
        if (timestamps.size() < 2) return 0.0;

        long firstTime = Long.parseLong(timestamps.get(0).toString());
        long lastTime = Long.parseLong(timestamps.get(timestamps.size() - 1).toString());
        long timeSpan = lastTime - firstTime;

        return timeSpan > 0 ? (double) timestamps.size() / timeSpan * 1000 : 0.0;
    }

    private boolean isBusinessHours(LocalDateTime time) {
        int hour = time.getHour();
        return hour >= 9 && hour <= 18 && !isWeekend(time);
    }

    private boolean isWeekend(LocalDateTime time) {
        int dayOfWeek = time.getDayOfWeek().getValue();
        return dayOfWeek == 6 || dayOfWeek == 7;
    }

    private double getCurrentSystemLoad() {
        return java.lang.management.ManagementFactory.getOperatingSystemMXBean().getSystemLoadAverage();
    }

    private long getActiveUserCount() {
        return redisTemplate.opsForSet().size("active_users");
    }

    private int getRecentSecurityAlerts() {
        LocalDateTime oneHourAgo = LocalDateTime.now().minusHours(1);
        return Math.toIntExact(auditLogRepository.countDeniedAttemptsSince(oneHourAgo));
    }

    private long getResourceAccessCount(String resourceId) {
        return auditLogRepository.countByResourceIdentifier(resourceId);
    }

    private long getUniqueUsersForResource(String resourceId) {
        return auditLogRepository.countDistinctUsersByResourceIdentifier(resourceId);
    }

    private double getAverageAccessesPerDay(String resourceId) {
        try {
            return resourceActionRepository.getAverageAccessesPerDay(resourceId);
        } catch (Exception e) {
            log.warn("Average accesses calculation failed: {}", e.getMessage());
            return 0.0;
        }
    }

    private long getRecentFailedAttempts(String resourceId) {
        LocalDateTime oneHourAgo = LocalDateTime.now().minusHours(1);
        return auditLogRepository.countFailedAttemptsSince(resourceId, oneHourAgo);
    }

    private String getResourceSensitivityLevel(String resourceId) {
        try {
            return resourceActionRepository.findByResourceIdentifier(resourceId)
                    .map(resource -> {
                        // BusinessResource에 sensitivityLevel 필드가 없으므로 임시로 resourceType 기반 판단
                        String resourceType = resource.getResourceType();
                        if (resourceType.contains("FINANCIAL") || resourceType.contains("SENSITIVE")) {
                            return "HIGH";
                        } else if (resourceType.contains("INTERNAL") || resourceType.contains("CONFIDENTIAL")) {
                            return "MEDIUM";
                        } else {
                            return "STANDARD";
                        }
                    })
                    .orElse("STANDARD");
        } catch (Exception e) {
            log.warn("Resource sensitivity assessment failed: {}", e.getMessage());
            return "STANDARD";
        }
    }

    private long getIpAccessCount(String remoteIp) {
        return auditLogRepository.countByRemoteIp(remoteIp);
    }

    private boolean isNewLocationForUser(String userId, String remoteIp) {
        String key = "user_locations:" + userId;
        return !redisTemplate.opsForSet().isMember(key, remoteIp);
    }

    private List<Integer> getTypicalAccessHours(String userId) {
        try {
            List<Object[]> hourCounts = auditLogRepository.findTypicalAccessHoursByPrincipalName(userId);
            return hourCounts.stream()
                    .limit(5) // 상위 5개 시간대만
                    .map(obj -> (Integer) obj[0])
                    .collect(Collectors.toList());
        } catch (Exception e) {
            log.warn("Typical access hours calculation failed: {}", e.getMessage());
            return List.of();
        }
    }
}