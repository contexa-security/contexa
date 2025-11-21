package io.contexa.contexacore.simulation.service;

import io.contexa.contexacore.domain.entity.AttackResult;
import lombok.Builder;
import lombok.Data;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.data.redis.core.StringRedisTemplate;

import java.time.Duration;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicLong;
import java.util.stream.Collectors;

/**
 * 시뮬레이션 통계 서비스
 *
 * 실시간으로 공격 시뮬레이션의 통계를 수집, 집계 및 제공합니다.
 * Redis를 사용하여 분산 환경에서도 정확한 통계를 유지합니다.
 */
@Slf4j
@RequiredArgsConstructor
public class SimulationStatisticsService {

    private final RedisTemplate<String, Object> redisTemplate;
    private final StringRedisTemplate stringRedisTemplate;

    // Redis 키 접두사
    private static final String STATS_PREFIX = "simulation:stats:";
    private static final String COUNTER_PREFIX = "simulation:counter:";
    private static final String TIMELINE_PREFIX = "simulation:timeline:";
    private static final String ATTACK_LOG_PREFIX = "simulation:attacks:";

    // 인메모리 캐시 (빠른 읽기용)
    private final Map<String, AtomicLong> localCounters = new ConcurrentHashMap<>();
    private final Map<String, AttackStatistics> attackTypeStats = new ConcurrentHashMap<>();
    private volatile SimulationStatistics cachedStatistics;
    private volatile long cacheLastUpdated = 0;
    private static final long CACHE_TTL_MS = 5000; // 5초 캐시

    /**
     * 공격 시도 기록
     */
    public void recordAttackAttempt(AttackResult result) {
        try {
            String dateKey = LocalDateTime.now().format(DateTimeFormatter.ISO_LOCAL_DATE);

            // 1. 전체 카운터 증가
            incrementCounter("total_attacks");
            incrementCounter("total_attacks:" + dateKey);

            // 2. 공격 유형별 카운터
            String attackType = result.getType().name();
            incrementCounter("attack_type:" + attackType);
            incrementCounter("attack_type:" + attackType + ":" + dateKey);

            // 3. 성공/실패 카운터
            if (result.isSuccessful()) {
                incrementCounter("successful_attacks");
                incrementCounter("successful_attacks:" + dateKey);
            } else {
                incrementCounter("failed_attacks");
                incrementCounter("failed_attacks:" + dateKey);
            }

            // 4. 탐지 여부
            if (result.isDetected()) {
                incrementCounter("detected_attacks");
                incrementCounter("detected_attacks:" + dateKey);
            }

            // 5. 차단 여부
            if (result.isBlocked()) {
                incrementCounter("blocked_attacks");
                incrementCounter("blocked_attacks:" + dateKey);
            }

            // 6. 위험 수준별 분류
            String riskLevel = calculateRiskLevel(result.getRiskScore());
            incrementCounter("risk_level:" + riskLevel);

            // 7. 타겟 사용자별 통계
            if (result.getTargetUser() != null) {
                incrementCounter("target_user:" + result.getTargetUser());
            }

            // 8. 캠페인별 통계
            if (result.getCampaignId() != null) {
                incrementCounter("campaign:" + result.getCampaignId());
            }

            // 9. 타임라인 기록
            recordToTimeline(result);

            // 10. 상세 공격 로그 저장
            saveAttackLog(result);

            // 캐시 무효화
            invalidateCache();

            log.debug("Attack attempt recorded: {} - Success: {}, Detected: {}, Blocked: {}",
                attackType, result.isSuccessful(), result.isDetected(), result.isBlocked());

        } catch (Exception e) {
            log.error("Failed to record attack attempt", e);
        }
    }

    /**
     * 현재 통계 조회
     */
    public SimulationStatistics getStatistics() {
        // 캐시 확인
        if (cachedStatistics != null &&
            System.currentTimeMillis() - cacheLastUpdated < CACHE_TTL_MS) {
            return cachedStatistics;
        }

        // 새로운 통계 생성
        SimulationStatistics stats = buildStatistics();

        // 캐시 업데이트
        cachedStatistics = stats;
        cacheLastUpdated = System.currentTimeMillis();

        return stats;
    }

    /**
     * 특정 기간의 통계 조회
     */
    public SimulationStatistics getStatisticsForPeriod(LocalDateTime from, LocalDateTime to) {
        SimulationStatistics stats = SimulationStatistics.builder()
            .timestamp(LocalDateTime.now())
            .periodStart(from)
            .periodEnd(to)
            .build();

        // 기간 내의 날짜들 계산
        List<String> dateKeys = new ArrayList<>();
        LocalDateTime current = from;
        while (!current.isAfter(to)) {
            dateKeys.add(current.format(DateTimeFormatter.ISO_LOCAL_DATE));
            current = current.plusDays(1);
        }

        // 각 날짜의 통계 집계
        long totalAttacks = 0;
        long successfulAttacks = 0;
        long detectedAttacks = 0;
        long blockedAttacks = 0;

        for (String dateKey : dateKeys) {
            totalAttacks += getCounterValue("total_attacks:" + dateKey);
            successfulAttacks += getCounterValue("successful_attacks:" + dateKey);
            detectedAttacks += getCounterValue("detected_attacks:" + dateKey);
            blockedAttacks += getCounterValue("blocked_attacks:" + dateKey);
        }

        stats.setTotalAttacks(totalAttacks);
        stats.setSuccessfulAttacks(successfulAttacks);
        stats.setFailedAttacks(totalAttacks - successfulAttacks);
        stats.setDetectedAttacks(detectedAttacks);
        stats.setBlockedAttacks(blockedAttacks);

        // 계산된 메트릭
        if (totalAttacks > 0) {
            stats.setSuccessRate((double) successfulAttacks / totalAttacks * 100);
            stats.setDetectionRate((double) detectedAttacks / totalAttacks * 100);
            stats.setBlockRate((double) blockedAttacks / totalAttacks * 100);
        }

        return stats;
    }

    /**
     * 공격 유형별 통계
     */
    public Map<String, AttackTypeStatistics> getAttackTypeStatistics() {
        Map<String, AttackTypeStatistics> stats = new HashMap<>();

        // 모든 공격 유형 조회
        for (AttackResult.AttackType type : AttackResult.AttackType.values()) {
            String typeName = type.name();
            long count = getCounterValue("attack_type:" + typeName);

            if (count > 0) {
                AttackTypeStatistics typeStats = AttackTypeStatistics.builder()
                    .attackType(typeName)
                    .totalAttempts(count)
                    .successfulAttempts(getCounterValue("attack_type:" + typeName + ":success"))
                    .detectedAttempts(getCounterValue("attack_type:" + typeName + ":detected"))
                    .blockedAttempts(getCounterValue("attack_type:" + typeName + ":blocked"))
                    .averageRiskScore(getAverageRiskScore(typeName))
                    .lastAttemptTime(getLastAttemptTime(typeName))
                    .build();

                stats.put(typeName, typeStats);
            }
        }

        return stats;
    }

    /**
     * 위험 수준 분포
     */
    public Map<String, Long> getRiskLevelDistribution() {
        Map<String, Long> distribution = new HashMap<>();
        distribution.put("LOW", getCounterValue("risk_level:LOW"));
        distribution.put("MEDIUM", getCounterValue("risk_level:MEDIUM"));
        distribution.put("HIGH", getCounterValue("risk_level:HIGH"));
        distribution.put("CRITICAL", getCounterValue("risk_level:CRITICAL"));
        return distribution;
    }

    /**
     * 시간대별 공격 분포
     */
    public Map<Integer, Long> getHourlyDistribution() {
        Map<Integer, Long> distribution = new HashMap<>();

        for (int hour = 0; hour < 24; hour++) {
            String key = String.format("hourly:%02d", hour);
            distribution.put(hour, getCounterValue(key));
        }

        return distribution;
    }

    /**
     * 상위 공격 대상
     */
    public List<TargetStatistics> getTopTargets(int limit) {
        // Redis에서 모든 타겟 키 조회
        Set<String> targetKeys = stringRedisTemplate.keys(COUNTER_PREFIX + "target_user:*");

        if (targetKeys == null || targetKeys.isEmpty()) {
            return new ArrayList<>();
        }

        List<TargetStatistics> targets = new ArrayList<>();

        for (String key : targetKeys) {
            String targetUser = key.substring(key.lastIndexOf(':') + 1);
            long attackCount = getCounterValue("target_user:" + targetUser);

            targets.add(TargetStatistics.builder()
                .targetUser(targetUser)
                .attackCount(attackCount)
                .successCount(getCounterValue("target_user:" + targetUser + ":success"))
                .blockCount(getCounterValue("target_user:" + targetUser + ":blocked"))
                .build());
        }

        // 공격 횟수로 정렬하여 상위 N개 반환
        return targets.stream()
            .sorted(Comparator.comparingLong(TargetStatistics::getAttackCount).reversed())
            .limit(limit)
            .collect(Collectors.toList());
    }

    /**
     * 최근 공격 로그
     */
    public List<AttackResult> getRecentAttacks(int limit) {
        String key = ATTACK_LOG_PREFIX + "recent";
        List<Object> results = redisTemplate.opsForList().range(key, 0, limit - 1);

        if (results == null) {
            return new ArrayList<>();
        }

        return results.stream()
            .filter(obj -> obj instanceof AttackResult)
            .map(obj -> (AttackResult) obj)
            .collect(Collectors.toList());
    }

    /**
     * 통계 초기화
     */
    public void resetStatistics() {
        log.warn("Resetting all simulation statistics");

        // Redis 키 패턴으로 삭제
        Set<String> keys = stringRedisTemplate.keys(STATS_PREFIX + "*");
        if (keys != null && !keys.isEmpty()) {
            stringRedisTemplate.delete(keys);
        }

        keys = stringRedisTemplate.keys(COUNTER_PREFIX + "*");
        if (keys != null && !keys.isEmpty()) {
            stringRedisTemplate.delete(keys);
        }

        keys = stringRedisTemplate.keys(TIMELINE_PREFIX + "*");
        if (keys != null && !keys.isEmpty()) {
            stringRedisTemplate.delete(keys);
        }

        keys = stringRedisTemplate.keys(ATTACK_LOG_PREFIX + "*");
        if (keys != null && !keys.isEmpty()) {
            stringRedisTemplate.delete(keys);
        }

        // 로컬 캐시 초기화
        localCounters.clear();
        attackTypeStats.clear();
        invalidateCache();

        log.info("Statistics reset completed");
    }

    /**
     * 모든 통계 초기화 (alias)
     */
    public void resetAllStatistics() {
        resetStatistics();
    }

    // === 추가 통계 메소드들 ===

    /**
     * 전체 공격 수
     */
    public long getTotalAttacks() {
        return getCounterValue("total_attacks");
    }

    /**
     * 성공한 공격 수
     */
    public long getSuccessfulAttacks() {
        return getCounterValue("successful_attacks");
    }

    /**
     * 탐지된 공격 수
     */
    public long getDetectedAttacks() {
        return getCounterValue("detected_attacks");
    }

    /**
     * 차단된 공격 수
     */
    public long getBlockedAttacks() {
        return getCounterValue("blocked_attacks");
    }

    /**
     * 평균 위험 점수 (인수 없는 버전)
     */
    public double getAverageRiskScore() {
        return getAverageRiskScore("overall");
    }

    /**
     * 공격 유형별 카운트
     */
    public Map<String, Long> getAttackCountByType() {
        Map<String, Long> counts = new HashMap<>();
        for (AttackResult.AttackType type : AttackResult.AttackType.values()) {
            String key = "attack_type_" + type.name().toLowerCase();
            counts.put(type.name(), getCounterValue(key));
        }
        return counts;
    }

    /**
     * 공격 카테고리별 카운트
     */
    public Map<String, Long> getAttackCountByCategory() {
        Map<String, Long> counts = new HashMap<>();
        counts.put("AUTHENTICATION", getCounterValue("category_authentication"));
        counts.put("BEHAVIORAL", getCounterValue("category_behavioral"));
        counts.put("API", getCounterValue("category_api"));
        counts.put("AI_ML", getCounterValue("category_ai_ml"));
        return counts;
    }

    /**
     * 유형별 성공률
     */
    public Map<String, Double> getSuccessRateByType() {
        Map<String, Double> rates = new HashMap<>();
        for (AttackResult.AttackType type : AttackResult.AttackType.values()) {
            String totalKey = "attack_type_" + type.name().toLowerCase();
            String successKey = "success_type_" + type.name().toLowerCase();
            long total = getCounterValue(totalKey);
            long success = getCounterValue(successKey);
            rates.put(type.name(), total > 0 ? (double) success / total : 0.0);
        }
        return rates;
    }

    /**
     * 유형별 탐지율
     */
    public Map<String, Double> getDetectionRateByType() {
        Map<String, Double> rates = new HashMap<>();
        for (AttackResult.AttackType type : AttackResult.AttackType.values()) {
            String totalKey = "attack_type_" + type.name().toLowerCase();
            String detectedKey = "detected_type_" + type.name().toLowerCase();
            long total = getCounterValue(totalKey);
            long detected = getCounterValue(detectedKey);
            rates.put(type.name(), total > 0 ? (double) detected / total : 0.0);
        }
        return rates;
    }

    /**
     * 위협 분포
     */
    public Map<String, Long> getThreatDistribution() {
        Map<String, Long> distribution = new HashMap<>();
        distribution.put("LOW", getCounterValue("risk_low"));
        distribution.put("MEDIUM", getCounterValue("risk_medium"));
        distribution.put("HIGH", getCounterValue("risk_high"));
        distribution.put("CRITICAL", getCounterValue("risk_critical"));
        return distribution;
    }

    /**
     * 최근 1시간 내 공격 수
     */
    public long getAttacksInLastHour() {
        return getAttacksInTimeRange(Duration.ofHours(1));
    }

    /**
     * 최근 1일 내 공격 수
     */
    public long getAttacksInLastDay() {
        return getAttacksInTimeRange(Duration.ofDays(1));
    }

    /**
     * 최근 1주일 내 공격 수
     */
    public long getAttacksInLastWeek() {
        return getAttacksInTimeRange(Duration.ofDays(7));
    }

    /**
     * 특정 시간 범위 내 공격 수
     */
    private long getAttacksInTimeRange(Duration duration) {
        LocalDateTime now = LocalDateTime.now();
        LocalDateTime from = now.minus(duration);
        String key = TIMELINE_PREFIX + "attacks:" + from.format(DateTimeFormatter.ISO_LOCAL_DATE_TIME);

        // 간단한 구현 - 실제로는 시간 기반 인덱싱 필요
        Object value = redisTemplate.opsForValue().get(key);
        if (value instanceof Number) {
            return ((Number) value).longValue();
        }
        return 0L;
    }

    // === Helper Methods ===

    private void incrementCounter(String key) {
        String redisKey = COUNTER_PREFIX + key;
        stringRedisTemplate.opsForValue().increment(redisKey);

        // 로컬 카운터도 업데이트
        localCounters.computeIfAbsent(key, k -> new AtomicLong()).incrementAndGet();

        // TTL 설정 (30일)
        stringRedisTemplate.expire(redisKey, Duration.ofDays(30));
    }

    private long getCounterValue(String key) {
        String redisKey = COUNTER_PREFIX + key;
        String value = stringRedisTemplate.opsForValue().get(redisKey);
        return value != null ? Long.parseLong(value) : 0L;
    }

    private String calculateRiskLevel(double riskScore) {
        if (riskScore >= 0.9) return "CRITICAL";
        if (riskScore >= 0.7) return "HIGH";
        if (riskScore >= 0.4) return "MEDIUM";
        return "LOW";
    }

    private void recordToTimeline(AttackResult result) {
        String hour = String.format("%02d", LocalDateTime.now().getHour());
        incrementCounter("hourly:" + hour);

        // 타임라인에 이벤트 추가
        String timelineKey = TIMELINE_PREFIX + LocalDateTime.now().format(DateTimeFormatter.ISO_LOCAL_DATE);
        redisTemplate.opsForList().rightPush(timelineKey, result);
        redisTemplate.expire(timelineKey, Duration.ofDays(7));
    }

    private void saveAttackLog(AttackResult result) {
        // 최근 공격 로그
        String recentKey = ATTACK_LOG_PREFIX + "recent";
        redisTemplate.opsForList().leftPush(recentKey, result);
        redisTemplate.opsForList().trim(recentKey, 0, 999); // 최근 1000개만 유지

        // 공격 유형별 로그
        String typeKey = ATTACK_LOG_PREFIX + "type:" + result.getType().name();
        redisTemplate.opsForList().leftPush(typeKey, result);
        redisTemplate.opsForList().trim(typeKey, 0, 99); // 유형별 100개만 유지
    }

    private double getAverageRiskScore(String attackType) {
        String key = ATTACK_LOG_PREFIX + "type:" + attackType;
        List<Object> results = redisTemplate.opsForList().range(key, 0, -1);

        if (results == null || results.isEmpty()) {
            return 0.0;
        }

        double totalScore = results.stream()
            .filter(obj -> obj instanceof AttackResult)
            .map(obj -> (AttackResult) obj)
            .mapToDouble(AttackResult::getRiskScore)
            .sum();

        return totalScore / results.size();
    }

    private LocalDateTime getLastAttemptTime(String attackType) {
        String key = ATTACK_LOG_PREFIX + "type:" + attackType;
        Object result = redisTemplate.opsForList().index(key, 0);

        if (result instanceof AttackResult) {
            return ((AttackResult) result).getExecutionTime();
        }

        return null;
    }

    private SimulationStatistics buildStatistics() {
        long totalAttacks = getCounterValue("total_attacks");
        long successfulAttacks = getCounterValue("successful_attacks");
        long detectedAttacks = getCounterValue("detected_attacks");
        long blockedAttacks = getCounterValue("blocked_attacks");

        SimulationStatistics stats = SimulationStatistics.builder()
            .timestamp(LocalDateTime.now())
            .totalAttacks(totalAttacks)
            .successfulAttacks(successfulAttacks)
            .failedAttacks(getCounterValue("failed_attacks"))
            .detectedAttacks(detectedAttacks)
            .blockedAttacks(blockedAttacks)
            .build();

        // 계산된 메트릭
        if (totalAttacks > 0) {
            stats.setSuccessRate((double) successfulAttacks / totalAttacks * 100);
            stats.setDetectionRate((double) detectedAttacks / totalAttacks * 100);
            stats.setBlockRate((double) blockedAttacks / totalAttacks * 100);
        }

        // 공격 유형 분포
        stats.setAttackTypeBreakdown(getAttackTypeBreakdown());

        // 위험 수준 분포
        stats.setRiskLevelDistribution(getRiskLevelDistribution());

        // 시간대별 분포
        stats.setHourlyDistribution(getHourlyDistribution());

        // 상위 타겟
        stats.setTopTargets(getTopTargets(10));

        // 활성 캠페인 수
        Set<String> campaignKeys = stringRedisTemplate.keys(COUNTER_PREFIX + "campaign:*");
        stats.setActiveCampaigns(campaignKeys != null ? campaignKeys.size() : 0);

        return stats;
    }

    private Map<String, Long> getAttackTypeBreakdown() {
        Map<String, Long> breakdown = new HashMap<>();

        for (AttackResult.AttackType type : AttackResult.AttackType.values()) {
            long count = getCounterValue("attack_type:" + type.name());
            if (count > 0) {
                breakdown.put(type.name(), count);
            }
        }

        return breakdown;
    }

    private void invalidateCache() {
        cachedStatistics = null;
        cacheLastUpdated = 0;
    }

    // === Data Classes ===

    @Data
    @Builder
    public static class SimulationStatistics {
        private LocalDateTime timestamp;
        private LocalDateTime periodStart;
        private LocalDateTime periodEnd;

        // 기본 카운터
        private long totalAttacks;
        private long successfulAttacks;
        private long failedAttacks;
        private long detectedAttacks;
        private long blockedAttacks;

        // 계산된 메트릭
        private double successRate;
        private double detectionRate;
        private double blockRate;

        // 분포 데이터
        private Map<String, Long> attackTypeBreakdown;
        private Map<String, Long> riskLevelDistribution;
        private Map<Integer, Long> hourlyDistribution;

        // 상위 타겟
        private List<TargetStatistics> topTargets;

        // 캠페인 정보
        private int activeCampaigns;
    }

    @Data
    @Builder
    public static class AttackTypeStatistics {
        private String attackType;
        private long totalAttempts;
        private long successfulAttempts;
        private long detectedAttempts;
        private long blockedAttempts;
        private double averageRiskScore;
        private LocalDateTime lastAttemptTime;
    }

    @Data
    @Builder
    public static class TargetStatistics {
        private String targetUser;
        private long attackCount;
        private long successCount;
        private long blockCount;
    }

    @Data
    @Builder
    private static class AttackStatistics {
        private long attempts;
        private long successes;
        private long detected;
        private long blocked;
        private double totalRiskScore;
        private LocalDateTime lastAttempt;
    }
}