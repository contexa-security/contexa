package io.contexa.contexacore.plane.service;

import io.contexa.contexacore.autonomous.domain.SecurityEvent;
import lombok.Builder;
import lombok.Getter;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.stereotype.Service;

import java.time.LocalDateTime;
import java.util.*;
import java.util.concurrent.TimeUnit;

/**
 * Honeypot 패턴 분석기 (Phase 1)
 *
 * Phase 1 구현 범위:
 * 1. 민감 리소스 접근 빈도 분석
 * 2. 짧은 시간 내 다량 접근 탐지
 * 3. 비정상 리소스 접근 순서 탐지
 *
 * Phase 2 구현 계획 (향후):
 * - Medium Honeypot: 존재하지 않지만 그럴듯한 리소스
 * - Hard Honeypot: 실제 데이터와 유사한 Decoy 데이터
 *
 * 외부기관 2 피드백 반영:
 * - "Honeypot 구현 로드맵 필요"
 * - Phase 1: Easy (민감 리소스 빈도)
 * - Phase 2: Medium (그럴듯한 가짜 리소스)
 * - Phase 3: Hard (정교한 Decoy)
 *
 * @author AI3Security
 * @since 3.0
 */
@Slf4j
@Service
public class HoneypotPatternAnalyzer {

    @Autowired
    @Qualifier("generalRedisTemplate")
    private RedisTemplate<String, Object> redisTemplate;

    @Autowired
    private SensitiveResourceService sensitiveResourceService;

    // ===== 설정값 (application.yml에서 주입) =====

    /**
     * 접근 빈도 임계값 (기본: 10회)
     * 짧은 시간 내 이 횟수 이상 접근 시 의심
     */
    @Value("${honeypot.access.frequency.threshold:10}")
    private int accessFrequencyThreshold;

    /**
     * 접근 빈도 윈도우 (초, 기본: 60초)
     */
    @Value("${honeypot.access.frequency.window:60}")
    private int accessFrequencyWindowSeconds;

    /**
     * 민감 리소스 다양성 임계값 (기본: 5개)
     * 짧은 시간 내 서로 다른 민감 리소스 N개 이상 접근 시 의심
     */
    @Value("${honeypot.sensitive.diversity.threshold:5}")
    private int sensitiveDiversityThreshold;

    /**
     * 순차 접근 패턴 윈도우 (초, 기본: 30초)
     * 이 시간 내 순차적 접근 패턴 탐지
     */
    @Value("${honeypot.sequential.pattern.window:30}")
    private int sequentialPatternWindowSeconds;

    /**
     * 비정상 순서 패턴 (기본: 상세→목록 역순)
     * 정상: 목록 조회 → 상세 조회
     * 비정상: 상세 조회 → 목록 조회 (직접 ID 추측)
     */
    private static final String PATTERN_DETAIL_BEFORE_LIST = "DETAIL_BEFORE_LIST";

    // ===== Public Methods =====

    /**
     * 민감 리소스 접근 이벤트 분석
     *
     * @param event SecurityEvent
     * @return HoneypotAnalysisResult
     */
    public HoneypotAnalysisResult analyzeSensitiveAccess(SecurityEvent event) {
        String userId = event.getUserId();
        String resourcePath = event.getTargetResource();
        String httpMethod = event.getProtocol();

        // @Protectable 리소스만 분석
        if (!sensitiveResourceService.isProtectableResource(resourcePath, httpMethod)) {
            return HoneypotAnalysisResult.normal();
        }

        // 1. 접근 기록 저장
        recordAccess(userId, resourcePath, httpMethod);

        // 2. 접근 빈도 분석
        FrequencyAnalysisResult frequencyResult = analyzeAccessFrequency(userId);

        // 3. 민감 리소스 다양성 분석
        DiversityAnalysisResult diversityResult = analyzeSensitiveDiversity(userId);

        // 4. 순차 접근 패턴 분석
        SequentialPatternResult sequentialResult = analyzeSequentialPattern(userId);

        // 5. 종합 판정
        boolean suspicious = frequencyResult.isSuspicious() ||
                            diversityResult.isSuspicious() ||
                            sequentialResult.isSuspicious();

        double suspicionScore = calculateSuspicionScore(frequencyResult, diversityResult, sequentialResult);

        if (suspicious) {
            log.warn("[HoneypotPattern] Suspicious pattern detected for user {}: frequency={}, diversity={}, sequential={}, score={}",
                    userId,
                    frequencyResult.isSuspicious(),
                    diversityResult.isSuspicious(),
                    sequentialResult.isSuspicious(),
                    String.format("%.3f", suspicionScore));
        }

        return HoneypotAnalysisResult.builder()
                .suspicious(suspicious)
                .suspicionScore(suspicionScore)
                .frequencyResult(frequencyResult)
                .diversityResult(diversityResult)
                .sequentialResult(sequentialResult)
                .build();
    }

    /**
     * 사용자의 접근 기록 정리 (테스트용)
     */
    public void clearAccessHistory(String userId) {
        String accessKey = buildAccessKey(userId);
        redisTemplate.delete(accessKey);
        log.info("[HoneypotPattern] Cleared access history for user {}", userId);
    }

    // ===== Private Methods =====

    /**
     * 접근 기록 저장
     */
    private void recordAccess(String userId, String resourcePath, String httpMethod) {
        String key = buildAccessKey(userId);

        AccessRecord record = AccessRecord.builder()
                .resourcePath(resourcePath)
                .httpMethod(httpMethod)
                .timestamp(LocalDateTime.now())
                .build();

        redisTemplate.opsForList().rightPush(key, record);

        // 1시간 TTL
        redisTemplate.expire(key, 1, TimeUnit.HOURS);

        // 최근 100개만 유지
        Long size = redisTemplate.opsForList().size(key);
        if (size != null && size > 100) {
            redisTemplate.opsForList().leftPop(key);
        }
    }

    /**
     * 접근 빈도 분석
     */
    private FrequencyAnalysisResult analyzeAccessFrequency(String userId) {
        String key = buildAccessKey(userId);

        @SuppressWarnings("unchecked")
        List<AccessRecord> allRecords = (List<AccessRecord>) (List<?>) redisTemplate.opsForList().range(key, 0, -1);

        if (allRecords == null || allRecords.isEmpty()) {
            return FrequencyAnalysisResult.normal();
        }

        // 최근 N초 이내 접근만 카운트
        LocalDateTime cutoff = LocalDateTime.now().minusSeconds(accessFrequencyWindowSeconds);
        long recentCount = allRecords.stream()
                .filter(r -> r.getTimestamp().isAfter(cutoff))
                .count();

        boolean suspicious = recentCount >= accessFrequencyThreshold;

        return FrequencyAnalysisResult.builder()
                .suspicious(suspicious)
                .accessCount((int) recentCount)
                .threshold(accessFrequencyThreshold)
                .windowSeconds(accessFrequencyWindowSeconds)
                .build();
    }

    /**
     * 민감 리소스 다양성 분석
     */
    private DiversityAnalysisResult analyzeSensitiveDiversity(String userId) {
        String key = buildAccessKey(userId);

        @SuppressWarnings("unchecked")
        List<AccessRecord> allRecords = (List<AccessRecord>) (List<?>) redisTemplate.opsForList().range(key, 0, -1);

        if (allRecords == null || allRecords.isEmpty()) {
            return DiversityAnalysisResult.normal();
        }

        // 최근 N초 이내 서로 다른 리소스 개수 카운트
        LocalDateTime cutoff = LocalDateTime.now().minusSeconds(accessFrequencyWindowSeconds);
        Set<String> uniqueResources = new HashSet<>();

        for (AccessRecord record : allRecords) {
            if (record.getTimestamp().isAfter(cutoff)) {
                uniqueResources.add(record.getResourcePath());
            }
        }

        boolean suspicious = uniqueResources.size() >= sensitiveDiversityThreshold;

        return DiversityAnalysisResult.builder()
                .suspicious(suspicious)
                .uniqueResourceCount(uniqueResources.size())
                .threshold(sensitiveDiversityThreshold)
                .build();
    }

    /**
     * 순차 접근 패턴 분석
     *
     * 비정상 패턴: 목록 조회 없이 바로 상세 조회 (ID 추측)
     */
    private SequentialPatternResult analyzeSequentialPattern(String userId) {
        String key = buildAccessKey(userId);

        @SuppressWarnings("unchecked")
        List<AccessRecord> allRecords = (List<AccessRecord>) (List<?>) redisTemplate.opsForList().range(key, 0, -1);

        if (allRecords == null || allRecords.size() < 2) {
            return SequentialPatternResult.normal();
        }

        // 최근 N초 이내 접근만 분석
        LocalDateTime cutoff = LocalDateTime.now().minusSeconds(sequentialPatternWindowSeconds);
        List<AccessRecord> recentRecords = allRecords.stream()
                .filter(r -> r.getTimestamp().isAfter(cutoff))
                .toList();

        if (recentRecords.size() < 2) {
            return SequentialPatternResult.normal();
        }

        // 상세 조회가 목록 조회보다 먼저 나타나는지 확인
        boolean detailBeforeList = false;

        for (int i = 0; i < recentRecords.size() - 1; i++) {
            AccessRecord current = recentRecords.get(i);
            AccessRecord next = recentRecords.get(i + 1);

            // 현재: 상세 (경로에 ID 포함), 다음: 목록
            if (isDetailAccess(current.getResourcePath()) && isListAccess(next.getResourcePath())) {
                detailBeforeList = true;
                break;
            }
        }

        return SequentialPatternResult.builder()
                .suspicious(detailBeforeList)
                .pattern(detailBeforeList ? PATTERN_DETAIL_BEFORE_LIST : "NORMAL")
                .build();
    }

    /**
     * 상세 접근 여부 판단 (경로에 ID 패턴 포함)
     */
    private boolean isDetailAccess(String resourcePath) {
        if (resourcePath == null) return false;

        // /api/users/123, /api/orders/456 같은 패턴
        return resourcePath.matches(".*/[0-9a-f-]{8,}.*") ||  // UUID
               resourcePath.matches(".*/\\d+$") ||             // 숫자 ID
               resourcePath.matches(".*/\\d+/.*");             // 중간 숫자 ID
    }

    /**
     * 목록 접근 여부 판단
     */
    private boolean isListAccess(String resourcePath) {
        if (resourcePath == null) return false;

        // /api/users, /api/orders 같은 패턴 (ID 없음)
        return !isDetailAccess(resourcePath);
    }

    /**
     * 의심 점수 계산 (0.0 ~ 1.0)
     */
    private double calculateSuspicionScore(
            FrequencyAnalysisResult frequency,
            DiversityAnalysisResult diversity,
            SequentialPatternResult sequential) {

        double score = 0.0;

        // 빈도 분석 (최대 0.4)
        if (frequency.isSuspicious()) {
            double ratio = (double) frequency.getAccessCount() / frequency.getThreshold();
            score += Math.min(0.4, ratio * 0.2);
        }

        // 다양성 분석 (최대 0.3)
        if (diversity.isSuspicious()) {
            double ratio = (double) diversity.getUniqueResourceCount() / diversity.getThreshold();
            score += Math.min(0.3, ratio * 0.15);
        }

        // 순차 패턴 (0.3 고정)
        if (sequential.isSuspicious()) {
            score += 0.3;
        }

        return Math.min(1.0, score);
    }

    /**
     * Redis 키 생성
     */
    private String buildAccessKey(String userId) {
        return "honeypot:access:" + userId;
    }

    // ===== Inner Classes =====

    /**
     * 접근 기록
     */
    @Getter
    @Builder
    private static class AccessRecord implements java.io.Serializable {
        private static final long serialVersionUID = 1L;

        private final String resourcePath;
        private final String httpMethod;
        private final LocalDateTime timestamp;
    }

    /**
     * Honeypot 분석 결과
     */
    @Getter
    @Builder
    public static class HoneypotAnalysisResult {
        private final boolean suspicious;
        private final double suspicionScore;
        private final FrequencyAnalysisResult frequencyResult;
        private final DiversityAnalysisResult diversityResult;
        private final SequentialPatternResult sequentialResult;

        public static HoneypotAnalysisResult normal() {
            return HoneypotAnalysisResult.builder()
                    .suspicious(false)
                    .suspicionScore(0.0)
                    .frequencyResult(FrequencyAnalysisResult.normal())
                    .diversityResult(DiversityAnalysisResult.normal())
                    .sequentialResult(SequentialPatternResult.normal())
                    .build();
        }
    }

    /**
     * 빈도 분석 결과
     */
    @Getter
    @Builder
    public static class FrequencyAnalysisResult {
        private final boolean suspicious;
        private final int accessCount;
        private final int threshold;
        private final int windowSeconds;

        public static FrequencyAnalysisResult normal() {
            return FrequencyAnalysisResult.builder()
                    .suspicious(false)
                    .accessCount(0)
                    .threshold(0)
                    .windowSeconds(0)
                    .build();
        }
    }

    /**
     * 다양성 분석 결과
     */
    @Getter
    @Builder
    public static class DiversityAnalysisResult {
        private final boolean suspicious;
        private final int uniqueResourceCount;
        private final int threshold;

        public static DiversityAnalysisResult normal() {
            return DiversityAnalysisResult.builder()
                    .suspicious(false)
                    .uniqueResourceCount(0)
                    .threshold(0)
                    .build();
        }
    }

    /**
     * 순차 패턴 분석 결과
     */
    @Getter
    @Builder
    public static class SequentialPatternResult {
        private final boolean suspicious;
        private final String pattern;

        public static SequentialPatternResult normal() {
            return SequentialPatternResult.builder()
                    .suspicious(false)
                    .pattern("NORMAL")
                    .build();
        }
    }
}
