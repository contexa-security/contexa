package io.contexa.contexacore.hcad.service;

import io.contexa.contexacommon.hcad.domain.BaselineVector;
import io.contexa.contexacommon.hcad.domain.HCADAnalysisResult;
import io.contexa.contexacore.autonomous.tiered.SecurityDecision;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.data.redis.core.RedisTemplate;

import io.contexa.contexacore.autonomous.domain.SecurityEvent;

import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * Baseline Learning Service (AI Native)
 *
 * 정상 패턴 학습 서비스 - EMA(Exponential Moving Average) 기반
 *
 * AI Native 원칙:
 * - LLM이 판단한 정상 요청(action=ALLOW, !isAnomaly, confidence >= 0.7)만 학습
 * - 학습된 Baseline은 Layer1 프롬프트의 컨텍스트로 제공
 * - LLM이 Baseline과 현재 요청을 비교하여 판단
 *
 * EMA 공식:
 * newBaseline = (alpha * currentValue) + ((1 - alpha) * oldBaseline)
 * - alpha = 0.1 (기본값, 새 값에 10% 가중치)
 *
 * 학습 조건:
 * - action = ALLOW (LLM이 허용 결정)
 * - isAnomaly = false (LLM이 정상 판단)
 * - confidence >= 0.7 (LLM 확신도 70% 이상)
 *
 * Redis 저장 스키마:
 * - Key: security:hcad:baseline:{userId}
 * - Fields: avgTrustScore, avgRequestCount, updateCount, confidence, lastUpdated
 *
 * @author contexa
 * @since 3.0.0
 */
@Slf4j
@RequiredArgsConstructor
public class BaselineLearningService {

    private final @Qualifier("generalRedisTemplate") RedisTemplate<String, Object> redisTemplate;

    private static final String BASELINE_KEY_PREFIX = "security:hcad:baseline:";
    private static final Duration BASELINE_TTL = Duration.ofDays(30);

    @Value("${hcad.baseline.learning.alpha:0.1}")
    private double alpha = 0.1;

    @Value("${hcad.baseline.learning.min-confidence:0.7}")
    private double minConfidence = 0.7;

    @Value("${hcad.baseline.learning.enabled:true}")
    private boolean learningEnabled = true;

    /**
     * 정상 패턴 학습 수행 (SecurityDecision 기반)
     *
     * AI Native: LLM이 판단한 결과를 바탕으로 정상 패턴 학습
     *
     * @param userId 사용자 ID
     * @param decision LLM의 SecurityDecision
     * @param analysisResult HCAD 분석 결과
     * @return 학습 수행 여부
     */
    public boolean learnIfNormal(String userId, SecurityDecision decision, HCADAnalysisResult analysisResult) {
        if (!learningEnabled) {
            log.debug("[BaselineLearningService] 학습 비활성화 상태");
            return false;
        }

        if (userId == null || decision == null) {
            log.debug("[BaselineLearningService] userId 또는 decision이 null");
            return false;
        }

        // 학습 조건 검증: action=ALLOW, !isAnomaly, confidence >= 0.7
        if (!shouldLearn(decision, analysisResult)) {
            log.debug("[BaselineLearningService] 학습 조건 미충족: userId={}, action={}, isAnomaly={}, confidence={}",
                userId,
                decision.getAction(),
                analysisResult != null && analysisResult.isAnomaly(),
                decision.getConfidence());
            return false;
        }

        try {
            // 기존 Baseline 조회
            BaselineVector currentBaseline = getBaseline(userId);

            // EMA 기반 업데이트
            BaselineVector newBaseline = updateWithEMA(currentBaseline, userId, decision, analysisResult);

            // Redis에 저장
            saveBaseline(userId, newBaseline);

            log.info("[BaselineLearningService][AI Native] 정상 패턴 학습 완료: userId={}, avgTrustScore={}, updateCount={}",
                userId,
                String.format("%.3f", newBaseline.getAvgTrustScore()),
                newBaseline.getUpdateCount());

            return true;

        } catch (Exception e) {
            log.error("[BaselineLearningService] 학습 실패: userId={}", userId, e);
            return false;
        }
    }

    /**
     * 학습 조건 검증
     *
     * AI Native 학습 조건:
     * - action = ALLOW (LLM이 허용 결정)
     * - isAnomaly = false (LLM이 정상 판단)
     * - confidence >= 0.7 (LLM 확신도 70% 이상)
     */
    private boolean shouldLearn(SecurityDecision decision, HCADAnalysisResult analysisResult) {
        // 1. action = ALLOW
        if (decision.getAction() != SecurityDecision.Action.ALLOW) {
            return false;
        }

        // 2. isAnomaly = false
        if (analysisResult != null && analysisResult.isAnomaly()) {
            return false;
        }

        // 3. confidence >= 0.7
        double confidence = decision.getConfidence();
        if (Double.isNaN(confidence) || confidence < minConfidence) {
            return false;
        }

        return true;
    }

    /**
     * EMA 기반 Baseline 업데이트
     *
     * newValue = alpha * currentValue + (1 - alpha) * oldValue
     *
     * BaselineVector 기존 필드 활용:
     * - avgTrustScore: 평균 신뢰 점수
     * - avgRequestCount: 평균 요청 수
     * - updateCount: 업데이트 횟수
     * - confidence: 기준선 신뢰도
     * - lastUpdated: 마지막 업데이트 시간
     */
    private BaselineVector updateWithEMA(BaselineVector current, String userId,
                                          SecurityDecision decision, HCADAnalysisResult analysisResult) {
        double currentTrustScore = analysisResult != null ? analysisResult.getTrustScore() : 1.0;
        double currentConfidence = decision.getConfidence();

        if (current == null) {
            // 첫 학습
            return BaselineVector.builder()
                .userId(userId)
                .avgTrustScore(currentTrustScore)
                .avgRequestCount(1L)
                .updateCount(1L)
                .confidence(currentConfidence * 0.1)  // 첫 학습은 신뢰도 낮게
                .lastUpdated(Instant.now())
                .build();
        }

        // EMA 적용
        double oldTrustScore = current.getAvgTrustScore() != null ? current.getAvgTrustScore() : 0.5;
        double newTrustScore = alpha * currentTrustScore + (1 - alpha) * oldTrustScore;

        // 신뢰도 증가 (최대 1.0)
        double oldConfidence = current.getConfidence() != null ? current.getConfidence() : 0.1;
        double newConfidence = Math.min(1.0, oldConfidence + 0.01);

        long oldUpdateCount = current.getUpdateCount() != null ? current.getUpdateCount() : 0L;
        long oldRequestCount = current.getAvgRequestCount() != null ? current.getAvgRequestCount() : 0L;

        return BaselineVector.builder()
            .userId(userId)
            .avgTrustScore(newTrustScore)
            .avgRequestCount(oldRequestCount + 1)
            .updateCount(oldUpdateCount + 1)
            .confidence(newConfidence)
            .lastUpdated(Instant.now())
            .build();
    }

    /**
     * Baseline 조회
     *
     * @param userId 사용자 ID
     * @return BaselineVector (없으면 null)
     */
    public BaselineVector getBaseline(String userId) {
        if (redisTemplate == null || userId == null) {
            return null;
        }

        try {
            String key = BASELINE_KEY_PREFIX + userId;
            Map<Object, Object> data = redisTemplate.opsForHash().entries(key);

            if (data == null || data.isEmpty()) {
                return null;
            }

            return BaselineVector.builder()
                .userId(userId)
                .avgTrustScore(parseDouble(data.get("avgTrustScore")))
                .avgRequestCount(parseLong(data.get("avgRequestCount")))
                .updateCount(parseLong(data.get("updateCount")))
                .confidence(parseDouble(data.get("confidence")))
                .lastUpdated(parseInstant(data.get("lastUpdated")))
                .build();

        } catch (Exception e) {
            log.error("[BaselineLearningService] Baseline 조회 실패: userId={}", userId, e);
            return null;
        }
    }

    /**
     * Baseline 저장
     */
    private void saveBaseline(String userId, BaselineVector baseline) {
        if (redisTemplate == null || userId == null || baseline == null) {
            return;
        }

        try {
            String key = BASELINE_KEY_PREFIX + userId;
            Map<String, Object> data = new HashMap<>();
            data.put("userId", userId);
            data.put("avgTrustScore", baseline.getAvgTrustScore());
            data.put("avgRequestCount", baseline.getAvgRequestCount());
            data.put("updateCount", baseline.getUpdateCount());
            data.put("confidence", baseline.getConfidence());
            data.put("lastUpdated", baseline.getLastUpdated() != null ?
                baseline.getLastUpdated().toString() : Instant.now().toString());

            redisTemplate.opsForHash().putAll(key, data);
            redisTemplate.expire(key, BASELINE_TTL);

        } catch (Exception e) {
            log.error("[BaselineLearningService] Baseline 저장 실패: userId={}", userId, e);
        }
    }

    /**
     * Baseline 삭제 (테스트용)
     */
    public void deleteBaseline(String userId) {
        if (redisTemplate == null || userId == null) {
            return;
        }

        try {
            String key = BASELINE_KEY_PREFIX + userId;
            redisTemplate.delete(key);
            log.debug("[BaselineLearningService] Baseline 삭제: userId={}", userId);
        } catch (Exception e) {
            log.error("[BaselineLearningService] Baseline 삭제 실패: userId={}", userId, e);
        }
    }

    private double parseDouble(Object value) {
        if (value instanceof Number) {
            return ((Number) value).doubleValue();
        }
        if (value instanceof String) {
            try {
                return Double.parseDouble((String) value);
            } catch (NumberFormatException e) {
                return 0.0;
            }
        }
        return 0.0;
    }

    private long parseLong(Object value) {
        if (value instanceof Number) {
            return ((Number) value).longValue();
        }
        if (value instanceof String) {
            try {
                return Long.parseLong((String) value);
            } catch (NumberFormatException e) {
                return 0L;
            }
        }
        return 0L;
    }

    private Instant parseInstant(Object value) {
        if (value instanceof String) {
            try {
                return Instant.parse((String) value);
            } catch (Exception e) {
                return Instant.now();
            }
        }
        return Instant.now();
    }

    // ========== AI Native: LLM 프롬프트 컨텍스트 생성 메서드 ==========

    /**
     * Baseline을 LLM 프롬프트 형식으로 변환 (AI Native v2.0)
     *
     * Phase 9 리팩토링:
     * - 플랫폼 판단 로직 제거 (is*() 메서드 호출 제거)
     * - raw 데이터만 제공, LLM이 직접 비교하여 판단
     *
     * AI Native 원칙:
     * - 플랫폼은 "정상 여부" 판단 금지
     * - LLM이 baseline과 현재 요청을 직접 비교
     *
     * @param userId 사용자 ID
     * @param currentEvent 현재 이벤트 (비교용)
     * @return LLM 프롬프트 형식 문자열 (raw 데이터만)
     */
    public String buildBaselinePromptContext(String userId, SecurityEvent currentEvent) {
        if (userId == null) {
            return "Baseline: User ID not available";
        }

        BaselineVector baseline = getBaseline(userId);
        if (baseline == null) {
            return "Baseline: Not established (new user - treat with caution)";
        }

        StringBuilder sb = new StringBuilder();
        sb.append("User Baseline (compare with current request):\n");

        // 1. IP 패턴 - raw 데이터만 제공
        String[] normalIps = baseline.getNormalIpRanges();
        sb.append(String.format("  Normal IPs: %s\n",
            normalIps != null && normalIps.length > 0 ? String.join(", ", normalIps) : "none"));

        String currentIp = currentEvent != null ? currentEvent.getSourceIp() : "unknown";
        sb.append(String.format("  Current IP: %s\n", currentIp));

        // 2. 시간 패턴 - raw 데이터만 제공
        Integer[] normalHours = baseline.getNormalAccessHours();
        sb.append(String.format("  Normal Hours: %s\n",
            normalHours != null && normalHours.length > 0 ? Arrays.toString(normalHours) : "none"));

        int currentHour = currentEvent != null && currentEvent.getTimestamp() != null
            ? currentEvent.getTimestamp().getHour() : -1;
        sb.append(String.format("  Current Hour: %d\n", currentHour));

        // 3. 경로 패턴 - raw 데이터만 제공
        String[] frequentPaths = baseline.getFrequentPaths();
        if (frequentPaths != null && frequentPaths.length > 0) {
            int maxPaths = Math.min(3, frequentPaths.length);
            sb.append(String.format("  Frequent Paths: %s\n",
                String.join(", ", Arrays.copyOf(frequentPaths, maxPaths))));
        }

        String currentPath = extractPath(currentEvent);
        if (currentPath != null) {
            sb.append(String.format("  Current Path: %s\n", currentPath));
        }

        // 4. 신뢰도 정보
        sb.append(String.format("  Baseline Confidence: %.2f (updates: %d)\n",
            baseline.getConfidence() != null ? baseline.getConfidence() : 0.0,
            baseline.getUpdateCount() != null ? baseline.getUpdateCount() : 0));

        return sb.toString();
    }

    // Phase 9: analyzeDeviations() 제거 - AI Native 위반 (규칙 기반 점수 계산)
    // Phase 9: calculateDeviationScore() 제거 - AI Native 위반 (중복 + 규칙 기반)
    // Phase 9: is* 헬퍼 메서드 5개 제거 - AI Native 위반 (플랫폼 판단 로직)
    //   - isIpInNormalRange(), isHourInNormalRange(), isPathFrequent()
    //   - isDeviceTrusted(), isUserAgentNormal()
    //
    // AI Native 원칙: 플랫폼은 raw 데이터만 제공, LLM이 직접 비교하여 판단

    // ========== Helper Methods (raw 데이터 추출만 유지) ==========

    /**
     * SecurityEvent에서 경로 추출 (raw 데이터 추출 유틸리티)
     */
    private String extractPath(SecurityEvent event) {
        if (event == null) {
            return null;
        }

        // targetResource 필드 우선 사용
        if (event.getTargetResource() != null && !event.getTargetResource().isEmpty()) {
            return event.getTargetResource();
        }

        // metadata에서 requestPath 추출
        Map<String, Object> metadata = event.getMetadata();
        if (metadata != null && metadata.containsKey("requestPath")) {
            Object path = metadata.get("requestPath");
            if (path != null) {
                return path.toString();
            }
        }

        return null;
    }

    /**
     * SecurityEvent에서 디바이스 ID 추출
     */
    private String extractDeviceId(SecurityEvent event) {
        if (event == null) {
            return null;
        }

        // metadata에서 deviceId 추출
        Map<String, Object> metadata = event.getMetadata();
        if (metadata != null && metadata.containsKey("deviceId")) {
            Object deviceId = metadata.get("deviceId");
            if (deviceId != null) {
                return deviceId.toString();
            }
        }

        // User-Agent 해시를 디바이스 ID로 사용 (fallback)
        if (event.getUserAgent() != null && !event.getUserAgent().isEmpty()) {
            return String.valueOf(event.getUserAgent().hashCode());
        }

        return null;
    }
}
