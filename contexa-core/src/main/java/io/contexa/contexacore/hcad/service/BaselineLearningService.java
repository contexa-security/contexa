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
     * Baseline을 LLM 프롬프트 형식으로 변환 (AI Native)
     *
     * BaselineVector의 풍부한 데이터를 LLM이 이해할 수 있는 형식으로 변환
     * - 정상 IP 범위
     * - 정상 접근 시간대
     * - 평균 요청 수
     * - 자주 접근하는 경로
     * - 신뢰 디바이스
     *
     * LLM이 "현재 요청"과 "사용자의 정상 패턴"을 비교하여
     * 이상 여부를 판단할 수 있도록 컨텍스트 제공
     *
     * @param userId 사용자 ID
     * @param currentEvent 현재 이벤트 (비교용)
     * @return LLM 프롬프트 형식 문자열
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
        sb.append("User Baseline Pattern:\n");

        // 1. IP 패턴
        String[] normalIps = baseline.getNormalIpRanges();
        sb.append(String.format("  - Normal IP Ranges: %s\n",
            normalIps != null && normalIps.length > 0 ? String.join(", ", normalIps) : "not established"));

        String currentIp = currentEvent != null ? currentEvent.getSourceIp() : null;
        boolean ipInRange = isIpInNormalRange(currentIp, normalIps);
        sb.append(String.format("  - Current IP: %s, In Normal Range: %s\n",
            currentIp != null ? currentIp : "unknown", ipInRange));

        // 2. 시간 패턴
        Integer[] normalHours = baseline.getNormalAccessHours();
        sb.append(String.format("  - Normal Access Hours: %s\n",
            normalHours != null && normalHours.length > 0 ? Arrays.toString(normalHours) : "not established"));

        int currentHour = currentEvent != null && currentEvent.getTimestamp() != null
            ? currentEvent.getTimestamp().getHour() : -1;
        boolean hourNormal = isHourInNormalRange(currentHour, normalHours);
        sb.append(String.format("  - Current Hour: %d, Normal: %s\n", currentHour, hourNormal));

        // 3. 요청 패턴
        Long avgReqs = baseline.getAvgRequestCount();
        sb.append(String.format("  - Avg Daily Requests: %d\n", avgReqs != null ? avgReqs : 0));

        // 4. 신뢰 점수
        Double avgTrustScore = baseline.getAvgTrustScore();
        sb.append(String.format("  - Avg Trust Score: %.2f\n", avgTrustScore != null ? avgTrustScore : 0.0));

        // 5. 경로 패턴
        String[] frequentPaths = baseline.getFrequentPaths();
        if (frequentPaths != null && frequentPaths.length > 0) {
            int maxPaths = Math.min(5, frequentPaths.length);
            sb.append(String.format("  - Frequent Paths: %s\n",
                String.join(", ", Arrays.copyOf(frequentPaths, maxPaths))));
        } else {
            sb.append("  - Frequent Paths: not established\n");
        }

        String currentPath = extractPath(currentEvent);
        boolean pathFrequent = isPathFrequent(currentPath, frequentPaths);
        sb.append(String.format("  - Current Path: %s, Frequent: %s\n",
            currentPath != null ? currentPath : "unknown", pathFrequent));

        // 6. 디바이스 패턴
        String[] trustedDevices = baseline.getTrustedDeviceIds();
        sb.append(String.format("  - Trusted Devices Count: %d\n",
            trustedDevices != null ? trustedDevices.length : 0));

        String currentDeviceId = extractDeviceId(currentEvent);
        boolean deviceTrusted = isDeviceTrusted(currentDeviceId, trustedDevices);
        sb.append(String.format("  - Current Device Trusted: %s\n", deviceTrusted));

        // 7. 기준선 신뢰도
        sb.append(String.format("  - Baseline Confidence: %.2f (updates: %d)\n",
            baseline.getConfidence() != null ? baseline.getConfidence() : 0.0,
            baseline.getUpdateCount() != null ? baseline.getUpdateCount() : 0));

        return sb.toString();
    }

    /**
     * 현재 요청과 Baseline의 편차 분석 (AI Native)
     *
     * LLM에게 현재 요청이 사용자의 정상 패턴에서 얼마나 벗어났는지 분석 결과 제공
     * - 편차 점수 (0.0 ~ 1.0)
     * - 구체적인 편차 항목
     * - 위험 요소 설명
     *
     * @param userId 사용자 ID
     * @param currentEvent 현재 이벤트
     * @return 편차 분석 결과 문자열
     */
    public String analyzeDeviations(String userId, SecurityEvent currentEvent) {
        if (userId == null || currentEvent == null) {
            return "Deviation: Cannot analyze (missing userId or event)";
        }

        BaselineVector baseline = getBaseline(userId);
        if (baseline == null) {
            return "Deviation: No baseline for comparison (new user - requires careful analysis)";
        }

        List<String> deviations = new ArrayList<>();
        List<String> riskFactors = new ArrayList<>();
        double deviationScore = 0.0;

        // 1. IP 편차 분석
        String[] normalIps = baseline.getNormalIpRanges();
        String currentIp = currentEvent.getSourceIp();
        if (normalIps != null && normalIps.length > 0 && currentIp != null
            && !isIpInNormalRange(currentIp, normalIps)) {
            deviations.add("IP address outside normal range");
            riskFactors.add("New IP: " + currentIp + ", Normal ranges: " + String.join(", ", normalIps));
            deviationScore += 0.30;
        }

        // 2. 시간 편차 분석
        Integer[] normalHours = baseline.getNormalAccessHours();
        int currentHour = currentEvent.getTimestamp() != null
            ? currentEvent.getTimestamp().getHour() : -1;
        if (normalHours != null && normalHours.length > 0 && currentHour >= 0
            && !isHourInNormalRange(currentHour, normalHours)) {
            deviations.add("Access time outside normal hours");
            riskFactors.add("Current hour: " + currentHour + ", Normal hours: " + Arrays.toString(normalHours));
            deviationScore += 0.20;
        }

        // 3. 경로 편차 분석
        String[] frequentPaths = baseline.getFrequentPaths();
        String currentPath = extractPath(currentEvent);
        if (frequentPaths != null && frequentPaths.length > 0 && currentPath != null
            && !isPathFrequent(currentPath, frequentPaths)) {
            deviations.add("Accessing unfamiliar path");
            riskFactors.add("Current path: " + currentPath);
            deviationScore += 0.15;
        }

        // 4. 디바이스 편차 분석
        String[] trustedDevices = baseline.getTrustedDeviceIds();
        String currentDeviceId = extractDeviceId(currentEvent);
        if (trustedDevices != null && trustedDevices.length > 0 && currentDeviceId != null
            && !isDeviceTrusted(currentDeviceId, trustedDevices)) {
            deviations.add("Unknown device");
            riskFactors.add("Device not in trusted list");
            deviationScore += 0.20;
        }

        // 5. User-Agent 편차 분석
        String[] normalUserAgents = baseline.getNormalUserAgents();
        String currentUserAgent = currentEvent.getUserAgent();
        if (normalUserAgents != null && normalUserAgents.length > 0 && currentUserAgent != null
            && !isUserAgentNormal(currentUserAgent, normalUserAgents)) {
            deviations.add("Unusual User-Agent");
            riskFactors.add("User-Agent not in normal list");
            deviationScore += 0.15;
        }

        // 결과 문자열 생성
        StringBuilder sb = new StringBuilder();
        sb.append("Deviation Analysis:\n");
        sb.append(String.format("  - Overall Deviation Score: %.2f\n", Math.min(1.0, deviationScore)));

        if (!deviations.isEmpty()) {
            sb.append("  - Detected Deviations:\n");
            for (String d : deviations) {
                sb.append("    * ").append(d).append("\n");
            }
            sb.append("  - Risk Factors:\n");
            for (String r : riskFactors) {
                sb.append("    * ").append(r).append("\n");
            }
        } else {
            sb.append("  - No significant deviations detected\n");
            sb.append("  - Request matches established baseline patterns\n");
        }

        // 기준선 신뢰도에 따른 해석 가이드
        Double confidence = baseline.getConfidence();
        if (confidence != null && confidence < 0.5) {
            sb.append("  - NOTE: Baseline confidence is low (").append(String.format("%.2f", confidence))
              .append("), deviations may be less reliable\n");
        }

        return sb.toString();
    }

    /**
     * 편차 점수 계산 (수치만 반환)
     *
     * @param userId 사용자 ID
     * @param currentEvent 현재 이벤트
     * @return 편차 점수 (0.0 ~ 1.0)
     */
    public double calculateDeviationScore(String userId, SecurityEvent currentEvent) {
        if (userId == null || currentEvent == null) {
            return 0.5; // 분석 불가 시 중립값
        }

        BaselineVector baseline = getBaseline(userId);
        if (baseline == null) {
            return 0.5; // baseline 없음 - 신규 사용자
        }

        double deviationScore = 0.0;

        // IP 편차
        String[] normalIps = baseline.getNormalIpRanges();
        if (normalIps != null && normalIps.length > 0
            && !isIpInNormalRange(currentEvent.getSourceIp(), normalIps)) {
            deviationScore += 0.30;
        }

        // 시간 편차
        Integer[] normalHours = baseline.getNormalAccessHours();
        int currentHour = currentEvent.getTimestamp() != null
            ? currentEvent.getTimestamp().getHour() : -1;
        if (normalHours != null && normalHours.length > 0
            && !isHourInNormalRange(currentHour, normalHours)) {
            deviationScore += 0.20;
        }

        // 경로 편차
        String[] frequentPaths = baseline.getFrequentPaths();
        String currentPath = extractPath(currentEvent);
        if (frequentPaths != null && frequentPaths.length > 0
            && !isPathFrequent(currentPath, frequentPaths)) {
            deviationScore += 0.15;
        }

        // 디바이스 편차
        String[] trustedDevices = baseline.getTrustedDeviceIds();
        String currentDeviceId = extractDeviceId(currentEvent);
        if (trustedDevices != null && trustedDevices.length > 0
            && !isDeviceTrusted(currentDeviceId, trustedDevices)) {
            deviationScore += 0.20;
        }

        // User-Agent 편차
        String[] normalUserAgents = baseline.getNormalUserAgents();
        if (normalUserAgents != null && normalUserAgents.length > 0
            && !isUserAgentNormal(currentEvent.getUserAgent(), normalUserAgents)) {
            deviationScore += 0.15;
        }

        return Math.min(1.0, deviationScore);
    }

    // ========== Helper Methods ==========

    /**
     * IP가 정상 범위에 속하는지 확인
     */
    private boolean isIpInNormalRange(String ip, String[] normalRanges) {
        if (ip == null || normalRanges == null || normalRanges.length == 0) {
            return false;
        }

        for (String range : normalRanges) {
            if (range != null && ip.startsWith(range)) {
                return true;
            }
        }
        return false;
    }

    /**
     * 현재 시간이 정상 접근 시간대에 속하는지 확인
     */
    private boolean isHourInNormalRange(int hour, Integer[] normalHours) {
        if (hour < 0 || normalHours == null || normalHours.length == 0) {
            return false;
        }

        for (Integer normalHour : normalHours) {
            if (normalHour != null && normalHour == hour) {
                return true;
            }
        }
        return false;
    }

    /**
     * 현재 경로가 자주 접근하는 경로인지 확인
     */
    private boolean isPathFrequent(String path, String[] frequentPaths) {
        if (path == null || frequentPaths == null || frequentPaths.length == 0) {
            return false;
        }

        for (String frequentPath : frequentPaths) {
            if (frequentPath != null && path.equals(frequentPath)) {
                return true;
            }
        }
        return false;
    }

    /**
     * 디바이스가 신뢰할 수 있는 디바이스인지 확인
     */
    private boolean isDeviceTrusted(String deviceId, String[] trustedDevices) {
        if (deviceId == null || trustedDevices == null || trustedDevices.length == 0) {
            return false;
        }

        for (String trustedDevice : trustedDevices) {
            if (trustedDevice != null && trustedDevice.equals(deviceId)) {
                return true;
            }
        }
        return false;
    }

    /**
     * User-Agent가 정상 목록에 있는지 확인
     */
    private boolean isUserAgentNormal(String userAgent, String[] normalUserAgents) {
        if (userAgent == null || normalUserAgents == null || normalUserAgents.length == 0) {
            return false;
        }

        for (String normalUa : normalUserAgents) {
            if (normalUa != null && userAgent.contains(normalUa)) {
                return true;
            }
        }
        return false;
    }

    /**
     * SecurityEvent에서 경로 추출
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
