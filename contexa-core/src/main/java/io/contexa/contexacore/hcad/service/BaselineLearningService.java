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
 * Baseline Learning Service (AI Native v3.4.0)
 *
 * 정상 패턴 학습 서비스 - EMA(Exponential Moving Average) 기반
 *
 * AI Native 원칙 (v3.4.0 강화):
 * - LLM이 ALLOW를 반환하면 무조건 학습 (confidence 임계값 검증 제거)
 * - LLM이 확신 없으면 ALLOW 대신 CHALLENGE/ESCALATE를 반환하도록 프롬프트에서 강제
 * - 학습된 Baseline은 Layer1 프롬프트의 컨텍스트로 제공
 * - LLM이 Baseline과 현재 요청을 비교하여 판단
 *
 * EMA 공식:
 * newBaseline = (alpha * currentValue) + ((1 - alpha) * oldBaseline)
 * - alpha = 0.1 (기본값, 새 값에 10% 가중치)
 *
 * 학습 조건 (AI Native v3.4.0):
 * - action = ALLOW (LLM이 허용 결정) -> 무조건 학습
 * - isAnomaly = false (LLM이 정상 판단)
 * - confidence 임계값 검증 제거 (규칙 기반 판단 = AI Native 위반)
 *
 * 기준선 오염 불가능 증명:
 * - 공격자 패턴 -> LLM이 BLOCK -> 학습 안 됨
 * - 애매한 패턴 -> LLM이 CHALLENGE/ESCALATE -> 학습 안 됨
 * - ALLOW는 "확실히 정상"일 때만 반환 -> 무조건 학습해도 안전
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
     * 정상 패턴 학습 수행 (SecurityEvent 기반 - ColdPathEventProcessor용)
     *
     * AI Native: LLM이 판단한 결과를 바탕으로 정상 패턴 학습
     * ColdPathEventProcessor에서 ThreatAnalysisResult만 사용 가능한 경우를 위한 오버로드
     *
     * @param userId 사용자 ID
     * @param decision LLM의 SecurityDecision
     * @param event SecurityEvent (IP, 시간, 경로 추출용)
     * @return 학습 수행 여부
     */
    public boolean learnIfNormal(String userId, SecurityDecision decision, SecurityEvent event) {
        if (!learningEnabled) {
            log.debug("[BaselineLearningService] 학습 비활성화 상태");
            return false;
        }

        if (userId == null || decision == null) {
            log.debug("[BaselineLearningService] userId 또는 decision이 null");
            return false;
        }

        // 학습 조건 검증: action=ALLOW, confidence >= 0.7
        if (!shouldLearnFromSecurityEvent(decision)) {
            log.debug("[BaselineLearningService] SecurityEvent 학습 조건 미충족: userId={}, action={}, confidence={}",
                userId,
                decision.getAction(),
                decision.getConfidence());
            return false;
        }

        try {
            // 기존 Baseline 조회
            BaselineVector currentBaseline = getBaseline(userId);

            // SecurityEvent 기반 EMA 업데이트
            BaselineVector newBaseline = updateWithEMAFromSecurityEvent(currentBaseline, userId, decision, event);

            // Redis에 저장
            saveBaseline(userId, newBaseline);

            log.info("[BaselineLearningService][AI Native] SecurityEvent 기반 정상 패턴 학습 완료: userId={}, avgTrustScore={}, updateCount={}",
                userId,
                String.format("%.3f", newBaseline.getAvgTrustScore()),
                newBaseline.getUpdateCount());

            return true;

        } catch (Exception e) {
            log.error("[BaselineLearningService] SecurityEvent 기반 학습 실패: userId={}", userId, e);
            return false;
        }
    }

    /**
     * 정상 패턴 학습 수행 (HCADAnalysisResult 기반)
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
     * 학습 조건 검증 (AI Native v3.4.0)
     *
     * AI Native 학습 조건:
     * - action = ALLOW (LLM이 허용 결정) -> 무조건 학습
     * - analysisResult != null (검증 데이터 필수 - Zero Trust 원칙)
     * - isAnomaly = false (LLM이 정상 판단)
     *
     * v3.4.0 변경: confidence 임계값 검증 제거
     * - 규칙 기반 판단은 AI Native 원칙 위반
     * - LLM이 확신 없으면 ALLOW 대신 CHALLENGE/ESCALATE 반환하도록 프롬프트에서 강제
     *
     * Zero Trust 원칙: 검증 데이터 없이는 학습 금지
     * - 악의적 요청이 첫 Baseline이 되는 것을 방지
     */
    private boolean shouldLearn(SecurityDecision decision, HCADAnalysisResult analysisResult) {
        // Zero Trust: analysisResult가 null이면 학습 금지
        // 검증 데이터 없이 학습하면 악의적 요청이 Baseline이 될 수 있음
        if (analysisResult == null) {
            log.warn("[BaselineLearningService][Zero Trust] analysisResult is null, skipping learning");
            return false;
        }

        // 1. action = ALLOW
        if (decision.getAction() != SecurityDecision.Action.ALLOW) {
            return false;
        }

        // 2. isAnomaly = false
        if (analysisResult.isAnomaly()) {
            return false;
        }

        // AI Native v3.4.0: confidence 임계값 검증 제거
        // LLM이 ALLOW를 반환했으면 무조건 학습
        // LLM이 확신 없으면 ALLOW 대신 CHALLENGE/ESCALATE를 반환해야 함
        return true;
    }

    /**
     * SecurityEvent 기반 학습 조건 검증 (AI Native v3.4.0)
     *
     * AI Native 학습 조건 (SecurityEvent용 - HCADAnalysisResult 없이):
     * - action = ALLOW (LLM이 허용 결정) -> 무조건 학습
     *
     * v3.4.0 변경: confidence 임계값 검증 제거
     * - 규칙 기반 판단은 AI Native 원칙 위반
     * - LLM이 확신 없으면 ALLOW 대신 CHALLENGE/ESCALATE 반환하도록 프롬프트에서 강제
     *
     * 주의: HCADAnalysisResult.isAnomaly() 검증 없이 진행
     * ColdPathEventProcessor의 ThreatAnalysisResult.getFinalDecision()이
     * 이미 이상 여부를 반영한 action을 반환하므로 action=ALLOW면 정상으로 판단
     */
    private boolean shouldLearnFromSecurityEvent(SecurityDecision decision) {
        // AI Native v3.4.0: ALLOW면 무조건 학습
        // LLM이 확신 없으면 ALLOW 대신 CHALLENGE/ESCALATE를 반환해야 함
        return decision.getAction() == SecurityDecision.Action.ALLOW;
    }

    /**
     * SecurityEvent 기반 EMA Baseline 업데이트
     *
     * newValue = alpha * currentValue + (1 - alpha) * oldValue
     *
     * SecurityEvent에서 직접 IP, 시간, 경로 추출하여 Zero Trust 필수 데이터 업데이트
     *
     * @param current 기존 Baseline (null이면 첫 학습)
     * @param userId 사용자 ID
     * @param decision LLM의 SecurityDecision
     * @param event SecurityEvent
     * @return 업데이트된 BaselineVector
     */
    private BaselineVector updateWithEMAFromSecurityEvent(BaselineVector current, String userId,
                                                           SecurityDecision decision, SecurityEvent event) {
        // SecurityEvent에서 trustScore 대신 riskScore의 역수 사용 (1 - riskScore)
        // riskScore가 낮을수록 신뢰도가 높음
        double currentTrustScore = 1.0 - decision.getRiskScore();
        double currentConfidence = decision.getConfidence();

        // SecurityEvent에서 Zero Trust 필수 데이터 직접 추출
        String currentIp = event != null ? event.getSourceIp() : null;
        Integer currentHour = extractHourFromSecurityEvent(event);
        String currentPath = extractPath(event);

        if (current == null) {
            // 첫 학습: Zero Trust 필수 데이터 초기화
            BaselineVector.BaselineVectorBuilder builder = BaselineVector.builder()
                .userId(userId)
                .avgTrustScore(currentTrustScore)
                .avgRequestCount(1L)
                .updateCount(1L)
                .confidence(currentConfidence * 0.1)  // 첫 학습은 신뢰도 낮게
                .lastUpdated(Instant.now());

            // Zero Trust 필수 데이터 초기화
            if (currentIp != null) {
                String ipRange = extractIpRange(currentIp);
                builder.normalIpRanges(new String[]{ipRange});
            }
            if (currentHour != null) {
                builder.normalAccessHours(new Integer[]{currentHour});
            }
            if (currentPath != null) {
                builder.frequentPaths(new String[]{currentPath});
            }

            return builder.build();
        }

        // EMA 적용
        double oldTrustScore = current.getAvgTrustScore() != null ? current.getAvgTrustScore() : 0.5;
        double newTrustScore = alpha * currentTrustScore + (1 - alpha) * oldTrustScore;

        // 신뢰도 증가 (최대 1.0)
        double oldConfidence = current.getConfidence() != null ? current.getConfidence() : 0.1;
        double newConfidence = Math.min(1.0, oldConfidence + 0.01);

        long oldUpdateCount = current.getUpdateCount() != null ? current.getUpdateCount() : 0L;
        long oldRequestCount = current.getAvgRequestCount() != null ? current.getAvgRequestCount() : 0L;

        // Zero Trust 필수 데이터 업데이트
        String[] normalIpRanges = updateNormalIpRanges(current.getNormalIpRanges(), currentIp);
        Integer[] normalAccessHours = updateNormalAccessHours(current.getNormalAccessHours(), currentHour);
        String[] frequentPaths = updateFrequentPaths(current.getFrequentPaths(), currentPath);

        return BaselineVector.builder()
            .userId(userId)
            .avgTrustScore(newTrustScore)
            .avgRequestCount(oldRequestCount + 1)
            .updateCount(oldUpdateCount + 1)
            .confidence(newConfidence)
            .lastUpdated(Instant.now())
            // Zero Trust 필수 데이터
            .normalIpRanges(normalIpRanges)
            .normalAccessHours(normalAccessHours)
            .frequentPaths(frequentPaths)
            .build();
    }

    /**
     * SecurityEvent에서 시간(hour) 추출
     *
     * @param event SecurityEvent
     * @return 시간 (0-23), 없으면 null
     */
    private Integer extractHourFromSecurityEvent(SecurityEvent event) {
        if (event == null || event.getTimestamp() == null) {
            return null;
        }
        return event.getTimestamp().getHour();
    }

    /**
     * EMA 기반 Baseline 업데이트 (HCADAnalysisResult 기반)
     *
     * newValue = alpha * currentValue + (1 - alpha) * oldValue
     *
     * BaselineVector 필드 업데이트:
     * - avgTrustScore: 평균 신뢰 점수 (EMA)
     * - avgRequestCount: 평균 요청 수
     * - updateCount: 업데이트 횟수
     * - confidence: 기준선 신뢰도
     * - lastUpdated: 마지막 업데이트 시간
     *
     * Zero Trust 필수 데이터:
     * - normalIpRanges: 정상 IP 대역 (LLM 비교용)
     * - normalAccessHours: 정상 접근 시간대 (LLM 비교용)
     * - frequentPaths: 자주 접근하는 경로 (LLM 비교용)
     */
    private BaselineVector updateWithEMA(BaselineVector current, String userId,
                                          SecurityDecision decision, HCADAnalysisResult analysisResult) {
        // Zero Trust: analysisResult가 null이면 기본값 0.5 (중립) 사용 - 최고 신뢰점수 부여 금지
        double currentTrustScore = analysisResult != null ? analysisResult.getTrustScore() : 0.5;
        double currentConfidence = decision.getConfidence();

        // analysisResult에서 Zero Trust 필수 데이터 추출
        String currentIp = extractIpFromAnalysisResult(analysisResult);
        Integer currentHour = extractHourFromAnalysisResult(analysisResult);
        String currentPath = extractPathFromAnalysisResult(analysisResult);

        if (current == null) {
            // 첫 학습: Zero Trust 필수 데이터 초기화
            BaselineVector.BaselineVectorBuilder builder = BaselineVector.builder()
                .userId(userId)
                .avgTrustScore(currentTrustScore)
                .avgRequestCount(1L)
                .updateCount(1L)
                .confidence(currentConfidence * 0.1)  // 첫 학습은 신뢰도 낮게
                .lastUpdated(Instant.now());

            // Zero Trust 필수 데이터 초기화
            if (currentIp != null) {
                String ipRange = extractIpRange(currentIp);
                builder.normalIpRanges(new String[]{ipRange});
            }
            if (currentHour != null) {
                builder.normalAccessHours(new Integer[]{currentHour});
            }
            if (currentPath != null) {
                builder.frequentPaths(new String[]{currentPath});
            }

            return builder.build();
        }

        // EMA 적용
        double oldTrustScore = current.getAvgTrustScore() != null ? current.getAvgTrustScore() : 0.5;
        double newTrustScore = alpha * currentTrustScore + (1 - alpha) * oldTrustScore;

        // 신뢰도 증가 (최대 1.0)
        double oldConfidence = current.getConfidence() != null ? current.getConfidence() : 0.1;
        double newConfidence = Math.min(1.0, oldConfidence + 0.01);

        long oldUpdateCount = current.getUpdateCount() != null ? current.getUpdateCount() : 0L;
        long oldRequestCount = current.getAvgRequestCount() != null ? current.getAvgRequestCount() : 0L;

        // Zero Trust 필수 데이터 업데이트
        String[] normalIpRanges = updateNormalIpRanges(current.getNormalIpRanges(), currentIp);
        Integer[] normalAccessHours = updateNormalAccessHours(current.getNormalAccessHours(), currentHour);
        String[] frequentPaths = updateFrequentPaths(current.getFrequentPaths(), currentPath);

        return BaselineVector.builder()
            .userId(userId)
            .avgTrustScore(newTrustScore)
            .avgRequestCount(oldRequestCount + 1)
            .updateCount(oldUpdateCount + 1)
            .confidence(newConfidence)
            .lastUpdated(Instant.now())
            // Zero Trust 필수 데이터
            .normalIpRanges(normalIpRanges)
            .normalAccessHours(normalAccessHours)
            .frequentPaths(frequentPaths)
            .build();
    }

    /**
     * analysisResult에서 IP 추출
     *
     * HCADAnalysisResult.getContext().getRemoteIp() 사용
     */
    private String extractIpFromAnalysisResult(HCADAnalysisResult analysisResult) {
        if (analysisResult == null) {
            return null;
        }
        // HCADAnalysisResult의 context에서 remoteIp 추출
        io.contexa.contexacommon.hcad.domain.HCADContext context = analysisResult.getContext();
        if (context == null) {
            return null;
        }
        return context.getRemoteIp();
    }

    /**
     * analysisResult에서 시간 추출
     *
     * HCADAnalysisResult.getContext().getTimestamp() 사용
     */
    private Integer extractHourFromAnalysisResult(HCADAnalysisResult analysisResult) {
        if (analysisResult == null) {
            return null;
        }
        io.contexa.contexacommon.hcad.domain.HCADContext context = analysisResult.getContext();
        if (context == null || context.getTimestamp() == null) {
            return null;
        }
        return context.getTimestamp().atZone(java.time.ZoneId.systemDefault()).getHour();
    }

    /**
     * analysisResult에서 경로 추출
     *
     * HCADAnalysisResult.getContext().getRequestPath() 사용
     */
    private String extractPathFromAnalysisResult(HCADAnalysisResult analysisResult) {
        if (analysisResult == null) {
            return null;
        }
        io.contexa.contexacommon.hcad.domain.HCADContext context = analysisResult.getContext();
        if (context == null) {
            return null;
        }
        return context.getRequestPath();
    }

    /**
     * IP 주소에서 C 클래스 대역 추출 (예: 192.168.1.100 -> 192.168.1)
     */
    private String extractIpRange(String ip) {
        if (ip == null || ip.isEmpty()) {
            return null;
        }
        int lastDot = ip.lastIndexOf('.');
        if (lastDot > 0) {
            return ip.substring(0, lastDot);
        }
        return ip;
    }

    /**
     * normalIpRanges 업데이트 (최대 5개 유지)
     */
    private String[] updateNormalIpRanges(String[] current, String newIp) {
        if (newIp == null) {
            return current;
        }
        String ipRange = extractIpRange(newIp);
        if (ipRange == null) {
            return current;
        }

        if (current == null || current.length == 0) {
            return new String[]{ipRange};
        }

        // 이미 존재하면 그대로 반환
        for (String existing : current) {
            if (ipRange.equals(existing)) {
                return current;
            }
        }

        // 최대 5개 유지
        if (current.length >= 5) {
            // 가장 오래된 것 제거하고 새로운 것 추가
            String[] updated = new String[5];
            System.arraycopy(current, 1, updated, 0, 4);
            updated[4] = ipRange;
            return updated;
        }

        // 새로운 것 추가
        String[] updated = new String[current.length + 1];
        System.arraycopy(current, 0, updated, 0, current.length);
        updated[current.length] = ipRange;
        return updated;
    }

    /**
     * normalAccessHours 업데이트 (최대 24개 유지)
     */
    private Integer[] updateNormalAccessHours(Integer[] current, Integer newHour) {
        if (newHour == null || newHour < 0 || newHour > 23) {
            return current;
        }

        if (current == null || current.length == 0) {
            return new Integer[]{newHour};
        }

        // 이미 존재하면 그대로 반환
        for (Integer existing : current) {
            if (newHour.equals(existing)) {
                return current;
            }
        }

        // 최대 24개 유지
        if (current.length >= 24) {
            return current;  // 모든 시간대 포함
        }

        // 새로운 것 추가
        Integer[] updated = new Integer[current.length + 1];
        System.arraycopy(current, 0, updated, 0, current.length);
        updated[current.length] = newHour;
        return updated;
    }

    /**
     * frequentPaths 업데이트 (최대 10개 유지)
     */
    private String[] updateFrequentPaths(String[] current, String newPath) {
        if (newPath == null || newPath.isEmpty()) {
            return current;
        }

        if (current == null || current.length == 0) {
            return new String[]{newPath};
        }

        // 이미 존재하면 그대로 반환
        for (String existing : current) {
            if (newPath.equals(existing)) {
                return current;
            }
        }

        // 최대 10개 유지
        if (current.length >= 10) {
            // 가장 오래된 것 제거하고 새로운 것 추가
            String[] updated = new String[10];
            System.arraycopy(current, 1, updated, 0, 9);
            updated[9] = newPath;
            return updated;
        }

        // 새로운 것 추가
        String[] updated = new String[current.length + 1];
        System.arraycopy(current, 0, updated, 0, current.length);
        updated[current.length] = newPath;
        return updated;
    }

    /**
     * Baseline 조회 (Zero Trust 필수 데이터 포함)
     *
     * 조회 필드:
     * - userId, avgTrustScore, avgRequestCount, updateCount, confidence, lastUpdated
     * - normalIpRanges: 정상 IP 대역 (CSV -> String[] 변환)
     * - normalAccessHours: 정상 접근 시간대 (CSV -> Integer[] 변환)
     * - frequentPaths: 자주 접근하는 경로 (CSV -> String[] 변환)
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
                // Zero Trust 필수 데이터 조회
                .normalIpRanges(parseStringArray(data.get("normalIpRanges")))
                .normalAccessHours(parseIntegerArray(data.get("normalAccessHours")))
                .frequentPaths(parseStringArray(data.get("frequentPaths")))
                .build();

        } catch (Exception e) {
            log.error("[BaselineLearningService] Baseline 조회 실패: userId={}", userId, e);
            return null;
        }
    }

    /**
     * CSV 문자열을 String[] 배열로 변환
     */
    private String[] parseStringArray(Object value) {
        if (value instanceof String && !((String) value).isEmpty()) {
            return ((String) value).split(",");
        }
        return null;
    }

    /**
     * CSV 문자열을 Integer[] 배열로 변환
     */
    private Integer[] parseIntegerArray(Object value) {
        if (value instanceof String && !((String) value).isEmpty()) {
            try {
                return Arrays.stream(((String) value).split(","))
                    .map(Integer::parseInt)
                    .toArray(Integer[]::new);
            } catch (NumberFormatException e) {
                log.warn("[BaselineLearningService] Integer 배열 파싱 실패: {}", value);
                return null;
            }
        }
        return null;
    }

    /**
     * Baseline 저장 (Zero Trust 필수 데이터 포함)
     *
     * 저장 필드:
     * - userId, avgTrustScore, avgRequestCount, updateCount, confidence, lastUpdated
     * - normalIpRanges: 정상 IP 대역 (CSV 형식)
     * - normalAccessHours: 정상 접근 시간대 (CSV 형식)
     * - frequentPaths: 자주 접근하는 경로 (CSV 형식)
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

            // Zero Trust 필수 데이터 저장 (CSV 형식)
            if (baseline.getNormalIpRanges() != null && baseline.getNormalIpRanges().length > 0) {
                data.put("normalIpRanges", String.join(",", baseline.getNormalIpRanges()));
            }
            if (baseline.getNormalAccessHours() != null && baseline.getNormalAccessHours().length > 0) {
                data.put("normalAccessHours", Arrays.stream(baseline.getNormalAccessHours())
                    .map(String::valueOf)
                    .collect(java.util.stream.Collectors.joining(",")));
            }
            if (baseline.getFrequentPaths() != null && baseline.getFrequentPaths().length > 0) {
                data.put("frequentPaths", String.join(",", baseline.getFrequentPaths()));
            }

            redisTemplate.opsForHash().putAll(key, data);
            redisTemplate.expire(key, BASELINE_TTL);

            log.debug("[BaselineLearningService] Baseline 저장 완료: userId={}, normalIpRanges={}, normalAccessHours={}, frequentPaths={}",
                userId,
                baseline.getNormalIpRanges() != null ? baseline.getNormalIpRanges().length : 0,
                baseline.getNormalAccessHours() != null ? baseline.getNormalAccessHours().length : 0,
                baseline.getFrequentPaths() != null ? baseline.getFrequentPaths().length : 0);

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
     * Baseline을 LLM 프롬프트 형식으로 변환 (AI Native v2.0 + Zero Trust)
     *
     * Phase 9 리팩토링:
     * - 플랫폼 판단 로직 제거 (is*() 메서드 호출 제거)
     * - raw 데이터만 제공, LLM이 직접 비교하여 판단
     *
     * AI Native 원칙:
     * - 플랫폼은 "정상 여부" 판단 금지
     * - LLM이 baseline과 현재 요청을 직접 비교
     *
     * Zero Trust 원칙:
     * - 신규 사용자 (Baseline 없음)에 대한 명시적 경고
     * - LLM이 ALLOW를 반환하지 않도록 강력한 지침 제공
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
            // Zero Trust: 신규 사용자에 대한 강화된 경고
            return buildNewUserWarning(userId, currentEvent);
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
     * 신규 사용자에 대한 Zero Trust 경고 메시지 생성
     *
     * Zero Trust 원칙: "Never Trust, Always Verify"
     * - Baseline이 없는 신규 사용자는 검증 불가
     * - 고권한 계정(admin, root, system)은 CHALLENGE 권장
     * - 일반 사용자는 ESCALATE 권장
     * - ALLOW 반환 금지
     *
     * @param userId 사용자 ID
     * @param currentEvent 현재 이벤트
     * @return Zero Trust 경고 메시지
     */
    private String buildNewUserWarning(String userId, SecurityEvent currentEvent) {
        StringBuilder sb = new StringBuilder();

        sb.append("=== CRITICAL: NO USER BASELINE ===\n");
        sb.append("This user has NO established behavior pattern.\n");
        sb.append("Zero Trust Principle: \"Never Trust, Always Verify\"\n\n");

        sb.append("WITHOUT baseline comparison:\n");
        sb.append("- You CANNOT determine if this behavior is normal\n");
        sb.append("- You CANNOT compare against historical patterns\n");
        sb.append("- This could be a first-time attacker\n\n");

        // 현재 요청 정보 제공 (LLM 분석용)
        sb.append("Current Request Context:\n");
        if (currentEvent != null) {
            String sourceIp = currentEvent.getSourceIp();
            sb.append(String.format("  IP: %s\n", sourceIp != null ? sourceIp : "NOT_PROVIDED"));

            String sessionId = currentEvent.getSessionId();
            sb.append(String.format("  SessionId: %s\n", sessionId != null ? sessionId : "NOT_PROVIDED"));

            String userAgent = currentEvent.getUserAgent();
            if (userAgent != null && userAgent.length() > 100) {
                userAgent = userAgent.substring(0, 97) + "...";
            }
            sb.append(String.format("  UserAgent: %s\n", userAgent != null ? userAgent : "NOT_PROVIDED"));

            if (currentEvent.getTimestamp() != null) {
                sb.append(String.format("  Timestamp: %s\n", currentEvent.getTimestamp()));
            }
        }
        sb.append("\n");

        // 고권한 계정 여부 확인
        boolean isHighPrivilege = isHighPrivilegeUser(userId);
        if (isHighPrivilege) {
            sb.append("*** HIGH PRIVILEGE ACCOUNT DETECTED ***\n");
            sb.append("User ID contains privileged keywords (admin/root/system/superuser)\n\n");
        }

        sb.append("MANDATORY RESPONSE:\n");
        if (isHighPrivilege) {
            sb.append("- This is a HIGH PRIVILEGE account: action = CHALLENGE (MFA required)\n");
        } else {
            sb.append("- For regular users without baseline: action = ESCALATE (need Layer2 deep analysis)\n");
        }
        sb.append("- DO NOT return ALLOW without baseline verification data.\n");
        sb.append("- If critical fields (IP, SessionId) are NOT_PROVIDED, strongly consider CHALLENGE.\n");

        return sb.toString();
    }

    /**
     * 고권한 계정 여부 판별
     *
     * @param userId 사용자 ID
     * @return 고권한 계정이면 true
     */
    private boolean isHighPrivilegeUser(String userId) {
        if (userId == null || userId.isEmpty()) {
            return false;
        }
        String lowerUserId = userId.toLowerCase();
        return lowerUserId.contains("admin") ||
               lowerUserId.contains("root") ||
               lowerUserId.contains("system") ||
               lowerUserId.contains("superuser");
    }

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
