package io.contexa.contexacore.hcad.service;

import io.contexa.contexacommon.hcad.domain.BaselineMatchStatus;
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


@Slf4j
@RequiredArgsConstructor
public class BaselineLearningService {

    private final @Qualifier("generalRedisTemplate") RedisTemplate<String, Object> redisTemplate;

    private static final String BASELINE_KEY_PREFIX = "security:hcad:baseline:";
    private static final Duration BASELINE_TTL = Duration.ofDays(30);

    @Value("${hcad.baseline.learning.alpha:0.1}")
    private double alpha = 0.1;

    // AI Native v3.0: minConfidence 필드 제거 - Dead Code
    // v3.4.0에서 confidence 임계값 검증 제거 (AI Native 원칙)
    // shouldLearn(), shouldLearnFromSecurityEvent() 어디에서도 사용 안 함

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
        // AI Native v3.0: riskScore 범위 검증 - LLM 응답의 범위를 보장하지 않으므로 클램핑 적용
        // riskScore가 0.0~1.0 범위를 벗어나면 trustScore가 음수 또는 1.0 초과 → Baseline 데이터 오염 방지
        double rawTrustScore = 1.0 - decision.getRiskScore();
        double currentTrustScore = Math.max(0.0, Math.min(1.0, rawTrustScore));
        double currentConfidence = decision.getConfidence();

        // SecurityEvent에서 Zero Trust 필수 데이터 직접 추출
        String currentIp = event != null ? event.getSourceIp() : null;
        Integer currentHour = extractHourFromSecurityEvent(event);
        String currentPath = extractPath(event);
        String currentUserAgent = event != null ? event.getUserAgent() : null;

        // AI Native v8.5: UA 파싱 실패 시 학습 차단 (기준선 오염 방지)
        // "Browser (Desktop)"은 파싱 실패 기본값으로, 실제 브라우저/OS 정보가 없음
        // 이 상태로 학습하면 이후 정상 UA와 비교 시 영구 MISMATCH 발생
        if (currentUserAgent == null || currentUserAgent.isEmpty()) {
            log.warn("[Baseline][AI Native v8.5] UA 없음 - 학습 차단: userId={}", userId);
            return current;  // 기존 baseline 유지 (null이면 첫 학습 불가 -> 정상 UA로 재시도 필요)
        }
        String uaSignatureForValidation = extractUASignature(currentUserAgent);
        if ("Browser (Desktop)".equals(uaSignatureForValidation)) {
            log.warn("[Baseline][AI Native v8.5] UA 파싱 실패 - 학습 차단: userId={}, ua={}",
                userId, currentUserAgent.length() > 50 ? currentUserAgent.substring(0, 50) + "..." : currentUserAgent);
            return current;  // 기존 baseline 유지 (null이면 첫 학습 불가 -> 정상 UA로 재시도 필요)
        }

        if (current == null) {
            // 첫 학습: Zero Trust 필수 데이터 초기화
            // AI Native v7.2: learningMaturity 제거 - updateCount만으로 학습 정도 표현
            BaselineVector.BaselineVectorBuilder builder = BaselineVector.builder()
                .userId(userId)
                .avgTrustScore(currentTrustScore)
                .avgRequestCount(1L)
                .updateCount(1L)
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
            // AI Native v7.1: User-Agent 시그니처 정규화 저장 (SecurityEvent 기반 첫 학습)
            // 원본 전체 저장 대신 시그니처만 저장 (비교 일관성 확보)
            // 기존: 원본 "Mozilla/5.0 ... Chrome/120.0.0.0" 저장
            // 변경: 시그니처 "Chrome/120 (Windows)" 저장
            if (currentUserAgent != null && !currentUserAgent.isEmpty()) {
                String uaSignature = extractUASignature(currentUserAgent);
                if (uaSignature != null && !uaSignature.equals("unknown") &&
                    !uaSignature.equals("unknown (unknown)")) {
                    builder.normalUserAgents(new String[]{uaSignature});
                    log.debug("[Baseline] SecurityEvent 첫 학습 - UA 시그니처 저장: {}", uaSignature);
                } else {
                    // 파싱 실패 시 원본 저장 (fallback)
                    String truncatedUA = currentUserAgent.length() > 100
                        ? currentUserAgent.substring(0, 100) : currentUserAgent;
                    builder.normalUserAgents(new String[]{truncatedUA});
                    log.warn("[Baseline] SecurityEvent 첫 학습 - UA 파싱 실패, 원본 저장: {}", truncatedUA);
                }
            }

            return builder.build();
        }

        // EMA 적용
        double oldTrustScore = current.getAvgTrustScore() != null ? current.getAvgTrustScore() : 0.5;
        double newTrustScore = alpha * currentTrustScore + (1 - alpha) * oldTrustScore;

        long oldUpdateCount = current.getUpdateCount() != null ? current.getUpdateCount() : 0L;
        long oldRequestCount = current.getAvgRequestCount() != null ? current.getAvgRequestCount() : 0L;

        // Zero Trust 필수 데이터 업데이트
        String[] normalIpRanges = updateNormalIpRanges(current.getNormalIpRanges(), currentIp);
        Integer[] normalAccessHours = updateNormalAccessHours(current.getNormalAccessHours(), currentHour);
        String[] frequentPaths = updateFrequentPaths(current.getFrequentPaths(), currentPath);
        // AI Native v3.1: User-Agent 패턴 업데이트 - LLM 세션 하이재킹 탐지용
        // AI Native v7.3: UA 시그니처 정규화 추가 - 첫 학습과 업데이트 간 일관성 확보
        // 문제: 첫 학습 시 시그니처("Chrome/120 (Windows)")로 저장하지만 업데이트 시 원본 UA로 비교하면 불일치 발생
        // 해결: 업데이트 시에도 동일한 extractUASignature() 적용하여 시그니처 단위로 비교
        String normalizedUA = extractUASignature(currentUserAgent);
        String uaForUpdate = (normalizedUA != null && !normalizedUA.equals("unknown") &&
                              !normalizedUA.equals("unknown (unknown)"))
                             ? normalizedUA : currentUserAgent;
        String[] normalUserAgents = updateNormalUserAgents(current.getNormalUserAgents(), uaForUpdate);

        // AI Native v7.2: learningMaturity 제거 - updateCount만으로 학습 정도 표현
        return BaselineVector.builder()
            .userId(userId)
            .avgTrustScore(newTrustScore)
            .avgRequestCount(oldRequestCount + 1)
            .updateCount(oldUpdateCount + 1)
            .lastUpdated(Instant.now())
            // Zero Trust 필수 데이터
            .normalIpRanges(normalIpRanges)
            .normalAccessHours(normalAccessHours)
            .frequentPaths(frequentPaths)
            .normalUserAgents(normalUserAgents)
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
        // AI Native v3.0: trustScore 범위 검증 - LLM 응답의 범위를 보장하지 않으므로 클램핑 적용
        double rawTrustScore = analysisResult != null ? analysisResult.getTrustScore() : 0.5;
        double currentTrustScore = Math.max(0.0, Math.min(1.0, rawTrustScore));
        double currentConfidence = decision.getConfidence();

        // analysisResult에서 Zero Trust 필수 데이터 추출
        String currentIp = extractIpFromAnalysisResult(analysisResult);
        Integer currentHour = extractHourFromAnalysisResult(analysisResult);
        String currentPath = extractPathFromAnalysisResult(analysisResult);
        String currentUserAgent = extractUserAgentFromAnalysisResult(analysisResult);

        if (current == null) {
            // 첫 학습: Zero Trust 필수 데이터 초기화
            // AI Native v7.2: learningMaturity 제거 - updateCount만으로 학습 정도 표현
            BaselineVector.BaselineVectorBuilder builder = BaselineVector.builder()
                .userId(userId)
                .avgTrustScore(currentTrustScore)
                .avgRequestCount(1L)
                .updateCount(1L)
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
            // AI Native v7.1: User-Agent 시그니처 정규화 저장 (HCADAnalysisResult 기반 첫 학습)
            // 원본 전체 저장 대신 시그니처만 저장 (비교 일관성 확보)
            // 기존: 원본 "Mozilla/5.0 ... Chrome/120.0.0.0" 저장
            // 변경: 시그니처 "Chrome/120 (Windows)" 저장
            if (currentUserAgent != null && !currentUserAgent.isEmpty()) {
                String uaSignature = extractUASignature(currentUserAgent);
                if (uaSignature != null && !uaSignature.equals("unknown") &&
                    !uaSignature.equals("unknown (unknown)")) {
                    builder.normalUserAgents(new String[]{uaSignature});
                    log.debug("[Baseline] HCAD 첫 학습 - UA 시그니처 저장: {}", uaSignature);
                } else {
                    // 파싱 실패 시 원본 저장 (fallback)
                    String truncatedUA = currentUserAgent.length() > 100
                        ? currentUserAgent.substring(0, 100) : currentUserAgent;
                    builder.normalUserAgents(new String[]{truncatedUA});
                    log.warn("[Baseline] HCAD 첫 학습 - UA 파싱 실패, 원본 저장: {}", truncatedUA);
                }
            }

            return builder.build();
        }

        // EMA 적용
        double oldTrustScore = current.getAvgTrustScore() != null ? current.getAvgTrustScore() : 0.5;
        double newTrustScore = alpha * currentTrustScore + (1 - alpha) * oldTrustScore;

        long oldUpdateCount = current.getUpdateCount() != null ? current.getUpdateCount() : 0L;
        long oldRequestCount = current.getAvgRequestCount() != null ? current.getAvgRequestCount() : 0L;

        // Zero Trust 필수 데이터 업데이트
        String[] normalIpRanges = updateNormalIpRanges(current.getNormalIpRanges(), currentIp);
        Integer[] normalAccessHours = updateNormalAccessHours(current.getNormalAccessHours(), currentHour);
        String[] frequentPaths = updateFrequentPaths(current.getFrequentPaths(), currentPath);
        // AI Native v3.1: User-Agent 패턴 업데이트 - LLM 세션 하이재킹 탐지용
        // AI Native v7.3: UA 시그니처 정규화 추가 - 첫 학습과 업데이트 간 일관성 확보
        // 문제: 첫 학습 시 시그니처("Chrome/120 (Windows)")로 저장하지만 업데이트 시 원본 UA로 비교하면 불일치 발생
        // 해결: 업데이트 시에도 동일한 extractUASignature() 적용하여 시그니처 단위로 비교
        String normalizedUA = extractUASignature(currentUserAgent);
        String uaForUpdate = (normalizedUA != null && !normalizedUA.equals("unknown") &&
                              !normalizedUA.equals("unknown (unknown)"))
                             ? normalizedUA : currentUserAgent;
        String[] normalUserAgents = updateNormalUserAgents(current.getNormalUserAgents(), uaForUpdate);

        // AI Native v7.2: learningMaturity 제거 - updateCount만으로 학습 정도 표현
        return BaselineVector.builder()
            .userId(userId)
            .avgTrustScore(newTrustScore)
            .avgRequestCount(oldRequestCount + 1)
            .updateCount(oldUpdateCount + 1)
            .lastUpdated(Instant.now())
            // Zero Trust 필수 데이터
            .normalIpRanges(normalIpRanges)
            .normalAccessHours(normalAccessHours)
            .frequentPaths(frequentPaths)
            .normalUserAgents(normalUserAgents)
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
     * analysisResult에서 User-Agent 추출 (AI Native v3.1)
     *
     * HCADAnalysisResult.getContext().getUserAgent() 사용
     * LLM이 User-Agent 변경을 탐지하여 세션 하이재킹 여부 판단 가능
     */
    private String extractUserAgentFromAnalysisResult(HCADAnalysisResult analysisResult) {
        if (analysisResult == null) {
            return null;
        }
        io.contexa.contexacommon.hcad.domain.HCADContext context = analysisResult.getContext();
        if (context == null) {
            return null;
        }
        return context.getUserAgent();
    }

    /**
     * IP 주소에서 범위 추출 (AI Native v6.5)
     *
     * IPv4: C 클래스 대역 추출 (예: 192.168.1.100 -> 192.168.1)
     * IPv6: Loopback 정규화 및 /64 prefix 추출
     * Loopback: 127.0.0.1, ::1, 0:0:0:0:0:0:0:1 모두 "loopback"으로 통일
     *
     * @param ip IP 주소 문자열
     * @return IP 범위 또는 정규화된 값
     */
    private String extractIpRange(String ip) {
        if (ip == null || ip.isEmpty()) {
            return null;
        }

        // Loopback 주소 정규화 (IPv4/IPv6 모두 처리)
        if (isLoopback(ip)) {
            return "loopback";
        }

        // IPv6 처리 (콜론 포함)
        if (ip.contains(":")) {
            return normalizeIPv6Range(ip);
        }

        // IPv4: C 클래스 대역 추출
        int lastDot = ip.lastIndexOf('.');
        if (lastDot > 0) {
            return ip.substring(0, lastDot);
        }
        return ip;
    }

    /**
     * Loopback 주소 여부 확인 (AI Native v6.5)
     *
     * @param ip IP 주소 문자열
     * @return true면 loopback 주소
     */
    private boolean isLoopback(String ip) {
        if (ip == null) {
            return false;
        }
        // IPv4 loopback
        if ("127.0.0.1".equals(ip) || ip.startsWith("127.")) {
            return true;
        }
        // IPv6 loopback (다양한 표기)
        if ("::1".equals(ip) ||
            "0:0:0:0:0:0:0:1".equals(ip) ||
            "0000:0000:0000:0000:0000:0000:0000:0001".equals(ip)) {
            return true;
        }
        return false;
    }

    /**
     * AI Native v9.0: 테이블 셀 문자열 자르기
     *
     * 테이블 형식 출력 시 셀 너비를 맞추기 위해 문자열을 지정된 길이로 자름
     * 길이 초과 시 "..." 추가
     *
     * @param str 원본 문자열
     * @param maxLength 최대 길이
     * @return 잘린 문자열
     */
    private String truncateForTable(String str, int maxLength) {
        if (str == null) {
            return "";
        }
        if (str.length() <= maxLength) {
            return str;
        }
        return str.substring(0, maxLength - 3) + "...";
    }

    /**
     * IPv6 주소 범위 정규화 (AI Native v6.5)
     *
     * /64 prefix 기준으로 범위 추출 (처음 4개 세그먼트)
     * 예: 2001:0db8:85a3:0000:0000:8a2e:0370:7334 -> 2001:db8:85a3:0
     *
     * @param ipv6 IPv6 주소 문자열
     * @return 정규화된 /64 범위
     */
    private String normalizeIPv6Range(String ipv6) {
        if (ipv6 == null || ipv6.isEmpty()) {
            return null;
        }

        // :: 확장 처리
        String expanded = expandIPv6(ipv6);
        String[] segments = expanded.split(":");

        // /64 prefix (처음 4개 세그먼트)
        if (segments.length >= 4) {
            return String.format("%s:%s:%s:%s",
                normalizeIPv6Segment(segments[0]),
                normalizeIPv6Segment(segments[1]),
                normalizeIPv6Segment(segments[2]),
                normalizeIPv6Segment(segments[3]));
        }
        return ipv6;
    }

    /**
     * IPv6 :: 축약 확장
     */
    private String expandIPv6(String ipv6) {
        if (!ipv6.contains("::")) {
            return ipv6;
        }
        String[] parts = ipv6.split("::", 2);
        String[] leftSegments = parts[0].isEmpty() ? new String[0] : parts[0].split(":");
        String[] rightSegments = parts.length > 1 && !parts[1].isEmpty() ? parts[1].split(":") : new String[0];

        int missingSegments = 8 - leftSegments.length - rightSegments.length;
        StringBuilder expanded = new StringBuilder();

        for (String seg : leftSegments) {
            if (expanded.length() > 0) expanded.append(":");
            expanded.append(seg);
        }
        for (int i = 0; i < missingSegments; i++) {
            if (expanded.length() > 0) expanded.append(":");
            expanded.append("0");
        }
        for (String seg : rightSegments) {
            if (expanded.length() > 0) expanded.append(":");
            expanded.append(seg);
        }
        return expanded.toString();
    }

    /**
     * IPv6 세그먼트 정규화 (선행 0 제거)
     */
    private String normalizeIPv6Segment(String segment) {
        if (segment == null || segment.isEmpty()) {
            return "0";
        }
        // 선행 0 제거
        String normalized = segment.replaceFirst("^0+", "");
        return normalized.isEmpty() ? "0" : normalized;
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
     * normalUserAgents 업데이트 (최대 5개 유지) - AI Native v3.1
     *
     * LLM이 User-Agent 변경을 탐지하여 세션 하이재킹 여부 판단 가능
     */
    private String[] updateNormalUserAgents(String[] current, String newUserAgent) {
        if (newUserAgent == null || newUserAgent.isEmpty()) {
            return current;
        }

        // User-Agent가 너무 길면 앞 100자만 저장 (Redis 용량 최적화)
        if (newUserAgent.length() > 100) {
            newUserAgent = newUserAgent.substring(0, 100);
        }

        if (current == null || current.length == 0) {
            return new String[]{newUserAgent};
        }

        // 이미 존재하면 그대로 반환
        for (String existing : current) {
            if (newUserAgent.equals(existing)) {
                return current;
            }
        }

        // 최대 5개 유지
        if (current.length >= 5) {
            // 가장 오래된 것 제거하고 새로운 것 추가
            String[] updated = new String[5];
            System.arraycopy(current, 1, updated, 0, 4);
            updated[4] = newUserAgent;
            return updated;
        }

        // 새로운 것 추가
        String[] updated = new String[current.length + 1];
        System.arraycopy(current, 0, updated, 0, current.length);
        updated[current.length] = newUserAgent;
        return updated;
    }

    /**
     * Baseline 조회 (Zero Trust 필수 데이터 포함)
     *
     * AI Native v6.0: 신규 사용자 Cold Start 문제 해결
     * - 사용자 Baseline이 없으면 조직 Baseline으로 폴백
     * - 조직 Baseline도 없으면 null 반환 (기존 동작)
     *
     * 조회 필드:
     * - userId, avgTrustScore, avgRequestCount, updateCount, confidence, lastUpdated
     * - normalIpRanges: 정상 IP 대역 (CSV -> String[] 변환)
     * - normalAccessHours: 정상 접근 시간대 (CSV -> Integer[] 변환)
     * - frequentPaths: 자주 접근하는 경로 (CSV -> String[] 변환)
     *
     * @param userId 사용자 ID
     * @return BaselineVector (없으면 조직 Baseline, 그것도 없으면 null)
     */
    public BaselineVector getBaseline(String userId) {
        if (redisTemplate == null || userId == null) {
            return null;
        }

        // 1. 사용자 Baseline 조회 시도
        BaselineVector userBaseline = getUserBaseline(userId);
        if (userBaseline != null) {
            return userBaseline;
        }

        // 2. 신규 사용자: 조직 Baseline으로 폴백
        String organizationId = extractOrganizationId(userId);
        if (organizationId != null) {
            log.info("[BaselineLearningService] 신규 사용자 {}, 조직 Baseline 사용: {}", userId, organizationId);
            BaselineVector orgBaseline = getOrganizationBaseline(organizationId);
            if (orgBaseline != null) {
                // 조직 Baseline에 사용자 ID 설정하여 반환
                // AI Native v7.2: learningMaturity 제거 - updateCount만으로 학습 정도 표현
                return BaselineVector.builder()
                    .userId(userId)
                    .avgTrustScore(orgBaseline.getAvgTrustScore())
                    .avgRequestCount(orgBaseline.getAvgRequestCount())
                    .updateCount(0L)  // 신규 사용자는 0
                    .lastUpdated(orgBaseline.getLastUpdated())
                    .normalIpRanges(orgBaseline.getNormalIpRanges())
                    .normalAccessHours(orgBaseline.getNormalAccessHours())
                    .frequentPaths(orgBaseline.getFrequentPaths())
                    .normalUserAgents(null)  // User-Agent는 사용자별 고유
                    .build();
            }
        }

        return null;
    }

    /**
     * 사용자별 Baseline 조회 (내부용)
     *
     * @param userId 사용자 ID
     * @return BaselineVector (없으면 null)
     */
    private BaselineVector getUserBaseline(String userId) {
        try {
            String key = BASELINE_KEY_PREFIX + userId;
            Map<Object, Object> data = redisTemplate.opsForHash().entries(key);

            if (data == null || data.isEmpty()) {
                return null;
            }

            // AI Native v7.2: learningMaturity 제거 - updateCount만으로 학습 정도 표현
            return BaselineVector.builder()
                .userId(userId)
                .avgTrustScore(parseDouble(data.get("avgTrustScore")))
                .avgRequestCount(parseLong(data.get("avgRequestCount")))
                .updateCount(parseLong(data.get("updateCount")))
                .lastUpdated(parseInstant(data.get("lastUpdated")))
                // Zero Trust 필수 데이터 조회
                .normalIpRanges(parseStringArray(data.get("normalIpRanges")))
                .normalAccessHours(parseIntegerArray(data.get("normalAccessHours")))
                .frequentPaths(parseStringArray(data.get("frequentPaths")))
                // AI Native v3.1: User-Agent 패턴 조회 - LLM 세션 하이재킹 탐지용
                .normalUserAgents(parseStringArray(data.get("normalUserAgents")))
                .build();

        } catch (Exception e) {
            log.error("[BaselineLearningService] 사용자 Baseline 조회 실패: userId={}", userId, e);
            return null;
        }
    }

    /**
     * 조직 Baseline 조회
     *
     * AI Native v6.0: 신규 사용자 Cold Start 문제 해결
     * - 조직 전체 사용자의 평균 Baseline
     * - Redis Key: security:hcad:baseline:org:{organizationId}
     *
     * @param organizationId 조직 ID
     * @return 조직 Baseline (없으면 null)
     */
    public BaselineVector getOrganizationBaseline(String organizationId) {
        if (redisTemplate == null || organizationId == null) {
            return null;
        }

        try {
            String key = BASELINE_KEY_PREFIX + "org:" + organizationId;
            Map<Object, Object> data = redisTemplate.opsForHash().entries(key);

            if (data == null || data.isEmpty()) {
                log.debug("[BaselineLearningService] 조직 Baseline 없음: {}", organizationId);
                return null;
            }

            // AI Native v7.2: learningMaturity 제거 - updateCount만으로 학습 정도 표현
            return BaselineVector.builder()
                .userId("org:" + organizationId)
                .avgTrustScore(parseDouble(data.get("avgTrustScore")))
                .avgRequestCount(parseLong(data.get("avgRequestCount")))
                .updateCount(parseLong(data.get("updateCount")))
                .lastUpdated(parseInstant(data.get("lastUpdated")))
                .normalIpRanges(parseStringArray(data.get("normalIpRanges")))
                .normalAccessHours(parseIntegerArray(data.get("normalAccessHours")))
                .frequentPaths(parseStringArray(data.get("frequentPaths")))
                .build();

        } catch (Exception e) {
            log.error("[BaselineLearningService] 조직 Baseline 조회 실패: organizationId={}", organizationId, e);
            return null;
        }
    }

    /**
     * 사용자 ID에서 조직 ID 추출
     *
     * 추출 규칙:
     * - userId 형식: {organizationId}_{username} 또는 {organizationId}@{domain}
     * - 예: "acme_john", "acme@company.com" -> "acme"
     * - 분리자가 없으면 기본 조직 "default" 반환
     *
     * @param userId 사용자 ID
     * @return 조직 ID
     */
    private String extractOrganizationId(String userId) {
        if (userId == null || userId.isEmpty()) {
            return null;
        }

        // 언더스코어 분리자
        int underscoreIndex = userId.indexOf('_');
        if (underscoreIndex > 0) {
            return userId.substring(0, underscoreIndex);
        }

        // @ 분리자 (이메일 형식)
        int atIndex = userId.indexOf('@');
        if (atIndex > 0) {
            return userId.substring(0, atIndex);
        }

        // 분리자가 없으면 기본 조직
        return "default";
    }

    /**
     * Adaptive Alpha 계산
     *
     * AI Native v6.0: 학습 횟수 기반 동적 Alpha 조정
     * - 신규 사용자: 빠른 학습 (alpha=0.3)
     * - 중간 단계: 중간 학습 (alpha=0.2)
     * - 안정 단계: 기본 학습 (alpha=0.1)
     *
     * @param current 현재 Baseline
     * @return 적응형 alpha 값
     */
    private double calculateAdaptiveAlpha(BaselineVector current) {
        if (current == null || current.getUpdateCount() < 5) {
            return 0.3;  // 신규 사용자: 빠른 학습
        } else if (current.getUpdateCount() < 20) {
            return 0.2;  // 중간 단계
        }
        return alpha;  // 기본값 0.1
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
            // AI Native v7.2: learningMaturity 제거 - updateCount만으로 학습 정도 표현
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
            // AI Native v3.1: User-Agent 패턴 저장 - LLM 세션 하이재킹 탐지용
            if (baseline.getNormalUserAgents() != null && baseline.getNormalUserAgents().length > 0) {
                data.put("normalUserAgents", String.join(",", baseline.getNormalUserAgents()));
            }

            redisTemplate.opsForHash().putAll(key, data);
            redisTemplate.expire(key, BASELINE_TTL);

            log.debug("[BaselineLearningService] Baseline 저장 완료: userId={}, normalIpRanges={}, normalAccessHours={}, frequentPaths={}, normalUserAgents={}",
                userId,
                baseline.getNormalIpRanges() != null ? baseline.getNormalIpRanges().length : 0,
                baseline.getNormalAccessHours() != null ? baseline.getNormalAccessHours().length : 0,
                baseline.getFrequentPaths() != null ? baseline.getFrequentPaths().length : 0,
                baseline.getNormalUserAgents() != null ? baseline.getNormalUserAgents().length : 0);

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

        // AI Native v9.9: Baseline raw 데이터만 추출 (MATCH/MISMATCH 계산 제거)
        // - AI가 Current vs Known 직접 비교하도록
        // - 플랫폼은 Known 값만 제공, 판단은 AI에게 위임

        // Baseline에서 raw 데이터 추출
        String[] normalIps = baseline.getNormalIpRanges();
        Integer[] normalHours = baseline.getNormalAccessHours();
        String[] normalUserAgents = baseline.getNormalUserAgents();
        String baselineUASignature = normalUserAgents != null && normalUserAgents.length > 0
            ? extractUASignature(normalUserAgents[0]) : "none";
        // - AI가 Current vs Known 직접 비교하도록
        // - 플랫폼은 Known 값만 제공, 판단은 AI에게 위임
        StringBuilder sb = new StringBuilder();

        // Known IP 목록
        if (normalIps != null && normalIps.length > 0) {
            sb.append("Known IPs: ").append(String.join(", ", normalIps)).append("\n");
        }

        // Known Hours 목록
        if (normalHours != null && normalHours.length > 0) {
            StringBuilder hours = new StringBuilder();
            for (int i = 0; i < normalHours.length; i++) {
                if (i > 0) hours.append(", ");
                hours.append(normalHours[i]);
            }
            sb.append("Known Hours: ").append(hours).append("\n");
        }

        // Known UA (원시 값)
        sb.append("Known UA: ").append(baselineUASignature).append("\n");

        return sb.toString();
    }

    /**
     * AI Native v8.14: Baseline 비교 상태 반환 (판단 제거)
     *
     * AI Native 원칙:
     * - 플랫폼은 원시 데이터/상태만 제공
     * - 판단(ALLOW/CHALLENGE/BLOCK)은 LLM에게 위임
     * - 플랫폼이 판단을 내리면 LLM이 편향됨
     *
     * 변경 이력:
     * - v7.4: 기본 권고 + 예외 조항 (AI Native 위반)
     * - v8.14: 판단 완전 제거, 원시 상태만 반환 (AI Native 준수)
     *
     * @param ipMatch IP 일치 여부
     * @param hourMatch Hour 일치 여부
     * @param uaStatus UA 일치 상태 (Enum)
     * @param matchCount 일치 항목 수
     * @param totalCriteria 전체 항목 수
     * @return 원시 상태 문자열 (판단 없음)
     */
    private String determineRecommendation(boolean ipMatch, boolean hourMatch,
                                           BaselineMatchStatus uaStatus, int matchCount, int totalCriteria) {
        // AI Native v8.14: 판단 제거, 원시 상태만 반환
        // LLM이 RELATED CONTEXT, CONTEXT SUMMARY와 비교하여 직접 판단
        String ipStatus = ipMatch ? "MATCH" : "MISMATCH";
        String hourStatus = hourMatch ? "MATCH" : "MISMATCH";
        String uaStatusStr = uaStatus != null ? uaStatus.name() : "UNKNOWN";

        return String.format("IP_STATUS=%s, HOUR_STATUS=%s, UA_STATUS=%s",
            ipStatus, hourStatus, uaStatusStr);
    }

    /**
     * AI Native v7.0: IP 일치 여부 판단
     *
     * @param normalIps Baseline IP 목록
     * @param currentIp 현재 IP (정규화됨)
     * @return 일치 여부
     */
    private boolean isIpMatch(String[] normalIps, String currentIp) {
        if (normalIps == null || normalIps.length == 0 || currentIp == null) {
            return false;
        }
        // AI Native v7.0: equals만 사용 (startsWith 버그 수정)
        // extractIpRange()가 이미 정규화하므로 정확히 일치해야 함
        // 버그: "192.168.10".startsWith("192.168.1") = true
        for (String normalIp : normalIps) {
            if (normalIp != null && normalIp.equals(currentIp)) {
                return true;
            }
        }
        return false;
    }

    /**
     * AI Native v7.0: Hour 일치 여부 판단
     *
     * @param normalHours Baseline 시간 목록
     * @param currentHour 현재 시간
     * @return 일치 여부
     */
    private boolean isHourMatch(Integer[] normalHours, int currentHour) {
        if (normalHours == null || normalHours.length == 0 || currentHour < 0) {
            return false;
        }
        for (Integer normalHour : normalHours) {
            if (normalHour != null && normalHour == currentHour) {
                return true;
            }
        }
        return false;
    }

    /**
     * AI Native v7.4: UserAgent 일치 상태 판단 (Enum 반환)
     *
     * v7.3 보안 개선:
     * - 기존: 브라우저명만 비교 -> OS 변경 미감지 -> 계정 탈취 공격 허용
     * - 변경: 브라우저명 + OS 분리 비교 -> OS 변경 시 MISMATCH 반환
     *
     * v7.4 리팩토링:
     * - 매직 스트링 제거 -> BaselineMatchStatus Enum 사용
     * - 타입 안전성 확보
     *
     * 판정 기준:
     * - MATCH: 브라우저명 + 버전 + OS 모두 일치
     * - PARTIAL: 브라우저명 + OS 일치, 버전만 다름 (자동 업데이트로 정상)
     * - MISMATCH: OS가 다름 (Windows -> Android = 디바이스 변경 = 의심)
     * - UNKNOWN: UA 정보 없거나 파싱 불가
     *
     * @param normalUserAgents Baseline UA 목록
     * @param currentUserAgent 현재 UA
     * @return BaselineMatchStatus Enum
     */
    private BaselineMatchStatus getUAMatchStatus(String[] normalUserAgents, String currentUserAgent) {
        if (normalUserAgents == null || normalUserAgents.length == 0 || currentUserAgent == null) {
            return BaselineMatchStatus.UNKNOWN;
        }
        String currentSig = extractUASignature(currentUserAgent);
        if (currentSig == null || currentSig.equals("unknown") || currentSig.equals("unknown (unknown)")) {
            return BaselineMatchStatus.UNKNOWN;
        }
        for (String normalUA : normalUserAgents) {
            String normalSig = extractUASignature(normalUA);
            if (normalSig != null && currentSig.equals(normalSig)) {
                return BaselineMatchStatus.MATCH;
            }

            // AI Native v7.3: 브라우저 + OS 분리 비교
            String currentBrowser = extractBrowserFromSignature(currentSig);  // "Chrome/120"
            String currentOS = extractOSFromSignature(currentSig);            // "Windows" 또는 "Android"
            String normalBrowser = extractBrowserFromSignature(normalSig);    // "Chrome/143"
            String normalOS = extractOSFromSignature(normalSig);              // "Windows"

            // 브라우저명 추출 (버전 제외)
            String currentBrowserName = currentBrowser != null && currentBrowser.contains("/")
                ? currentBrowser.split("/")[0] : currentBrowser;
            String normalBrowserName = normalBrowser != null && normalBrowser.contains("/")
                ? normalBrowser.split("/")[0] : normalBrowser;

            // 같은 브라우저인 경우
            if (currentBrowserName != null && currentBrowserName.equals(normalBrowserName)) {
                // OS가 다르면 MISMATCH (디바이스 변경 = 계정 탈취 의심)
                // 예: Windows -> Android, Mac -> iOS 등
                if (currentOS != null && normalOS != null && !currentOS.equals(normalOS)) {
                    log.debug("[Baseline] UA OS 불일치 감지: current={}, baseline={}", currentOS, normalOS);
                    return BaselineMatchStatus.MISMATCH;  // v7.3: OS 변경은 PARTIAL이 아닌 MISMATCH
                }
                // OS 동일, 버전만 다르면 PARTIAL (브라우저 자동 업데이트로 정상)
                return BaselineMatchStatus.PARTIAL;
            }
        }
        return BaselineMatchStatus.MISMATCH;
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

        // AI Native v7.0: LLM 분석에 필요한 데이터만 제공
        // - SessionId, 전체 Timestamp 제거 (LLM 판단에 불필요)
        // - IP, Hour, UA만 제공 (Baseline 비교에 사용되는 핵심 데이터)
        sb.append("Current Request Context:\n");
        if (currentEvent != null) {
            String sourceIp = currentEvent.getSourceIp();
            String normalizedIp = extractIpRange(sourceIp);
            sb.append(String.format("  IP: %s\n", normalizedIp != null ? normalizedIp : "NOT_PROVIDED"));

            if (currentEvent.getTimestamp() != null) {
                sb.append(String.format("  Hour: %d\n", currentEvent.getTimestamp().getHour()));
            }

            String userAgent = currentEvent.getUserAgent();
            String uaSignature = extractUASignature(userAgent);
            sb.append(String.format("  UA: %s\n", uaSignature));
        }
        sb.append("\n");

        // AI Native v8.14: 강제 규칙 제거, 정보성 텍스트로 변경
        // 기존 MANDATORY CONSTRAINT ("MUST NOT", "MUST be")가 LLM 판단을 편향시킴
        // RELATED CONTEXT에 검증된 패턴이 있어도 ALLOW 불가능했던 문제 해결
        sb.append("=== BASELINE CONSIDERATIONS ===\n");
        sb.append("No traditional baseline profile established for this user.\n\n");

        sb.append("Decision guidance (facts, not rules):\n");
        sb.append("- RELATED CONTEXT contains VERIFIED NORMAL BEHAVIOR (past ALLOW decisions)\n");
        sb.append("- If RELATED CONTEXT has documents matching current OS/IP/Hour → verified pattern exists\n");
        sb.append("- If RELATED CONTEXT is EMPTY → no verified patterns to compare against\n");
        sb.append("- Cannot verify behavior without comparison data\n\n");

        return sb.toString();
    }

    // AI Native v3.0: isHighPrivilegeUser() 메서드 제거
    // 문제점: 실제 권한 체계와 무관한 문자열 contains 검사
    // "adminSupport", "sysadmin_viewer" 같은 일반 사용자도 매칭
    // 플랫폼이 하드코딩된 규칙으로 권한 판단 → AI Native 위반
    // LLM에 userId만 제공하고 판단 위임해야 함

    /**
     * SecurityEvent에서 경로 추출 (raw 데이터 추출 유틸리티)
     */
    private String extractPath(SecurityEvent event) {
        if (event == null) {
            return null;
        }

        // AI Native v4.0.0: targetResource 필드 제거 - metadata에서 추출
        Map<String, Object> metadata = event.getMetadata();
        if (metadata != null && metadata.containsKey("targetResource")) {
            Object targetResource = metadata.get("targetResource");
            if (targetResource != null && !targetResource.toString().isEmpty()) {
                return targetResource.toString();
            }
        }

        // metadata에서 requestPath 추출
        if (metadata != null && metadata.containsKey("requestPath")) {
            Object path = metadata.get("requestPath");
            if (path != null) {
                return path.toString();
            }
        }

        return null;
    }

    /**
     * User-Agent 문자열에서 OS 정보 추출 (AI Native v6.1)
     *
     * 세션 하이재킹 탐지를 위한 raw 데이터 파싱:
     * - Windows, Android, iOS, macOS, Linux 등 OS 식별
     * - LLM에 OS 정보를 제공하여 OS 변경 여부 판단 위임
     *
     * AI Native 원칙 준수:
     * - 플랫폼은 OS 정보 추출만 수행 (데이터 파싱)
     * - 판단은 LLM에 위임 (OS 변경 = 위협 여부는 LLM이 결정)
     *
     * @param userAgent User-Agent 문자열
     * @return OS 이름 (Unknown if not detected)
     */
    private String extractOS(String userAgent) {
        if (userAgent == null || userAgent.isEmpty()) {
            return "Unknown";
        }

        // AI Native v8.8: lowercase 변환 제거 (원본 대소문자 유지)
        // UA 문자열은 표준 형식이므로 변환 불필요

        // 모바일 OS 우선 검사 (Android가 Linux를 포함하므로)
        if (userAgent.contains("Android")) {
            return "Android";
        }

        // iOS 계열 (iPhone, iPad, iPod)
        if (userAgent.contains("iPhone") || userAgent.contains("iPad") || userAgent.contains("iPod")) {
            return "iOS";
        }

        // Windows 계열
        if (userAgent.contains("Windows")) {
            return "Windows";
        }

        // macOS (Mac OS X) - AI Native v8.8: "Mac" 반환 (extractUASignature와 일치)
        if (userAgent.contains("Mac OS") || userAgent.contains("Macintosh")) {
            return "Mac";
        }

        // Chrome OS
        if (userAgent.contains("CrOS")) {
            return "ChromeOS";
        }

        // Linux (Android 제외)
        if (userAgent.contains("Linux") && !userAgent.contains("Android")) {
            return "Linux";
        }

        return "Unknown";
    }

    /**
     * OS 변경 감지 및 경고 메시지 생성 (AI Native v6.1)
     *
     * 세션 하이재킹 탐지:
     * - 동일 세션에서 OS가 변경되면 세션 토큰 탈취 가능성
     * - Windows -> Android 같은 크로스 플랫폼 변경은 강력한 위협 신호
     *
     * AI Native 원칙 준수:
     * - 플랫폼은 OS 변경 감지 사실만 제공
     * - LLM이 컨텍스트(시간, 위치 등)를 고려하여 위협 여부 판단
     *
     * @param normalUserAgents 기준선의 정상 User-Agent 목록
     * @param currentUserAgent 현재 요청의 User-Agent
     * @return OS 변경 경고 메시지 (변경 없으면 null)
     */
    private String detectOSChange(String[] normalUserAgents, String currentUserAgent) {
        if (normalUserAgents == null || normalUserAgents.length == 0 || currentUserAgent == null) {
            return null;
        }

        String currentOS = extractOS(currentUserAgent);
        if ("Unknown".equals(currentOS)) {
            return null; // OS 식별 불가 시 경고 생략
        }

        // 기준선의 모든 User-Agent에서 OS 추출
        for (String normalUA : normalUserAgents) {
            String normalOS = extractOS(normalUA);
            if (!"Unknown".equals(normalOS) && !normalOS.equals(currentOS)) {
                // OS 변경 감지!
                StringBuilder warning = new StringBuilder();
                warning.append("\n=== SESSION HIJACKING WARNING ===\n");
                warning.append("OS CHANGED from baseline!\n");
                warning.append(String.format("  Previous OS: %s\n", normalOS));
                warning.append(String.format("  Current OS: %s\n", currentOS));
                warning.append("  Previous UA: ").append(truncateUA(normalUA)).append("\n");
                warning.append("  Current UA: ").append(truncateUA(currentUserAgent)).append("\n");
                warning.append("\nCRITICAL INDICATOR:\n");
                warning.append("- Same session with different OS is a strong indicator of session hijacking\n");
                warning.append("- Legitimate users do NOT change operating systems mid-session\n");
                warning.append("- Recommended action: CHALLENGE or BLOCK\n");
                return warning.toString();
            }
        }

        return null; // OS 변경 없음
    }

    /**
     * User-Agent 문자열 truncate (로그/프롬프트용)
     */
    private String truncateUA(String userAgent) {
        if (userAgent == null) {
            return "N/A";
        }
        return userAgent.length() > 80 ? userAgent.substring(0, 77) + "..." : userAgent;
    }

    /**
     * AI Native v10.3: UserAgent에서 브라우저/버전만 추출
     *
     * OS는 이미 [OS] Factor에서 별도로 비교하므로,
     * UA에서는 브라우저/버전만 추출하여 중복 비교 제거
     *
     * AI Native v10.3 변경:
     * - 변경 전: "Chrome/120/Windows" - OS 중복 + LLM 환각 유발
     * - 변경 후: "Chrome/120" - 브라우저/버전만 비교
     *
     * @param userAgent 전체 User-Agent 문자열
     * @return 브라우저/버전 (예: "Chrome/120")
     */
    private String extractUASignature(String userAgent) {
        if (userAgent == null || userAgent.isEmpty()) {
            return "Browser";
        }

        // 브라우저 및 버전 추출 (메이저 버전만)
        if (userAgent.contains("Chrome/") && !userAgent.contains("Edg/")) {
            return extractBrowserVersion(userAgent, "Chrome/");
        } else if (userAgent.contains("Edg/")) {
            String browser = extractBrowserVersion(userAgent, "Edg/");
            return browser.replace("Edg", "Edge");
        } else if (userAgent.contains("Firefox/")) {
            return extractBrowserVersion(userAgent, "Firefox/");
        } else if (userAgent.contains("Safari/") && !userAgent.contains("Chrome") && !userAgent.contains("Edg")) {
            String browser = extractBrowserVersion(userAgent, "Version/");
            return browser.replace("Version", "Safari");
        }

        return "Browser";
    }

    /**
     * AI Native v7.1: User-Agent에서 브라우저 버전 추출 (메이저 버전만)
     *
     * 기존 버그 수정:
     * - dotIdx > 0 조건이 잘못됨 (dotIdx > start 이어야 함)
     * - end가 start보다 작은 경우 처리 누락
     * - 빈 문자열 반환 방지
     *
     * 수정 후:
     * - while 루프로 숫자만 추출 (첫 번째 . 또는 공백까지)
     * - 예: "Chrome/120.0.0.0" -> "Chrome/120"
     *
     * @param userAgent User-Agent 문자열
     * @param prefix 브라우저 prefix (예: "Chrome/")
     * @return 브라우저명/메이저버전 (예: "Chrome/120") 또는 "unknown"
     */
    private String extractBrowserVersion(String userAgent, String prefix) {
        int idx = userAgent.indexOf(prefix);
        if (idx == -1) return "unknown";

        int start = idx + prefix.length();
        if (start >= userAgent.length()) return "unknown";

        // AI Native v7.1: 메이저 버전만 추출 (첫 번째 . 또는 공백까지)
        int end = start;
        while (end < userAgent.length()) {
            char c = userAgent.charAt(end);
            if (c == '.' || c == ' ' || !Character.isDigit(c)) {
                break;
            }
            end++;
        }

        // 버전 문자열이 비어있으면 "unknown"
        if (end == start) return "unknown";

        String version = userAgent.substring(start, end);
        String browserName = prefix.replace("/", "");
        return browserName + "/" + version;
    }

    /**
     * AI Native v7.3: UA 시그니처에서 브라우저명/버전 추출
     *
     * 시그니처 형식: "Chrome/120 (Windows)"
     * 반환값: "Chrome/120"
     *
     * @param signature UA 시그니처 (extractUASignature() 반환값)
     * @return 브라우저/버전 또는 null
     */
    private String extractBrowserFromSignature(String signature) {
        if (signature == null) return null;
        int spaceIdx = signature.indexOf(" ");
        if (spaceIdx > 0) {
            return signature.substring(0, spaceIdx);
        }
        return signature;
    }

    /**
     * AI Native v7.3: UA 시그니처에서 OS 추출
     *
     * 시그니처 형식: "Chrome/120 (Windows)" 또는 "Chrome/120 (Android)"
     * 반환값: "Windows" 또는 "Android"
     *
     * 보안 목적:
     * - Windows → Android 변경 감지 (디바이스 변경 = 계정 탈취 의심)
     * - Mac → iOS 변경 감지 (동일 생태계지만 디바이스 변경)
     *
     * @param signature UA 시그니처 (extractUASignature() 반환값)
     * @return OS 또는 null
     */
    private String extractOSFromSignature(String signature) {
        if (signature == null) return null;
        int openParen = signature.indexOf("(");
        int closeParen = signature.indexOf(")");
        if (openParen > 0 && closeParen > openParen) {
            return signature.substring(openParen + 1, closeParen);
        }
        return null;
    }

}
