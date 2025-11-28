package io.contexa.contexacoreenterprise.plane;

import io.contexa.contexacore.autonomous.domain.SecurityEvent;
import io.contexa.contexacore.autonomous.event.decision.EventTier;
import io.contexa.contexacore.plane.ZeroTrustHotPathOrchestrator;
import io.contexa.contexacoreenterprise.dashboard.metrics.plane.OrthogonalSignalCollector;
import io.contexa.contexacore.hcad.service.HCADSimilarityCalculator.TrustedSimilarityResult;
import io.contexa.contexacoreenterprise.plane.service.*;
import io.contexa.contexacoreenterprise.plane.service.AccumulatedRiskCalculator.AccumulatedRiskResult;
import io.contexa.contexacoreenterprise.plane.service.AttackModeHysteresisManager.AttackModeState;
import io.contexa.contexacoreenterprise.plane.service.ColdPathCapacityManager.EnqueueResult;
import io.contexa.contexacoreenterprise.plane.service.HoneypotPatternAnalyzer.HoneypotAnalysisResult;
import io.contexa.contexacoreenterprise.dashboard.metrics.plane.OrthogonalSignalCollector.OrthogonalSignals;
import io.contexa.contexacoreenterprise.plane.service.SignalInconsistencyDetector.InconsistencyResult;
import lombok.Builder;
import lombok.Getter;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;

import java.util.HashMap;
import java.util.Map;

/**
 * Zero Trust HOT Path 오케스트레이터
 *
 * HOT Path (similarity > 0.7)에서도 Zero Trust 원칙을 적용하여
 * 정교한 회피 공격을 탐지하는 통합 오케스트레이션 서비스입니다.
 *
 * 통합 컴포넌트 (11개):
 * 1. SensitiveResourceService - @Protectable 동적 탐지
 * 2. AntiEvasionSamplingEngine - 회피 불가능 샘플링
 * 3. OrthogonalSignalCollector - 7차원 직교 신호
 * 4. SignalInconsistencyDetector - Mahalanobis Distance
 * 5. UnifiedThresholdManager - Auto-tuning
 * 6. HCADRedisKeys - Redis 키 관리
 * 7. AdaptiveThresholdSystem - CUSUM 베이스라인
 * 8. ColdPathCapacityManager - Priority Queue + Graceful Degradation
 * 9. AttackModeHysteresisManager - Dual Threshold 히스테리시스
 * 10. AccumulatedRiskCalculator - 7-signal 종합 위험
 * 11. HoneypotPatternAnalyzer - 접근 패턴 이상 탐지
 *
 * 외부기관 1 & 2 피드백 100% 반영
 *
 * @author contexa
 * @since 3.0
 */
@Slf4j
public class ZeroTrustHotPathOrchestratorImpl implements ZeroTrustHotPathOrchestrator {

    @Autowired
    private AntiEvasionSamplingEngine samplingEngine;

    @Autowired
    private OrthogonalSignalCollector signalCollector;

    @Autowired
    private SignalInconsistencyDetector inconsistencyDetector;

    @Autowired
    private AccumulatedRiskCalculator riskCalculator;

    @Autowired
    private AttackModeHysteresisManager attackModeManager;

    @Autowired
    private ColdPathCapacityManager capacityManager;

    @Autowired
    private HoneypotPatternAnalyzer honeypotAnalyzer;

    @Autowired
    private AdaptiveThresholdSystem adaptiveThresholdSystem;

    // ===== Public Methods =====

    /**
     * HOT Path 이벤트에 대한 Zero Trust 평가
     *
     * @param event SecurityEvent
     * @param hcadResult HCAD 분석 결과 (similarity > 0.7 = HOT Path)
     * @return ZeroTrustDecision (HOT Path 통과 or Cold Path 라우팅)
     */
    public ZeroTrustDecision evaluateHotPathEvent(SecurityEvent event, TrustedSimilarityResult hcadResult) {
        long startTime = System.currentTimeMillis();

        try {
            String userId = event.getUserId();

            // ===== Phase 1: Anti-Evasion 샘플링 =====
            EventTier tier = EventTier.fromRiskScore(event.getRiskScore());
            boolean shouldSample = samplingEngine.shouldSample(event, tier);

            if (!shouldSample) {
                // 샘플링되지 않음 → HOT Path 통과
                log.debug("[ZeroTrustHotPath] Event {} not sampled, allowing HOT Path", event.getEventId());

                return ZeroTrustDecision.builder()
                        .decision(Decision.ALLOW_HOT_PATH)
                        .reason("NOT_SAMPLED")
                        .shouldSample(false)
                        .tier(tier)
                        .processingTimeMs(System.currentTimeMillis() - startTime)
                        .build();
            }

            // ===== Phase 2: 7차원 직교 신호 수집 =====
            OrthogonalSignals signals = signalCollector.collect(event, hcadResult);

            // EventRecorder 인터페이스를 통한 신호 수집 이벤트 기록
            Map<String, Object> metadata = new HashMap<>();
            metadata.put("user_id", userId);
            metadata.put("network_signal", signals.getNetworkSignal());
            metadata.put("crypto_signal", signals.getCryptoSignal());
            metadata.put("timing_signal", signals.getTimingSignal());
            metadata.put("hcad_trust_score", hcadResult.getTrustScore());
            metadata.put("event_id", event.getEventId());

            signalCollector.recordEvent("signal_collected", metadata);

            // ===== Phase 3: 신호 불일치 탐지 (Mahalanobis Distance) =====
            InconsistencyResult inconsistency = inconsistencyDetector.detectInconsistency(
                    userId, signals, hcadResult
            );

            // ===== Phase 4: Adaptive Threshold 업데이트 (CUSUM) =====
            // 각 신호 타입별로 베이스라인 변화 탐지
            adaptiveThresholdSystem.updateAndDetectChange(
                    userId, "network", signals.getNetworkSignal(), hcadResult.getTrustScore()
            );
            adaptiveThresholdSystem.updateAndDetectChange(
                    userId, "crypto", signals.getCryptoSignal(), hcadResult.getTrustScore()
            );
            adaptiveThresholdSystem.updateAndDetectChange(
                    userId, "timing", signals.getTimingSignal(), hcadResult.getTrustScore()
            );

            // ===== Phase 5: 누적 위험 계산 (7-signal 종합) =====
            double previousRisk = event.getRiskScore() != null ? event.getRiskScore() : 0.0;
            AccumulatedRiskResult riskResult = riskCalculator.calculateAccumulatedRisk(
                    signals, inconsistency, previousRisk
            );

            // ===== Phase 6: 공격 모드 업데이트 (Dual Threshold Hysteresis) =====
            AttackModeState attackMode = attackModeManager.updateAttackMode(
                    userId, riskResult.getAccumulatedRisk()
            );

            // ===== Phase 7: Honeypot 패턴 분석 =====
            HoneypotAnalysisResult honeypotResult = honeypotAnalyzer.analyzeSensitiveAccess(event);

            // ===== Phase 8: 최종 결정 =====
            Decision finalDecision = makeDecision(
                    tier, riskResult, attackMode, honeypotResult, inconsistency
            );

            // ===== Phase 9: Cold Path 용량 체크 (라우팅 결정 시) =====
            EnqueueResult enqueueResult = null;
            if (finalDecision == Decision.ROUTE_TO_COLD_PATH) {
                enqueueResult = capacityManager.tryEnqueue(event, tier);

                if (!enqueueResult.isSuccess()) {
                    // Cold Path 용량 부족 → HOT Path 강제 통과 (Graceful Degradation)
                    log.warn("[ZeroTrustHotPath] Cold Path capacity full, forcing HOT Path for event {}",
                            event.getEventId());

                    finalDecision = Decision.ALLOW_HOT_PATH_DEGRADED;
                }
            }

            long processingTime = System.currentTimeMillis() - startTime;

            log.info("[ZeroTrustHotPath] Event {} decision: {} (risk: {}, attack: {}, honeypot: {}, time: {}ms)",
                    event.getEventId(),
                    finalDecision,
                    String.format("%.3f", riskResult.getAccumulatedRisk()),
                    attackMode.getMode(),
                    honeypotResult.isSuspicious(),
                    processingTime);

            return ZeroTrustDecision.builder()
                    .decision(finalDecision)
                    .reason(buildReason(riskResult, attackMode, honeypotResult, inconsistency))
                    .shouldSample(true)
                    .tier(tier)
                    .signals(signals)
                    .inconsistency(inconsistency)
                    .riskResult(riskResult)
                    .attackMode(attackMode)
                    .honeypotResult(honeypotResult)
                    .enqueueResult(enqueueResult)
                    .processingTimeMs(processingTime)
                    .build();

        } catch (Exception e) {
            log.error("[ZeroTrustHotPath] Error evaluating event {}: {}", event.getEventId(), e.getMessage(), e);

            // 오류 발생 시 안전한 쪽으로 Fail-Safe → Cold Path 라우팅
            return ZeroTrustDecision.builder()
                    .decision(Decision.ROUTE_TO_COLD_PATH)
                    .reason("ERROR_FAIL_SAFE")
                    .shouldSample(true)
                    .tier(EventTier.CRITICAL)
                    .processingTimeMs(System.currentTimeMillis() - startTime)
                    .build();
        }
    }

    /**
     * ZeroTrustHotPathOrchestrator 인터페이스 구현
     *
     * HOT Path 이벤트에 대한 Zero Trust 평가 후 TrustedSimilarityResult 조정
     * Phase 1.3 확장: 7차원 신호 및 Zero Trust 검증 정보 포함
     *
     * @param event SecurityEvent
     * @param originalResult HCAD 분석 원본 결과
     * @return 조정된 TrustedSimilarityResult (Zero Trust 평가 결과 반영)
     */
    @Override
    public TrustedSimilarityResult evaluateAndAdjustResult(
            SecurityEvent event,
            TrustedSimilarityResult originalResult) {

        // 기존 evaluateHotPathEvent() 호출하여 Zero Trust 평가 수행
        ZeroTrustDecision decision = evaluateHotPathEvent(event, originalResult);

        // 7차원 신호 값 추출 (null-safe)
        OrthogonalSignals signals = decision.getSignals();
        double networkSignal = signals != null ? signals.getNetworkSignal() : 0.5;
        double cryptoSignal = signals != null ? signals.getCryptoSignal() : 0.5;
        double timingSignal = signals != null ? signals.getTimingSignal() : 0.5;

        // 위험 요소 목록 생성
        java.util.List<TrustedSimilarityResult.RiskFactor> riskFactors = buildRiskFactors(decision);

        // decision 결과에 따라 TrustedSimilarityResult 조정
        if (decision.getDecision() == Decision.ROUTE_TO_COLD_PATH) {
            // Zero Trust 평가 실패 -> trustScore 하향 조정 (0.3 감소)
            double adjustedTrust = Math.max(0.0, originalResult.getTrustScore() - 0.3);

            log.info("[ZeroTrustHotPath] Adjusting TrustedSimilarityResult for Cold Path routing: " +
                    "eventId={}, reason={}, originalTrust={}, adjustedTrust={}",
                    event.getEventId(), decision.getReason(), originalResult.getTrustScore(), adjustedTrust);

            return TrustedSimilarityResult.builder()
                    .finalSimilarity(originalResult.getFinalSimilarity())
                    .trustScore(adjustedTrust)
                    .crossValidationPassed(false)
                    .threatEvidence(decision.getReason())
                    .threatType(originalResult.getThreatType())
                    .layer1ThreatSearchScore(originalResult.getLayer1ThreatSearchScore())
                    .layer2BaselineSimilarity(originalResult.getLayer2BaselineSimilarity())
                    .layer3AnomalyScore(originalResult.getLayer3AnomalyScore())
                    .layer4CorrelationScore(originalResult.getLayer4CorrelationScore())
                    // Zero Trust 확장 필드
                    .adjustedSimilarity(Math.max(0.0, originalResult.getFinalSimilarity() - 0.3))
                    .zeroTrustVerified(true)
                    .verificationLevel(TrustedSimilarityResult.VerificationLevel.FULL)
                    .riskFactors(riskFactors)
                    // 7차원 신호
                    .networkSignal(networkSignal)
                    .cryptoSignal(cryptoSignal)
                    .timingSignal(timingSignal)
                    .build();
        }

        if (decision.getDecision() == Decision.ALLOW_HOT_PATH_DEGRADED) {
            // Graceful Degradation -> trustScore 소폭 하향 조정 (0.1 감소)
            double adjustedTrust = Math.max(0.0, originalResult.getTrustScore() - 0.1);

            log.debug("[ZeroTrustHotPath] Degraded HOT Path: eventId={}, reason={}",
                    event.getEventId(), decision.getReason());

            return TrustedSimilarityResult.builder()
                    .finalSimilarity(originalResult.getFinalSimilarity())
                    .trustScore(adjustedTrust)
                    .crossValidationPassed(originalResult.isCrossValidationPassed())
                    .threatEvidence(originalResult.getThreatEvidence() + "_DEGRADED")
                    .threatType(originalResult.getThreatType())
                    .layer1ThreatSearchScore(originalResult.getLayer1ThreatSearchScore())
                    .layer2BaselineSimilarity(originalResult.getLayer2BaselineSimilarity())
                    .layer3AnomalyScore(originalResult.getLayer3AnomalyScore())
                    .layer4CorrelationScore(originalResult.getLayer4CorrelationScore())
                    // Zero Trust 확장 필드
                    .adjustedSimilarity(Math.max(0.0, originalResult.getFinalSimilarity() - 0.1))
                    .zeroTrustVerified(true)
                    .verificationLevel(TrustedSimilarityResult.VerificationLevel.BASIC)
                    .riskFactors(riskFactors)
                    // 7차원 신호
                    .networkSignal(networkSignal)
                    .cryptoSignal(cryptoSignal)
                    .timingSignal(timingSignal)
                    .build();
        }

        // ALLOW_HOT_PATH -> Zero Trust 검증 통과, 확장 필드 추가하여 반환
        return TrustedSimilarityResult.builder()
                .finalSimilarity(originalResult.getFinalSimilarity())
                .trustScore(originalResult.getTrustScore())
                .crossValidationPassed(originalResult.isCrossValidationPassed())
                .threatEvidence(originalResult.getThreatEvidence())
                .threatType(originalResult.getThreatType())
                .layer1ThreatSearchScore(originalResult.getLayer1ThreatSearchScore())
                .layer2BaselineSimilarity(originalResult.getLayer2BaselineSimilarity())
                .layer3AnomalyScore(originalResult.getLayer3AnomalyScore())
                .layer4CorrelationScore(originalResult.getLayer4CorrelationScore())
                // Zero Trust 확장 필드
                .adjustedSimilarity(originalResult.getFinalSimilarity())
                .zeroTrustVerified(true)
                .verificationLevel(decision.isShouldSample() ?
                        TrustedSimilarityResult.VerificationLevel.FULL :
                        TrustedSimilarityResult.VerificationLevel.BASIC)
                .riskFactors(java.util.Collections.emptyList())
                // 7차원 신호
                .networkSignal(networkSignal)
                .cryptoSignal(cryptoSignal)
                .timingSignal(timingSignal)
                .build();
    }

    /**
     * ZeroTrustDecision에서 RiskFactor 목록 생성
     */
    private java.util.List<TrustedSimilarityResult.RiskFactor> buildRiskFactors(ZeroTrustDecision decision) {
        java.util.List<TrustedSimilarityResult.RiskFactor> factors = new java.util.ArrayList<>();

        // 공격 모드 상태 기반 위험 요소
        if (decision.getAttackMode() != null &&
            decision.getAttackMode().getMode() != AttackModeHysteresisManager.AttackMode.NORMAL) {
            factors.add(TrustedSimilarityResult.RiskFactor.builder()
                    .type("ATTACK_MODE")
                    .score(decision.getAttackMode().getMode() == AttackModeHysteresisManager.AttackMode.CONFIRMED ? 1.0 : 0.7)
                    .description("Attack mode: " + decision.getAttackMode().getMode())
                    .source("HYSTERESIS")
                    .build());
        }

        // Honeypot 패턴 기반 위험 요소
        if (decision.getHoneypotResult() != null && decision.getHoneypotResult().isSuspicious()) {
            factors.add(TrustedSimilarityResult.RiskFactor.builder()
                    .type("HONEYPOT_ACCESS")
                    .score(decision.getHoneypotResult().getSuspicionScore())
                    .description("Suspicious honeypot access pattern detected")
                    .source("HONEYPOT")
                    .build());
        }

        // 신호 불일치 기반 위험 요소
        if (decision.getInconsistency() != null && decision.getInconsistency().isInconsistent()) {
            factors.add(TrustedSimilarityResult.RiskFactor.builder()
                    .type("SIGNAL_INCONSISTENCY")
                    .score(Math.min(1.0, decision.getInconsistency().getMahalanobisDistance() / 10.0))
                    .description("Signal inconsistency detected (Mahalanobis: " +
                            String.format("%.2f", decision.getInconsistency().getMahalanobisDistance()) + ")")
                    .source("MAHALANOBIS")
                    .build());
        }

        // 누적 위험 기반 위험 요소
        if (decision.getRiskResult() != null &&
            decision.getRiskResult().getRiskLevel() != AccumulatedRiskCalculator.RiskLevel.LOW) {
            factors.add(TrustedSimilarityResult.RiskFactor.builder()
                    .type("ACCUMULATED_RISK")
                    .score(decision.getRiskResult().getAccumulatedRisk())
                    .description("Accumulated risk level: " + decision.getRiskResult().getRiskLevel())
                    .source("RISK_CALCULATOR")
                    .build());
        }

        return factors;
    }

    // ===== Private Methods =====

    /**
     * 최종 결정 로직
     */
    private Decision makeDecision(
            EventTier tier,
            AccumulatedRiskResult riskResult,
            AttackModeState attackMode,
            HoneypotAnalysisResult honeypotResult,
            InconsistencyResult inconsistency) {

        // 1. CRITICAL Tier → 무조건 Cold Path
        if (tier == EventTier.CRITICAL) {
            return Decision.ROUTE_TO_COLD_PATH;
        }

        // 2. 공격 모드 CONFIRMED → Cold Path
        if (attackMode.getMode() == AttackModeHysteresisManager.AttackMode.CONFIRMED) {
            return Decision.ROUTE_TO_COLD_PATH;
        }

        // 3. 누적 위험 HIGH 이상 → Cold Path
        if (riskResult.getRiskLevel() == AccumulatedRiskCalculator.RiskLevel.HIGH ||
            riskResult.getRiskLevel() == AccumulatedRiskCalculator.RiskLevel.CRITICAL) {
            return Decision.ROUTE_TO_COLD_PATH;
        }

        // 4. Honeypot 패턴 의심 (score > 0.6) → Cold Path
        if (honeypotResult.isSuspicious() && honeypotResult.getSuspicionScore() > 0.6) {
            return Decision.ROUTE_TO_COLD_PATH;
        }

        // 5. 신호 불일치 + 공격 모드 SUSPECTED → Cold Path
        if (inconsistency.isInconsistent() &&
            attackMode.getMode() == AttackModeHysteresisManager.AttackMode.SUSPECTED) {
            return Decision.ROUTE_TO_COLD_PATH;
        }

        // 6. 누적 위험 MEDIUM + 신호 불일치 → Cold Path
        if (riskResult.getRiskLevel() == AccumulatedRiskCalculator.RiskLevel.MEDIUM &&
            inconsistency.isInconsistent()) {
            return Decision.ROUTE_TO_COLD_PATH;
        }

        // 7. 그 외 → HOT Path 통과
        return Decision.ALLOW_HOT_PATH;
    }

    /**
     * 결정 이유 생성
     */
    private String buildReason(
            AccumulatedRiskResult riskResult,
            AttackModeState attackMode,
            HoneypotAnalysisResult honeypotResult,
            InconsistencyResult inconsistency) {

        StringBuilder reason = new StringBuilder();

        reason.append("risk=").append(riskResult.getRiskLevel());
        reason.append(",attack=").append(attackMode.getMode());

        if (honeypotResult.isSuspicious()) {
            reason.append(",honeypot=").append(String.format("%.2f", honeypotResult.getSuspicionScore()));
        }

        if (inconsistency.isInconsistent()) {
            reason.append(",inconsistent=true");
        }

        return reason.toString();
    }

    // ===== Inner Classes =====

    /**
     * 결정 타입
     */
    public enum Decision {
        ALLOW_HOT_PATH,              // HOT Path 통과 (정상)
        ALLOW_HOT_PATH_DEGRADED,     // HOT Path 강제 통과 (Graceful Degradation)
        ROUTE_TO_COLD_PATH           // Cold Path 라우팅 (의심)
    }

    /**
     * Zero Trust 결정 결과
     */
    @Getter
    @Builder
    public static class ZeroTrustDecision {
        private final Decision decision;                      // 최종 결정
        private final String reason;                          // 결정 이유
        private final boolean shouldSample;                   // 샘플링 여부
        private final EventTier tier;                         // 이벤트 Tier

        // 분석 결과
        private final OrthogonalSignals signals;              // 7차원 신호
        private final InconsistencyResult inconsistency;      // 불일치 탐지 결과
        private final AccumulatedRiskResult riskResult;       // 누적 위험 결과
        private final AttackModeState attackMode;             // 공격 모드 상태
        private final HoneypotAnalysisResult honeypotResult;  // Honeypot 분석 결과
        private final EnqueueResult enqueueResult;            // Cold Path 큐 결과

        // 성능 메트릭
        private final long processingTimeMs;                  // 처리 시간 (ms)
    }
}
