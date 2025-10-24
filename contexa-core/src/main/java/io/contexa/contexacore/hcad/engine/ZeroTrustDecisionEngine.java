package io.contexa.contexacore.hcad.engine;

import io.contexa.contexacore.autonomous.domain.SecurityEvent;
import io.contexa.contexacore.autonomous.security.processor.ColdPathEventProcessor;
import io.contexa.contexacore.autonomous.tiered.SecurityDecision;
import io.contexa.contexacore.hcad.domain.*;
import io.contexa.contexacore.hcad.service.ZeroTrustThresholdManager;
import io.contexa.contexacore.hcad.service.ThreatCorrelationService;
import io.contexa.contexacore.hcad.service.TrustProfileService;
import lombok.*;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.time.Duration;
import java.time.Instant;
import java.util.*;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Zero Trust Decision Engine (v2.0)
 * **핵심 변경사항**:
 * - AI Layer 진단은 ColdPathEventProcessor에서 이미 완료됨 (ThreatAnalysisResult)
 * - ZeroTrustDecisionEngine은 AI 결과를 입력으로 받아서 Zero Trust 결정만 수행
 * - 3개 전담 서비스로 책임 분리: TrustProfileService, ThreatCorrelationService, AdaptiveThresholdManager
 *
 * **주요 기능**:
 * 1. AI 진단 결과 기반 Zero Trust 최종 결정
 * 2. 신뢰 프로필 관리 (TrustProfileService)
 * 3. 위협 상관관계 분석 (ThreatCorrelationService)
 * 4. 적응형 임계값 관리 (AdaptiveThresholdManager)
 *
 * **제로트러스트 원칙**:
 * - Never Trust, Always Verify
 * - Assume Breach
 * - Verify Explicitly
 * - Use Least Privilege Access
 * - Minimize Blast Radius
 *
 * **LLM 비용 절감**: AI Layer 중복 실행 제거로 50% 비용 절감
 *
 * @author AI3Security
 * @since 2.0
 */
@Slf4j
@Service
@RequiredArgsConstructor
public class ZeroTrustDecisionEngine {

    private final TrustProfileService trustProfileService;
    private final ThreatCorrelationService threatCorrelationService;
    private final ZeroTrustThresholdManager zeroTrustThresholdManager;

    // 활성 위협 세션 관리
    private final Map<String, ActiveThreatSession> activeThreatSessions = new ConcurrentHashMap<>();

    @Value("${zerotrust.engine.enabled:true}")
    private boolean engineEnabled;

    /**
     * AI 진단 결과 기반 Zero Trust 결정 생성
     *
     * 중요: AI Layer 진단은 ColdPathEventProcessor 에서 이미 완료되어 전달됨
     * 이 메소드는 AI 결과를 활용하여 Zero Trust 원칙을 적용하고 최종 결정만 생성
     *
     * @param event 보안 이벤트
     * @param aiAnalysisResult AI 진단 결과 (Layer 1/2/3 완료)
     * @return CompletableFuture<ZeroTrustDecision>
     */
    public CompletableFuture<ZeroTrustDecision> makeDecision(SecurityEvent event,
                                                             ColdPathEventProcessor.ThreatAnalysisResult aiAnalysisResult) {
        if (!engineEnabled) {
            return CompletableFuture.completedFuture(createFallbackDecision(event));
        }

        return CompletableFuture.supplyAsync(() -> {
            long startTime = System.currentTimeMillis();
            String userId = event.getUserId();

            try {
                log.debug("[ZeroTrustDecision] Processing event {} for user {}", event.getEventId(), userId);

                // 1. 신뢰 프로필 로드
                UserTrustProfile trustProfile = trustProfileService.getOrCreateUserTrustProfile(userId);

                // 2. 위협 상관관계 분석
                ThreatCorrelationResult correlationResult =
                    threatCorrelationService.performThreatCorrelation(event, trustProfile);

                // 3. AI 결과에서 최종 결정 추출
                SecurityDecision aiDecision = aiAnalysisResult.getFinalDecision();

                // 4. Zero Trust 결정 생성
                ZeroTrustDecision decision = generateZeroTrustDecision(
                    event, trustProfile, aiDecision, aiAnalysisResult, correlationResult, startTime);

                // 5. 신뢰 프로필 업데이트
                updateUserTrustProfile(trustProfile, decision);

                // 6. 활성 위협 세션 관리
                manageActiveThreatSessions(event, decision, correlationResult);

                // 7. 성능 메트릭 기록
                long processingTime = System.currentTimeMillis() - startTime;
                zeroTrustThresholdManager.recordAnalysisMetrics(userId, processingTime, true);

                log.info("[ZeroTrustDecision] Decision completed for user {} - Action: {}, Trust: {}, Risk: {}, Time: {}ms",
                        userId, decision.getFinalAction(), String.format("%.3f", decision.getCurrentTrustScore()),
                        decision.getRiskLevel(), processingTime);

                return decision;

            } catch (Exception e) {
                log.error("[ZeroTrustDecision] Decision failed for user {}", userId, e);
                zeroTrustThresholdManager.recordAnalysisMetrics(userId,
                    System.currentTimeMillis() - startTime, false);
                return createErrorDecision(event, e, startTime);
            }
        });
    }

    /**
     * Zero Trust 결정 생성
     */
    private ZeroTrustDecision generateZeroTrustDecision(SecurityEvent event, UserTrustProfile trustProfile,
                                                        SecurityDecision aiDecision,
                                                        ColdPathEventProcessor.ThreatAnalysisResult aiAnalysisResult,
                                                        ThreatCorrelationResult correlationResult, long startTime) {
        // 1. 신뢰 점수 조정
        double adjustedTrustScore = calculateAdjustedTrustScore(
            trustProfile.getCurrentTrustScore(), aiDecision, correlationResult);

        // 2. 위험 수준 결정
        RiskLevel riskLevel = determineRiskLevel(adjustedTrustScore, aiDecision, correlationResult);

        // 3. 최종 액션 결정 (Zero Trust 원칙 적용)
        SecurityDecision.Action finalAction = applyZeroTrustPrinciples(
            aiDecision.getAction(), adjustedTrustScore, riskLevel, correlationResult);

        // 4. 접근 제어 권고사항 생성
        List<String> accessRecommendations = generateAccessRecommendations(
            adjustedTrustScore, riskLevel, correlationResult);

        // 5. 연속 모니터링 요구사항
        ContinuousMonitoring monitoringRequirements = generateMonitoringRequirements(
            riskLevel, correlationResult, aiDecision);

        // 6. 추가 메타데이터
        Map<String, Object> metadata = new HashMap<>();
        metadata.put("ai_layer_executed", aiAnalysisResult.getLayerExecuted());
        metadata.put("ai_processing_time_ms", aiAnalysisResult.getProcessingTimeMs());
        metadata.put("threat_level", aiAnalysisResult.getThreatLevel());

        return ZeroTrustDecision.builder()
            .analysisId(generateAnalysisId(event))
            .eventId(event.getEventId())
            .userId(event.getUserId())
            .finalAction(finalAction)
            .originalAction(aiDecision.getAction())
            .currentTrustScore(adjustedTrustScore)
            .previousTrustScore(trustProfile.getCurrentTrustScore())
            .riskLevel(riskLevel)
            .confidence(aiDecision.getConfidence())
            .reasoning(generateZeroTrustReasoning(aiDecision, correlationResult, aiAnalysisResult))
            .threatCorrelation(correlationResult)
            .accessRecommendations(accessRecommendations)
            .monitoringRequirements(monitoringRequirements)
            .processingTimeMs(System.currentTimeMillis() - startTime)
            .timestamp(Instant.now())
            .zeroTrustPrinciples(getAppliedPrinciples(finalAction, riskLevel))
            .metadata(metadata)
            .build();
    }

    /**
     * 신뢰 점수 조정 계산
     */
    private double calculateAdjustedTrustScore(double currentTrustScore, SecurityDecision aiDecision,
                                              ThreatCorrelationResult correlationResult) {
        double adjustment = 0.0;

        // 1. AI 결정 기반 조정
        switch (aiDecision.getAction()) {
            case ALLOW:
                adjustment += 0.05;
                break;
            case MONITOR:
                adjustment += 0.02;
                break;
            case INVESTIGATE:
                adjustment -= 0.05;
                break;
            case MITIGATE:
                adjustment -= 0.10;
                break;
            case BLOCK:
                adjustment -= 0.20;
                break;
            case ESCALATE:
                adjustment -= 0.15;
                break;
        }

        // 2. 상관관계 기반 조정
        adjustment -= correlationResult.getCorrelationScore() * 0.3;

        // 3. AI 위험 점수 기반 조정
        adjustment -= aiDecision.getRiskScore() * 0.2;

        // 4. AI 신뢰도 기반 가중치
        adjustment *= aiDecision.getConfidence();

        // 5. 조정된 점수 계산 (0.0 ~ 1.0 범위 유지)
        double adjustedScore = currentTrustScore + adjustment;
        return Math.max(0.0, Math.min(1.0, adjustedScore));
    }

    /**
     * 위험 수준 결정
     */
    private RiskLevel determineRiskLevel(double trustScore, SecurityDecision aiDecision,
                                       ThreatCorrelationResult correlationResult) {
        double aiRiskScore = aiDecision.getRiskScore();
        double correlationScore = correlationResult.getCorrelationScore();

        // 복합 위험 점수 계산
        double compositeRisk = (aiRiskScore * 0.4) + (correlationScore * 0.3) + ((1.0 - trustScore) * 0.3);

        if (compositeRisk >= 0.8) {
            return RiskLevel.CRITICAL;
        } else if (compositeRisk >= 0.6) {
            return RiskLevel.HIGH;
        } else if (compositeRisk >= 0.4) {
            return RiskLevel.MEDIUM;
        } else if (compositeRisk >= 0.2) {
            return RiskLevel.LOW;
        } else {
            return RiskLevel.MINIMAL;
        }
    }

    /**
     * Zero Trust 원칙 적용
     */
    private SecurityDecision.Action applyZeroTrustPrinciples(SecurityDecision.Action aiAction,
                                                           double trustScore, RiskLevel riskLevel,
                                                           ThreatCorrelationResult correlationResult) {
        // Never Trust, Always Verify 원칙
        if (riskLevel == RiskLevel.CRITICAL || trustScore < 0.2) {
            return SecurityDecision.Action.BLOCK;
        }

        // Assume Breach 원칙
        if (correlationResult.getCorrelationScore() > 0.7 || riskLevel == RiskLevel.HIGH) {
            if (aiAction == SecurityDecision.Action.ALLOW) {
                return SecurityDecision.Action.MITIGATE;
            }
        }

        // Least Privilege 원칙
        if (trustScore < 0.5 && aiAction == SecurityDecision.Action.ALLOW) {
            return SecurityDecision.Action.MONITOR;
        }

        return aiAction;
    }

    /**
     * Zero Trust 추론 생성
     */
    private String generateZeroTrustReasoning(SecurityDecision aiDecision, ThreatCorrelationResult correlation,
                                            ColdPathEventProcessor.ThreatAnalysisResult aiAnalysisResult) {
        StringBuilder reasoning = new StringBuilder();
        reasoning.append("Zero Trust Analysis: ");
        reasoning.append("AI_Action=").append(aiDecision.getAction());
        reasoning.append(", AI_Layer=").append(aiAnalysisResult.getLayerExecuted());
        reasoning.append(", AI_Confidence=").append(String.format("%.2f", aiDecision.getConfidence()));
        reasoning.append(", Correlation=").append(String.format("%.2f", correlation.getCorrelationScore()));

        if (!correlation.getSuspiciousPatterns().isEmpty()) {
            reasoning.append(", Patterns=").append(String.join(",", correlation.getSuspiciousPatterns()));
        }

        return reasoning.toString();
    }

    /**
     * 접근 제어 권고사항 생성
     */
    private List<String> generateAccessRecommendations(double trustScore, RiskLevel riskLevel,
                                                      ThreatCorrelationResult correlation) {
        List<String> recommendations = new ArrayList<>();

        if (riskLevel.ordinal() >= RiskLevel.HIGH.ordinal()) {
            recommendations.add("ENFORCE_MFA");
            recommendations.add("LIMIT_ACCESS_SCOPE");
        }

        if (trustScore < 0.5) {
            recommendations.add("ADDITIONAL_VERIFICATION");
        }

        if (correlation.getCorrelationScore() > 0.6) {
            recommendations.add("CONTINUOUS_MONITORING");
        }

        return recommendations;
    }

    /**
     * 연속 모니터링 요구사항 생성
     */
    private ContinuousMonitoring generateMonitoringRequirements(RiskLevel riskLevel,
                                                              ThreatCorrelationResult correlation,
                                                              SecurityDecision aiDecision) {
        boolean required = riskLevel.ordinal() >= RiskLevel.MEDIUM.ordinal();
        Duration duration = riskLevel == RiskLevel.CRITICAL ? Duration.ofHours(24) : Duration.ofHours(1);
        List<String> aspects = Arrays.asList("ACCESS_PATTERNS", "BEHAVIOR_ANOMALIES", "RESOURCE_USAGE");
        int threshold = riskLevel == RiskLevel.CRITICAL ? 1 : 3;

        return ContinuousMonitoring.builder()
            .required(required)
            .monitoringDuration(duration)
            .monitoringAspects(aspects)
            .alertThreshold(threshold)
            .build();
    }

    /**
     * 적용된 Zero Trust 원칙
     */
    private List<String> getAppliedPrinciples(SecurityDecision.Action action, RiskLevel riskLevel) {
        List<String> principles = new ArrayList<>();
        principles.add("NEVER_TRUST_ALWAYS_VERIFY");

        if (action == SecurityDecision.Action.BLOCK || riskLevel == RiskLevel.CRITICAL) {
            principles.add("ASSUME_BREACH");
            principles.add("MINIMIZE_BLAST_RADIUS");
        }

        if (action != SecurityDecision.Action.ALLOW) {
            principles.add("LEAST_PRIVILEGE_ACCESS");
        }

        return principles;
    }

    /**
     * 사용자 신뢰 프로필 업데이트
     */
    private void updateUserTrustProfile(UserTrustProfile trustProfile, ZeroTrustDecision decision) {
        try {
            // 1. 신뢰 점수 업데이트
            trustProfileService.updateTrustScore(trustProfile, decision.getCurrentTrustScore());

            // 2. 분석 카운트 증가
            trustProfileService.incrementAnalysisCount(trustProfile);

            // 3. 보안 인시던트 추가 (위험한 경우만)
            if (decision.getRiskLevel().ordinal() >= RiskLevel.MEDIUM.ordinal()) {
                SecurityIncident incident = SecurityIncident.builder()
                    .eventId(decision.getEventId())
                    .eventType(decision.getFinalAction().toString())
                    .riskLevel(decision.getRiskLevel())
                    .timestamp(decision.getTimestamp())
                    .sourceIp(null)  // event에서 추출 필요
                    .build();

                trustProfileService.addSecurityIncident(trustProfile, incident);
            }

            // 4. 적응형 임계값 업데이트
            zeroTrustThresholdManager.updateThresholdsFromDecision(trustProfile.getUserId(), decision);

        } catch (Exception e) {
            log.error("[ZeroTrustDecision] Failed to update trust profile", e);
        }
    }

    /**
     * 활성 위협 세션 관리
     */
    private void manageActiveThreatSessions(SecurityEvent event, ZeroTrustDecision decision,
                                          ThreatCorrelationResult correlation) {
        String userId = event.getUserId();
        String sessionKey = userId + "_" + System.currentTimeMillis();

        if (decision.getRiskLevel().ordinal() >= RiskLevel.HIGH.ordinal()) {
            ActiveThreatSession session = ActiveThreatSession.builder()
                .sessionId(sessionKey)
                .userId(userId)
                .startTime(Instant.now())
                .maxRiskLevel(decision.getRiskLevel())
                .eventIds(new ArrayList<>(Arrays.asList(event.getEventId())))
                .incidentCount(1)
                .build();

            activeThreatSessions.put(sessionKey, session);
        }
    }

    /**
     * 분석 ID 생성
     */
    private String generateAnalysisId(SecurityEvent event) {
        return String.format("ZT_%s_%s_%d",
            event.getUserId() != null ? event.getUserId() : "unknown",
            event.getEventId() != null ? event.getEventId() : "unknown",
            System.currentTimeMillis());
    }

    /**
     * 폴백 결정 생성
     */
    private ZeroTrustDecision createFallbackDecision(SecurityEvent event) {
        return ZeroTrustDecision.builder()
            .analysisId("FALLBACK_" + System.currentTimeMillis())
            .eventId(event.getEventId())
            .userId(event.getUserId())
            .finalAction(SecurityDecision.Action.MONITOR)
            .originalAction(SecurityDecision.Action.MONITOR)
            .currentTrustScore(0.5)
            .previousTrustScore(0.5)
            .riskLevel(RiskLevel.MEDIUM)
            .confidence(0.5)
            .reasoning("ZeroTrust engine disabled - fallback decision")
            .processingTimeMs(1L)
            .timestamp(Instant.now())
            .zeroTrustPrinciples(Arrays.asList("FALLBACK_MODE"))
            .build();
    }

    /**
     * 오류 결정 생성
     */
    private ZeroTrustDecision createErrorDecision(SecurityEvent event, Exception error, long startTime) {
        return ZeroTrustDecision.builder()
            .analysisId("ERROR_" + System.currentTimeMillis())
            .eventId(event.getEventId())
            .userId(event.getUserId())
            .finalAction(SecurityDecision.Action.BLOCK) // 오류 시 안전한 기본값
            .originalAction(SecurityDecision.Action.MONITOR)
            .currentTrustScore(0.0)
            .previousTrustScore(0.5)
            .riskLevel(RiskLevel.CRITICAL)
            .confidence(0.0)
            .reasoning("Error in Zero Trust decision: " + error.getMessage())
            .processingTimeMs(System.currentTimeMillis() - startTime)
            .timestamp(Instant.now())
            .zeroTrustPrinciples(Arrays.asList("ERROR_MODE", "ASSUME_BREACH"))
            .build();
    }
}
