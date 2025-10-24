package io.contexa.contexaiam.aiam.web;

import io.contexa.contexacore.autonomous.event.SecurityEventPublisher;
import io.contexa.contexacore.autonomous.event.domain.ThreatDetectionEvent;
import io.contexa.contexacore.autonomous.event.publisher.KafkaSecurityEventPublisher;
import io.contexa.contexacore.domain.entity.AttackResult;
import io.contexa.contexacore.domain.entity.CustomerData;
import io.contexa.contexacore.simulation.context.SimulationModeHolder;
import io.contexa.contexacore.simulation.tracker.DataBreachTracker;
import io.contexa.contexaiam.aiam.service.ProtectableDataService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;

import java.util.Map;
import java.util.Optional;

/**
 * 공격 이벤트 발행을 위한 헬퍼 클래스
 *
 * AttackResult를 ThreatDetectionEvent로 변환하여 발행합니다.
 * 시뮬레이션 모드에 따라:
 * - 무방비 모드: 이벤트 발행 없이 직접 데이터 접근
 * - 방어 모드: 정상적으로 이벤트 발행
 */
@Slf4j
@Component
@RequiredArgsConstructor
public class AttackEventHelper {

    private final KafkaSecurityEventPublisher eventPublisher;
    private final ProtectableDataService protectableDataService;
    private final DataBreachTracker dataBreachTracker;

    /**
     * AttackResult를 ThreatDetectionEvent로 변환하여 발행
     * 시뮬레이션 모드를 확인하여 무방비 모드에서는 이벤트 발행하지 않음
     */
    public void publishAttackEvent(AttackResult attack, String action, String description) {
        // 시뮬레이션 컨텍스트 확인
        SimulationModeHolder.SimulationContext context = SimulationModeHolder.getContext();

        // 무방비 모드에서는 이벤트 발행하지 않음
        if (context != null && context.shouldBypassSecurity()) {
            log.warn("UNPROTECTED MODE - Skipping event publication for attack: {}", attack.getAttackId());

            // 대신 직접 데이터 접근 시도 (고객 ID가 있는 경우)
            String targetUser = attack.getTargetUser();
            if (targetUser != null && targetUser.startsWith("customer-")) {
                attemptDirectDataBreach(targetUser, attack, context);
            }
            return;
        }

        // 방어 모드 또는 일반 모드에서는 정상적으로 이벤트 발행
        ThreatDetectionEvent threatEvent = ThreatDetectionEvent.builder()
            .threatId(attack.getAttackId())
            .threatType(mapAttackTypeToThreatType(attack.getAttackType()))
            .threatLevel(mapRiskScoreToThreatLevel(attack.getRiskScore()))
            .detectionSource(attack.getTargetResource())
            .confidenceScore(attack.getRiskScore())
            .affectedResources(new String[]{attack.getTargetResource()})
            .recommendedActions(generateRecommendedActions(attack))
            .metadata(Map.of(
                "username", attack.getUsername() != null ? attack.getUsername() : "unknown",
                "action", action != null ? action : "unknown",
                "description", description != null ? description : "",
                "attackType", attack.getAttackType().toString()
            ))
            .build();

        eventPublisher.publishThreatDetection(threatEvent);
    }

    /**
     * 간단한 공격 이벤트 발행
     */
    public void publishSimpleAttack(String threatId, String threatType,
                                   ThreatDetectionEvent.ThreatLevel level,
                                   String source, double confidence,
                                   String[] resources, Map<String, Object> metadata) {
        ThreatDetectionEvent threatEvent = ThreatDetectionEvent.builder()
            .threatId(threatId)
            .threatType(threatType)
            .threatLevel(level)
            .detectionSource(source)
            .confidenceScore(confidence)
            .affectedResources(resources)
            .metadata(metadata)
            .build();

        eventPublisher.publishThreatDetection(threatEvent);
    }

    private String mapAttackTypeToThreatType(AttackResult.AttackType attackType) {
        return switch (attackType) {
            case BEHAVIORAL_ANOMALY -> "BEHAVIORAL_ANOMALY";
            case DATA_EXFILTRATION -> "DATA_EXFILTRATION";
            case IDOR -> "IDOR";
            case ACCOUNT_ENUMERATION -> "ACCOUNT_ENUMERATION";
            case API_KEY_EXPOSURE -> "API_KEY_EXPOSURE";
            case GRAPHQL_INJECTION -> "GRAPHQL_INJECTION";
            case ADVERSARIAL_EVASION -> "ADVERSARIAL_EVASION";
            case MODEL_POISONING -> "MODEL_POISONING";
            case MODEL_EXTRACTION -> "MODEL_EXTRACTION";
            case PROMPT_INJECTION -> "PROMPT_INJECTION";
            case MFA_BYPASS -> "MFA_BYPASS";
            case SEQUENCE_BREAKING -> "SEQUENCE_BREAKING";
            case RATE_LIMIT_BYPASS -> "RATE_LIMIT_BYPASS";
            case VELOCITY_ATTACK -> "VELOCITY_ATTACK";
            case PRIVILEGE_ESCALATION -> "PRIVILEGE_ESCALATION";
            default -> "UNKNOWN_THREAT";
        };
    }

    private ThreatDetectionEvent.ThreatLevel mapRiskScoreToThreatLevel(double riskScore) {
        if (riskScore >= 0.9) return ThreatDetectionEvent.ThreatLevel.CRITICAL;
        if (riskScore >= 0.7) return ThreatDetectionEvent.ThreatLevel.HIGH;
        if (riskScore >= 0.5) return ThreatDetectionEvent.ThreatLevel.MEDIUM;
        if (riskScore >= 0.3) return ThreatDetectionEvent.ThreatLevel.LOW;
        return ThreatDetectionEvent.ThreatLevel.INFO;
    }

    private String[] generateRecommendedActions(AttackResult attack) {
        double risk = attack.getRiskScore();

        if (risk >= 0.9) {
            return new String[]{
                "Block immediately",
                "Alert security team",
                "Initiate incident response",
                "Preserve evidence"
            };
        } else if (risk >= 0.7) {
            return new String[]{
                "Monitor closely",
                "Review access logs",
                "Consider rate limiting",
                "Alert on-call team"
            };
        } else if (risk >= 0.5) {
            return new String[]{
                "Monitor activity",
                "Review patterns",
                "Update security rules"
            };
        } else {
            return new String[]{
                "Log for analysis",
                "Monitor trends"
            };
        }
    }

    /**
     * 무방비 모드에서 직접 데이터 유출 시도
     */
    private void attemptDirectDataBreach(String targetUser, AttackResult attack,
                                        SimulationModeHolder.SimulationContext context) {
        try {
            // 고객 ID 추출 (예: "customer-123" → "123")
            String customerId = targetUser.replace("customer-", "");

            // 보안 체크 없이 직접 접근
            Optional<CustomerData> dataOpt = protectableDataService.getCustomerDataDirect(customerId);

            if (dataOpt.isPresent()) {
                CustomerData data = dataOpt.get();
                log.error("UNPROTECTED DATA BREACH - Attack: {}, Customer: {}, Sensitivity: {}",
                         attack.getAttackType(), customerId, data.getSensitivityLevel());

                // 데이터 유출 기록
                dataBreachTracker.recordDataBreach(
                    context.getCampaignId(),
                    context.getAttackId(),
                    attack.getAttackType().name(),
                    data,
                    "UNPROTECTED"
                );

                // AttackResult에 유출 정보 추가
                attack.setDataBreached(true);
                attack.setBreachedRecordCount(1);
            } else {
                log.debug("No customer data found for: {}", customerId);
                dataBreachTracker.recordAccessAttempt(
                    context.getCampaignId(),
                    context.getAttackId(),
                    attack.getAttackType().name(),
                    customerId,
                    false,
                    "UNPROTECTED"
                );
            }
        } catch (Exception e) {
            log.error("Error attempting direct data breach", e);
        }
    }
}