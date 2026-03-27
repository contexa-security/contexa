package io.contexa.contexacore.autonomous.tiered;

import io.contexa.contexacommon.enums.ZeroTrustAction;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

class SecurityDecisionTest {

    @Test
    void resolveAuditScoresReturnDedicatedAuditFields() {
        SecurityDecision decision = SecurityDecision.builder()
                .riskScore(null)
                .confidence(null)
                .llmAuditRiskScore(0.81)
                .llmAuditConfidence(0.77)
                .build();

        assertThat(decision.getRiskScore()).isNull();
        assertThat(decision.getConfidence()).isNull();
        assertThat(decision.resolveAuditRiskScore()).isEqualTo(0.81);
        assertThat(decision.resolveAuditConfidence()).isEqualTo(0.77);
    }

    @Test
    void resolveAutonomousActionPrefersDedicatedEnforcementAction() {
        SecurityDecision decision = SecurityDecision.builder()
                .action(ZeroTrustAction.ALLOW)
                .autonomousAction(ZeroTrustAction.CHALLENGE)
                .build();

        assertThat(decision.resolveAutonomousAction()).isEqualTo(ZeroTrustAction.CHALLENGE);
    }
}
