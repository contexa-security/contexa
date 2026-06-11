/*
 * Copyright 2026 The Contexa Project
 *
 * The Contexa Project licenses this file to you under the Apache License,
 * version 2.0 (the "License"); you may not use this file except in compliance
 * with the License. You may obtain a copy of the License at:
 *
 *   https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
 * License for the specific language governing permissions and limitations
 * under the License.
 */
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
