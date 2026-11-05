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
package io.contexa.contexaidentity.security.core.mfa.util;

import io.contexa.contexacommon.enums.ZeroTrustAction;
import io.contexa.contexaidentity.security.core.mfa.model.MfaDecision.DecisionType;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

/** PR-99: no stored action reads as a waiver of the second step of a new sign-in. */
class ZeroTrustActionMfaMapperTest {

    @Test
    @DisplayName("no stored action, ALLOW included, maps to no MFA")
    void noStoredActionWaivesTheSecondStep() {
        for (ZeroTrustAction action : ZeroTrustAction.values()) {
            assertThat(ZeroTrustActionMfaMapper.toDecisionType(action)).as(action.name())
                    .isNotEqualTo(DecisionType.NO_MFA_REQUIRED);
        }
    }

    @Test
    @DisplayName("ALLOW, CHALLENGE, a pending analysis and no action ask for the second step; BLOCK and ESCALATE refuse")
    void eachActionHasItsDecision() {
        assertThat(ZeroTrustActionMfaMapper.toDecisionType(ZeroTrustAction.ALLOW)).isEqualTo(DecisionType.CHALLENGED);
        assertThat(ZeroTrustActionMfaMapper.toDecisionType(ZeroTrustAction.CHALLENGE)).isEqualTo(DecisionType.CHALLENGED);
        assertThat(ZeroTrustActionMfaMapper.toDecisionType(ZeroTrustAction.PENDING_ANALYSIS)).isEqualTo(DecisionType.CHALLENGED);
        assertThat(ZeroTrustActionMfaMapper.toDecisionType(null)).isEqualTo(DecisionType.CHALLENGED);
        assertThat(ZeroTrustActionMfaMapper.toDecisionType(ZeroTrustAction.BLOCK)).isEqualTo(DecisionType.BLOCKED);
        assertThat(ZeroTrustActionMfaMapper.toDecisionType(ZeroTrustAction.ESCALATE)).isEqualTo(DecisionType.ESCALATED);
    }
}
