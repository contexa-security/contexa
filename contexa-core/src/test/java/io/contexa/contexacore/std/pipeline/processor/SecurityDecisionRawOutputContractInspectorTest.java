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
package io.contexa.contexacore.std.pipeline.processor;

import io.contexa.contexacore.autonomous.tiered.prompt.SecurityDecisionFactChecks;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * What the response checks share after the v19 and v20 checks went with their bundles (plan 6-2): the fallback of a
 * rule an answer still breaks after the corrective retry. The checks of the form and of what an answer says, and the
 * boundaries on the facts its prompt states, are the v21 check and the v1.0 rules (SecurityDecisionV21OutputInspectorTest,
 * SecurityDecisionV1ResponseCheckTest, SecurityDecisionFactChecksTest).
 */
class SecurityDecisionRawOutputContractInspectorTest {

    /**
     * N-OUT-1 (G1-1, decision A): a contract violation left after the retry falls back to ESCALATE (the code does not
     * choose the response), unless the broken rule asks for one action ESCALATE does not give.
     */
    @Test
    void theFallbackOfAViolationLeftAfterTheRetryFollowsTheRuleItBroke() {
        assertThat(SecurityDecisionRawOutputContractInspector.fallbackActionFor("REQUIRED_BLOCK_BOUNDARY_ACTION_MISMATCH"))
                .isEqualTo("BLOCK");
        assertThat(SecurityDecisionRawOutputContractInspector.fallbackActionFor(
                "REQUIRED_LOW_RISK_BOUNDARY_ACTION_MISMATCH")).isEqualTo("ALLOW");
        assertThat(SecurityDecisionRawOutputContractInspector.fallbackActionFor(
                SecurityDecisionFactChecks.REQUIRED_COVERED_WORK)).isEqualTo("ALLOW");
        assertThat(SecurityDecisionRawOutputContractInspector.fallbackActionFor("BLOCK_WITHOUT_DECISIVE_EVIDENCE"))
                .isEqualTo("ESCALATE");
        assertThat(SecurityDecisionRawOutputContractInspector.fallbackActionFor(
                "MINIMUM_ACTION_VIOLATION: MIN_P1_IDENTITY_DEVIATION requires CHALLENGE or a stronger action"))
                .isEqualTo("ESCALATE");
        assertThat(SecurityDecisionRawOutputContractInspector.fallbackActionFor("FALSE_AUTHORIZED_RAG_CLAIM"))
                .isEqualTo("ESCALATE");
        assertThat(SecurityDecisionRawOutputContractInspector.fallbackActionFor("PARSER_MALFORMED_JSON"))
                .isEqualTo("ESCALATE");
        assertThat(SecurityDecisionRawOutputContractInspector.fallbackActionFor(null)).isEqualTo("ESCALATE");
    }
}
