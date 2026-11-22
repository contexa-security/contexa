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
package io.contexa.contexacore.std.components.prompt.quality;

import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Plan 3.3: the final action the scoring computes from the server's settings: a first answer that does not defer is
 * the action; after an ESCALATE the second pass decides, an action it cannot use is CHALLENGE, and an ESCALATE left
 * after it ends in the action the server is set to, or stays when the server lets it.
 */
class QualityClosingRulesTest {

    @Test
    void aFirstAnswerThatDoesNotDeferIsTheFinalAction() {
        QualityClosingRules rules = QualityClosingRules.DEFAULTS;
        assertThat(rules.finalAction("ALLOW", false, null)).isEqualTo(QualityAction.ALLOW);
        assertThat(rules.finalAction(" block ", true, "ALLOW")).isEqualTo(QualityAction.BLOCK);
        assertThat(rules.finalAction("CHALLENGE", false, null)).isEqualTo(QualityAction.CHALLENGE);
        // An action no rule can use is replaced, as the engine replaces it.
        assertThat(rules.finalAction("REVIEW", false, null)).isEqualTo(QualityAction.CHALLENGE);
        assertThat(rules.finalAction(null, false, null)).isNull();
        assertThat(rules.finalAction(" ", false, null)).isNull();
    }

    @Test
    void afterAnEscalateTheSecondPassDecidesAndAnEscalateLeftEndsInTheTerminalAction() {
        QualityClosingRules rules = QualityClosingRules.DEFAULTS;
        assertThat(rules.finalAction("ESCALATE", true, "ALLOW")).isEqualTo(QualityAction.ALLOW);
        assertThat(rules.finalAction("ESCALATE", true, "BLOCK")).isEqualTo(QualityAction.BLOCK);
        assertThat(rules.finalAction("ESCALATE", true, "ESCALATE")).isEqualTo(QualityAction.CHALLENGE);
        assertThat(rules.finalAction("ESCALATE", true, "unreadable")).isEqualTo(QualityAction.CHALLENGE);
        assertThat(rules.finalAction("ESCALATE", true, null)).isEqualTo(QualityAction.CHALLENGE);
        // Without the second pass's answer the final action is not known.
        assertThat(rules.finalAction("ESCALATE", false, null)).isNull();

        assertThat(new QualityClosingRules(QualityAction.BLOCK).finalAction("ESCALATE", true, "ESCALATE"))
                .isEqualTo(QualityAction.BLOCK);
        QualityClosingRules kept = new QualityClosingRules(null);
        assertThat(kept.finalAction("ESCALATE", true, "ESCALATE")).isEqualTo(QualityAction.ESCALATE);
        assertThat(new QualityClosingRules(QualityAction.ESCALATE).escalateTerminalAction()).isNull();
    }
}
