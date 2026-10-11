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
package io.contexa.contexacore.autonomous.tiered.prompt;

import io.contexa.contexacore.autonomous.tiered.util.SecurityEventEnricher;
import io.contexa.contexacore.properties.TieredStrategyProperties;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

class SecurityDecisionPromptSectionsSessionTimelineTest {

    @Test
    @DisplayName("the session action sample is the session's most recent actions (W1-11, B-12)")
    void theSampleIsTheMostRecentActions() {
        SecurityDecisionPromptSections sections = new SecurityDecisionPromptSections(
                new SecurityEventEnricher(),
                new TieredStrategyProperties(),
                SecurityDecisionStandardPromptTemplate.SECURITY_DECISION_PROMPT_GOVERNANCE);
        SecurityDecisionStandardPromptTemplate.SessionContext sessionContext =
                new SecurityDecisionStandardPromptTemplate.SessionContext();
        sessionContext.setRecentActions(List.of(
                "03:10 | GET /api/first",
                "03:12 | GET /api/second",
                "03:15 | GET /api/third",
                "03:17 | POST /api/fourth"));

        String section = sections.buildSessionTimelineSection(sessionContext, null);

        String sample = section.lines()
                .filter(line -> line.startsWith("RecentSessionActionSample"))
                .findFirst()
                .orElseThrow();
        assertThat(sample).contains("/api/third", "/api/fourth").doesNotContain("/api/first", "/api/second");
    }
}
