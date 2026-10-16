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

import io.contexa.contexacommon.domain.EventTimeZone;
import io.contexa.contexacommon.domain.SecurityEvent;
import io.contexa.contexacore.autonomous.context.prompt.PromptListItem;
import io.contexa.contexacore.autonomous.context.support.PastDeniedDecisions;
import io.contexa.contexacore.autonomous.tiered.util.SecurityEventEnricher;
import io.contexa.contexacore.properties.TieredStrategyProperties;
import io.contexa.contexacore.std.components.prompt.PromptBudgetProfile;
import org.junit.jupiter.api.Test;

import java.time.Instant;
import java.time.LocalDateTime;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

/** W5-4: the user's recent decisions that did not allow are lines of the past records block, sealed with the prompt. */
class PastDeniedDecisionsPromptTest {

    private static final Instant REQUEST = Instant.parse("2026-10-12T03:17:00Z");

    @Test
    void theRecentDecisionsThatDidNotAllowAreLinesOfThePastRecordsBlock() {
        SecurityEvent event = event("event-denied-1");
        PastDeniedDecisions denied = new PastDeniedDecisions(List.of(new PastDeniedDecisions.Entry(
                LocalDateTime.of(2026, 10, 10, 3, 17), "EXPORT", "projectKey=GB-500", "CHALLENGE",
                PastDeniedDecisions.NOT_VERIFIED)));
        event.addMetadata(PastDeniedDecisions.EVENT_METADATA_KEY, denied.toMetadata());

        SecurityDecisionStandardPromptTemplate.StructuredPrompt prompt = v20().buildStructuredPrompt(event, null, null,
                List.of(), PromptBudgetProfile.CORTEX_L1_INTERACTIVE_STRICT);
        List<PromptListItem> expected = PastDeniedLines.items(denied, LocalDateTime.ofInstant(REQUEST, EventTimeZone.get()));

        assertThat(prompt.userText()).contains("PastDeniedDecision1: " + expected.get(0).text());
        assertThat(prompt.executionMetadata().toMetadataMap()).containsEntry("promptPastDeniedDecisions",
                denied.toMetadata());
    }

    @Test
    void withoutDecisionsThereIsNoLine() {
        SecurityDecisionStandardPromptTemplate.StructuredPrompt prompt = v20().buildStructuredPrompt(
                event("event-denied-2"), null, null, List.of(), PromptBudgetProfile.CORTEX_L1_INTERACTIVE_STRICT);

        assertThat(prompt.userText()).doesNotContain("PastDeniedDecision");
        assertThat(prompt.executionMetadata().toMetadataMap()).doesNotContainKey("promptPastDeniedDecisions");
    }

    private static SecurityDecisionPromptSections v20() {
        TieredStrategyProperties properties = new TieredStrategyProperties();
        properties.getPromptBundle().setActive(SecurityDecisionPromptBundles.V20.version());
        return new SecurityDecisionPromptSections(new SecurityEventEnricher(), properties);
    }

    private static SecurityEvent event(String eventId) {
        SecurityEvent event = SecurityEvent.builder()
                .eventId(eventId)
                .timestamp(REQUEST)
                .userId("alice")
                .sessionId("session-denied")
                .build();
        event.addMetadata("requestPath", "/api/projects/GB-500/exports");
        event.addMetadata("resourceUrlTemplate", "/api/projects/{projectKey}/exports");
        event.addMetadata("httpMethod", "POST");
        event.addMetadata("ragSearchExecuted", true);
        event.addMetadata("ragRetrievalState", "ZERO_RESULTS");
        return event;
    }
}
