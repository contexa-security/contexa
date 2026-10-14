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

import io.contexa.contexacommon.domain.SecurityEvent;
import io.contexa.contexacore.autonomous.context.support.PastRecordCounts;
import io.contexa.contexacore.autonomous.tiered.util.SecurityEventEnricher;
import io.contexa.contexacore.properties.TieredStrategyProperties;
import io.contexa.contexacore.std.components.prompt.PromptBudgetProfile;
import org.junit.jupiter.api.Test;

import java.time.Instant;
import java.time.LocalDateTime;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * W3-18: the counted past record facts of the exact lookup are one line of the v20 PAST RECORDS block; without them
 * their name goes to the UNKNOWN block as not retrieved this time.
 */
class PastRecordCountsPromptTest {

    private static final String EXPORTS = "/api/projects/{projectKey}/exports";

    @Test
    void theCountsOfTheLookupAreALineOfThePastRecordsBlock() {
        SecurityEvent event = event("event-counts-1");
        event.addMetadata("ragSearchExecuted", true);
        event.addMetadata("ragRetrievalState", "ZERO_RESULTS");
        PastRecordCounts counts = new PastRecordCounts("EXPORT", "POST " + EXPORTS, 2,
                LocalDateTime.of(2026, 10, 12, 1, 0), 1, null, 0, 3);
        event.addMetadata("ragPastRecordCounts", counts.toMetadata());

        SecurityDecisionStandardPromptTemplate.StructuredPrompt prompt = v20().buildStructuredPrompt(event, null, null,
                List.of(), PromptBudgetProfile.CORTEX_L1_INTERACTIVE_STRICT);
        String user = prompt.userText();

        assertThat(user).contains("PastRecordCounts: EXPORT on this target 2 (last ")
                .contains("; on other targets 1 (last time not recorded); entry point POST " + EXPORTS
                        + " used 3 times before");
        assertThat(unknownLine(user)).doesNotContain("PastRecordCounts");
        // The prompt inspector compares the line with the counts the render drew it from, sealed with the prompt.
        assertThat(prompt.executionMetadata().toMetadataMap()).containsEntry("promptPastRecordCounts",
                counts.toMetadata());
    }

    @Test
    void withoutCountsTheirNameIsUnknownAsNotRetrieved() {
        SecurityEvent event = event("event-counts-2");
        event.addMetadata("ragSearchExecuted", false);
        event.addMetadata("ragRetrievalState", "UNAVAILABLE");

        SecurityDecisionStandardPromptTemplate.StructuredPrompt prompt = v20().buildStructuredPrompt(event, null, null,
                List.of(), PromptBudgetProfile.CORTEX_L1_INTERACTIVE_STRICT);
        String user = prompt.userText();

        assertThat(user).doesNotContain("PastRecordCounts:");
        assertThat(unknownLine(user)).contains("PastRecordCounts (not retrieved, UNAVAILABLE)");
        assertThat(prompt.executionMetadata().toMetadataMap()).doesNotContainKey("promptPastRecordCounts");
    }

    private static SecurityDecisionPromptSections v20() {
        TieredStrategyProperties properties = new TieredStrategyProperties();
        properties.getPromptBundle().setActive(SecurityDecisionPromptBundles.V20.version());
        return new SecurityDecisionPromptSections(new SecurityEventEnricher(), properties);
    }

    private static SecurityEvent event(String eventId) {
        SecurityEvent event = SecurityEvent.builder()
                .eventId(eventId)
                .timestamp(Instant.parse("2026-10-12T03:17:00Z"))
                .userId("alice")
                .sessionId("session-counts")
                .build();
        event.addMetadata("requestPath", "/api/projects/GB-500/exports");
        event.addMetadata("resourceUrlTemplate", EXPORTS);
        event.addMetadata("httpMethod", "POST");
        return event;
    }

    private static String unknownLine(String user) {
        return user.lines().filter(line -> line.startsWith("Unknown:")).findFirst().orElse("");
    }
}
