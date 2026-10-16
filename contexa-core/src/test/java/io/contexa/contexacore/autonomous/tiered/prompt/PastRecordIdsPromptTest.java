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
import io.contexa.contexacore.autonomous.tiered.util.SecurityEventEnricher;
import io.contexa.contexacore.properties.TieredStrategyProperties;
import io.contexa.contexacore.std.components.prompt.PromptBudgetProfile;
import io.contexa.contexacore.std.components.prompt.PromptExecutionMetadata;
import org.junit.jupiter.api.Test;
import org.springframework.ai.document.Document;

import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * W6-12 (P6-CHANGE-9): the render names the stored IDs of the past records it drew, one per drawn line, so the seal
 * keeps which records the model was given; a record past the list cap is not drawn and not named.
 */
class PastRecordIdsPromptTest {

    @Test
    void theDrawnPastRecordsAreNamedByTheirStoredIds() {
        SecurityDecisionStandardPromptTemplate.StructuredPrompt prompt = v20().buildStructuredPrompt(event("ids-1"),
                null, null, List.of(record("rec-1", "2026-10-12T10:00:00"), record("rec-2", "2026-10-11T10:00:00")),
                PromptBudgetProfile.CORTEX_L1_INTERACTIVE_STRICT);

        assertThat(prompt.userText()).contains("PastRecord1: ").contains("PastRecord2: ");
        assertThat(ids(prompt)).containsExactlyInAnyOrder("rec-1", "rec-2");
    }

    @Test
    void aRecordPastTheListCapIsNotNamed() {
        List<Document> records = new ArrayList<>();
        for (int day = 1; day <= 7; day++) {
            records.add(record("rec-" + day, "2026-10-0" + day + "T10:00:00"));
        }

        SecurityDecisionStandardPromptTemplate.StructuredPrompt prompt = v20().buildStructuredPrompt(event("ids-2"),
                null, null, records, PromptBudgetProfile.CORTEX_L1_INTERACTIVE_STRICT);

        assertThat(prompt.userText()).contains("+2 more");
        assertThat(ids(prompt)).hasSize(5);
    }

    @Test
    void withoutPastRecordsNoIdIsNamed() {
        SecurityDecisionStandardPromptTemplate.StructuredPrompt prompt = v20().buildStructuredPrompt(event("ids-3"),
                null, null, List.of(), PromptBudgetProfile.CORTEX_L1_INTERACTIVE_STRICT);

        assertThat(ids(prompt)).isEmpty();
    }

    private static List<Object> ids(SecurityDecisionStandardPromptTemplate.StructuredPrompt prompt) {
        Object ids = prompt.executionMetadata().toMetadataMap().get(PromptExecutionMetadata.PROMPT_PAST_RECORD_IDS);
        return ids instanceof List<?> list ? List.copyOf(list) : List.of();
    }

    private static Document record(String id, String timestamp) {
        return new Document(id, "User accessed /api/reports/" + id,
                Map.of("userId", "alice", "documentType", "behavior", "requestPath", "/api/reports/" + id,
                        "pathFamily", "/api/reports/{id}", "eventId", "e-" + id, "timestamp", timestamp,
                        "actionFamily", "READ"));
    }

    private static SecurityEvent event(String eventId) {
        SecurityEvent event = SecurityEvent.builder()
                .eventId(eventId)
                .timestamp(Instant.parse("2026-10-13T10:00:00Z"))
                .userId("alice")
                .sessionId("session-ids")
                .build();
        event.addMetadata("ragSearchExecuted", true);
        event.addMetadata("ragRetrievalState", "AVAILABLE");
        event.addMetadata("requestPath", "/api/reports/r-0");
        return event;
    }

    private static SecurityDecisionPromptSections v20() {
        TieredStrategyProperties properties = new TieredStrategyProperties();
        properties.getPromptBundle().setActive(SecurityDecisionPromptBundles.V20.version());
        return new SecurityDecisionPromptSections(new SecurityEventEnricher(), properties);
    }
}
