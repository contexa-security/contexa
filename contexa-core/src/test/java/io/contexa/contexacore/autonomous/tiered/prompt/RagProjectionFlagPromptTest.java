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
import io.contexa.contexacore.std.llm.client.StructuredOutputMode;
import org.junit.jupiter.api.Test;
import org.springframework.ai.document.Document;

import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.regex.Pattern;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * BR-C8 (QF-16): the event's {@code ragProjectedToFinalPrompt} says whether past records reached the user prompt the
 * model gets, read from that prompt, and not only that the retrieval found authorized records. The flag is compared
 * with the prompt's own past record lines in every case.
 */
class RagProjectionFlagPromptTest {

    private static final String FLAG = "ragProjectedToFinalPrompt";
    private static final Pattern DICTIONARY_PAST_RECORD_LINE =
            Pattern.compile("^(\\[[A-Z]\\d+\\] )?(New)?PastRecord\\d+: .*$", Pattern.MULTILINE);
    private static final Pattern V19_RAG_DOCUMENT_LINE = Pattern.compile("^RagDocument\\d+: .*$", Pattern.MULTILINE);

    @Test
    void aV20PromptThatDrawsItsRecordsSaysSo() {
        SecurityEvent event = retrievedEvent("flag-1");

        String userText = sections(SecurityDecisionPromptBundles.V20).buildStructuredPrompt(event, null, null,
                List.of(record("rec-1", "2026-10-12T10:00:00"), record("rec-2", "2026-10-11T10:00:00")),
                PromptBudgetProfile.CORTEX_L1_INTERACTIVE_STRICT).userText();

        assertThat(DICTIONARY_PAST_RECORD_LINE.matcher(userText).find()).isTrue();
        assertThat(event.getMetadata().get(FLAG)).isEqualTo(true);
    }

    @Test
    void aV20PromptOverTheListCapStillSaysItDrewRecords() {
        SecurityEvent event = retrievedEvent("flag-2");
        List<Document> records = new ArrayList<>();
        for (int day = 1; day <= 7; day++) {
            records.add(record("rec-" + day, "2026-10-0" + day + "T10:00:00"));
        }

        String userText = sections(SecurityDecisionPromptBundles.V20).buildStructuredPrompt(event, null, null, records,
                PromptBudgetProfile.CORTEX_L1_INTERACTIVE_STRICT).userText();

        assertThat(userText).contains("+2 more");
        assertThat(event.getMetadata().get(FLAG)).isEqualTo(true);
    }

    @Test
    void aPromptWithoutRecordsSaysItDrewNone() {
        SecurityEvent event = retrievedEvent("flag-3");

        String userText = sections(SecurityDecisionPromptBundles.V21).buildStructuredPrompt(event, null, null,
                List.of(), PromptBudgetProfile.CORTEX_L1_INTERACTIVE_STRICT).userText();

        assertThat(DICTIONARY_PAST_RECORD_LINE.matcher(userText).find()).isFalse();
        assertThat(event.getMetadata().get(FLAG)).isEqualTo(false);
    }

    /**
     * The case QF-16 names: the second pass's search found authorized records, so the retrieval wrote the flag true,
     * but the first pass had retrieved its own (none), so this pass draws no record and the first prompt holds none.
     */
    @Test
    void aSecondPassThatDrawsNoRecordSaysSoThoughItsSearchFoundSome() {
        SecurityDecisionPromptSections v21 = sections(SecurityDecisionPromptBundles.V21);
        String firstPrompt = v21.buildStructuredPrompt(retrievedEvent("flag-4a"), null, null, List.of(),
                PromptBudgetProfile.CORTEX_L1_INTERACTIVE_STRICT).userText();
        SecurityEvent event = retrievedEvent("flag-4");
        // What the retrieval of the second pass wrote: authorized records were found.
        event.addMetadata(FLAG, true);

        String userText = v21.buildStructuredPrompt(event, null, null,
                List.of(record("rec-1", "2026-10-12T10:00:00")), PromptBudgetProfile.CORTEX_L2_EXPERT_STRICT,
                StructuredOutputMode.VALIDATED_CONVERTER, null,
                SecurityDecisionPromptSections.SecondPass.of(firstPrompt, "ESCALATE", "ZERO_RESULTS")).userText();

        assertThat(DICTIONARY_PAST_RECORD_LINE.matcher(userText).find()).isFalse();
        assertThat(event.getMetadata().get(FLAG)).isEqualTo(false);
    }

    @Test
    void aSecondPassThatDrawsTheRecordsTheFirstPassMissedSaysSo() {
        SecurityDecisionPromptSections v21 = sections(SecurityDecisionPromptBundles.V21);
        String firstPrompt = v21.buildStructuredPrompt(retrievedEvent("flag-5a"), null, null, List.of(),
                PromptBudgetProfile.CORTEX_L1_INTERACTIVE_STRICT).userText();
        SecurityEvent event = retrievedEvent("flag-5");

        String userText = v21.buildStructuredPrompt(event, null, null,
                List.of(record("rec-1", "2026-10-12T10:00:00")), PromptBudgetProfile.CORTEX_L2_EXPERT_STRICT,
                StructuredOutputMode.VALIDATED_CONVERTER, null,
                SecurityDecisionPromptSections.SecondPass.of(firstPrompt, "ESCALATE", "TIMEOUT")).userText();

        assertThat(userText).contains("NewPastRecord1");
        assertThat(event.getMetadata().get(FLAG)).isEqualTo(true);
    }

    @Test
    void aSecondPassWhoseFirstPromptHoldsRecordsSaysTheyReachedThePrompt() {
        SecurityDecisionPromptSections v21 = sections(SecurityDecisionPromptBundles.V21);
        String firstPrompt = v21.buildStructuredPrompt(retrievedEvent("flag-6a"), null, null,
                List.of(record("rec-1", "2026-10-12T10:00:00")), PromptBudgetProfile.CORTEX_L1_INTERACTIVE_STRICT)
                .userText();
        SecurityEvent event = retrievedEvent("flag-6");

        String userText = v21.buildStructuredPrompt(event, null, null,
                List.of(record("rec-1", "2026-10-12T10:00:00")), PromptBudgetProfile.CORTEX_L2_EXPERT_STRICT,
                StructuredOutputMode.VALIDATED_CONVERTER, null,
                SecurityDecisionPromptSections.SecondPass.of(firstPrompt, "ESCALATE", "AVAILABLE")).userText();

        assertThat(DICTIONARY_PAST_RECORD_LINE.matcher(userText).find()).isTrue();
        assertThat(userText).doesNotContain("NewPastRecord1");
        assertThat(event.getMetadata().get(FLAG)).isEqualTo(true);
    }

    @Test
    void aV19PromptThatDrawsItsDocumentsSaysSo() {
        SecurityEvent event = retrievedEvent("flag-7");

        String userText = sections(SecurityDecisionPromptBundles.DEFAULT).buildStructuredPrompt(event, null, null,
                List.of(record("rec-1", "2026-10-12T10:00:00")), PromptBudgetProfile.CORTEX_L1_INTERACTIVE_STRICT)
                .userText();

        assertThat(V19_RAG_DOCUMENT_LINE.matcher(userText).find()).isTrue();
        assertThat(event.getMetadata().get(FLAG)).isEqualTo(true);
    }

    private static Document record(String id, String timestamp) {
        return new Document(id, "User accessed /api/reports/" + id,
                Map.of("userId", "alice", "documentType", "behavior", "requestPath", "/api/reports/" + id,
                        "pathFamily", "/api/reports/{id}", "eventId", "e-" + id, "timestamp", timestamp,
                        "actionFamily", "READ"));
    }

    private static SecurityEvent retrievedEvent(String eventId) {
        SecurityEvent event = SecurityEvent.builder()
                .eventId(eventId)
                .timestamp(Instant.parse("2026-10-13T10:00:00Z"))
                .userId("alice")
                .sessionId("session-flag")
                .build();
        event.addMetadata("ragSearchExecuted", true);
        event.addMetadata("ragRetrievalState", "AVAILABLE");
        event.addMetadata("requestPath", "/api/reports/r-0");
        return event;
    }

    private static SecurityDecisionPromptSections sections(SecurityDecisionPromptBundles.Bundle bundle) {
        TieredStrategyProperties properties = new TieredStrategyProperties();
        properties.getPromptBundle().setActive(bundle.version());
        return new SecurityDecisionPromptSections(new SecurityEventEnricher(), properties);
    }
}
