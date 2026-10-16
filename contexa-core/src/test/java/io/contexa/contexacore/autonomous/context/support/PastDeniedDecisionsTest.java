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
package io.contexa.contexacore.autonomous.context.support;

import org.junit.jupiter.api.Test;
import org.springframework.ai.document.Document;

import java.time.LocalDateTime;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

/** W5-4: the recent decisions that did not allow, as facts kept for the past records block. */
class PastDeniedDecisionsTest {

    @Test
    void theRecordsKeepTheirTimeActionTargetDecisionAndOutcome() {
        Document challenged = record("1", "2026-10-12T03:17:00", "CHALLENGE", null);
        Document released = record("2", "2026-10-10T22:05:00", "BLOCK", PastDeniedDecisions.RELEASED_BY_ADMINISTRATOR);
        String target = PastRecordRelevance.Subject.ofRecord(challenged.getMetadata(), challenged.getText()).target();

        PastDeniedDecisions decisions = PastDeniedDecisions.of(List.of(challenged, released));

        assertThat(decisions.entries()).containsExactly(
                new PastDeniedDecisions.Entry(LocalDateTime.of(2026, 10, 12, 3, 17), "EXPORT", target, "CHALLENGE",
                        PastDeniedDecisions.NOT_VERIFIED),
                new PastDeniedDecisions.Entry(LocalDateTime.of(2026, 10, 10, 22, 5), "EXPORT", target, "BLOCK",
                        PastDeniedDecisions.RELEASED_BY_ADMINISTRATOR));
        assertThat(target).isNotNull();
        assertThat(PastDeniedDecisions.fromMetadata(decisions.toMetadata())).isEqualTo(decisions);
        assertThat(PastDeniedDecisions.fromMetadata(null).entries()).isEmpty();
    }

    @Test
    void atMostThreeDecisionsAreKept() {
        List<Document> records = List.of(record("1", "2026-10-12T03:00:00", "CHALLENGE", null),
                record("2", "2026-10-11T03:00:00", "CHALLENGE", null), record("3", "2026-10-10T03:00:00", "BLOCK", null),
                record("4", "2026-10-09T03:00:00", "ESCALATE", null));

        assertThat(PastDeniedDecisions.of(records).entries()).hasSize(PastDeniedDecisions.LIMIT)
                .extracting(PastDeniedDecisions.Entry::decidedAction).containsExactly("CHALLENGE", "CHALLENGE", "BLOCK");
    }

    private static Document record(String id, String timestamp, String action, String outcome) {
        Map<String, Object> metadata = new HashMap<>();
        metadata.put("documentType", "BLOCK".equals(action) ? "threat" : "suspicious");
        metadata.put("userId", "alice");
        metadata.put("actionFamily", "EXPORT");
        metadata.put("pathFamily", "/api/projects/{projectKey}/exports");
        metadata.put("requestPath", "/api/projects/GB-500/exports");
        metadata.put("timestamp", timestamp);
        metadata.put("action", action);
        if (outcome != null) {
            metadata.put(PastDeniedDecisions.OUTCOME_KEY, outcome);
        }
        return new Document("00000000-0000-0000-0000-00000000000" + id, "record " + id, metadata);
    }
}
