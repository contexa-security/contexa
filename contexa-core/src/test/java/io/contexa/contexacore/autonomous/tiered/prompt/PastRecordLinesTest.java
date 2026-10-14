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

import io.contexa.contexacore.autonomous.context.prompt.PromptDictionaryEntry;
import io.contexa.contexacore.autonomous.context.prompt.PromptListItem;
import io.contexa.contexacore.autonomous.context.prompt.PromptListOrder;
import io.contexa.contexacore.autonomous.context.support.PastRecordRelevance;
import org.junit.jupiter.api.Test;
import org.springframework.ai.document.Document;

import java.time.LocalDateTime;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * W3-3: one past record is one line of the dictionary 7 form, the same facts are one line with their count, and the
 * audit metadata stays in the sealed record only.
 */
class PastRecordLinesTest {

    private static final PastRecordRelevance.Subject REQUEST = PastRecordRelevance.Subject.ofRequest(
            Map.of("requestPath", "/api/projects/GB-500/exports", "resourceUrlTemplate", "/api/projects/{projectKey}/exports"),
            "POST /api/projects/GB-500/exports");
    private static final PromptDictionaryEntry PAST_RECORD = SecurityDecisionPromptDictionary.ENTRIES.stream()
            .filter(entry -> entry.name().equals("PastRecord{i}")).findFirst().orElseThrow();

    @Test
    void aRecordIsOneLineOfTheDictionaryForm() {
        List<PromptListItem> items = PastRecordLines.items(List.of(export("e1", "2026-09-25T10:30", 0.83)), REQUEST);

        assertThat(items).hasSize(1);
        assertThat(items.get(0).text()).isEqualTo("09-25 Fri 10:30 / EXPORT / /api/projects/{projectKey}/exports"
                + " / projectKey=PLM-OPS / 23 items / class NORMAL / 10.40.12.0/24 zone CORPORATE / Chrome/140 on WINDOWS"
                + " / PASSWORD login / allowed / same target: no"
                + " / authorized as ALLOWED_USER_SCOPE (scope USER, tenant bound, purpose match)");
        assertThat(PAST_RECORD.acceptsValue(items.get(0).text())).isTrue();
        assertThat(items.get(0).sameTarget()).isFalse();
        // W3-18: a similarity decides nothing and is not shown; a tie in the order goes to the stored ID.
        assertThat(items.get(0).id()).isEqualTo("doc-e1");
    }

    @Test
    void aValueTheRecordDoesNotHoldIsSaidToBeNotRecorded() {
        Map<String, Object> metadata = new LinkedHashMap<>();
        metadata.put("documentType", "behavior");
        metadata.put("eventId", "old");
        metadata.put("timestamp", "2026-09-24T09:05");
        metadata.put("actionFamily", "READ");
        metadata.put("requestPath", "/api/projects/GB-500/documents");
        metadata.put("action", "ALLOW");
        Document old = new Document("old", "User accessed /api/projects/GB-500/documents", metadata);

        String line = PastRecordLines.items(List.of(old), REQUEST).get(0).text();

        // Without a stored template the record reads its path generalized, as the relevance does (one reading): no
        // target can be bound and whether it is the request's target is not known.
        assertThat(line).isEqualTo("09-24 Thu 09:05 / READ / /api/projects/{id}/documents/* / no target"
                + " / items not recorded / class not recorded / network not recorded / device not recorded"
                + " / login not recorded / allowed / same target: unknown / authorized as not recorded");
        assertThat(PAST_RECORD.acceptsValue(line)).isTrue();
    }

    @Test
    void recordsOfTheSameFactsAreOneLineWithTheirCountAndTheLatestTime() {
        List<PromptListItem> items = PastRecordLines.items(List.of(
                export("e1", "2026-09-24T10:30", 0.80),
                export("e2", "2026-09-25T11:00", 0.70),
                export("e3", "2026-09-22T09:00", 0.90)), REQUEST);

        assertThat(items).hasSize(1);
        assertThat(items.get(0).text()).startsWith("09-25 Fri 11:00 ×3 / EXPORT / ").doesNotContain("similarity");
        assertThat(items.get(0).id()).isEqualTo("doc-e2");
    }

    /** W3-13 (dictionary 1.5): the latest time of a line says how long before the request it was. */
    @Test
    void theLatestTimeOfALineSaysHowLongBeforeTheRequestItWas() {
        LocalDateTime request = LocalDateTime.parse("2026-09-30T03:17");

        List<PromptListItem> items = PastRecordLines.items(List.of(
                export("e1", "2026-09-24T10:30", 0.80),
                export("e2", "2026-09-25T11:00", 0.70)), REQUEST, request);
        String recent = PastRecordLines.items(List.of(export("e1", "2026-09-29T13:52", 0.83)), REQUEST, request)
                .get(0).text();

        assertThat(items.get(0).text()).startsWith("09-25 Fri 11:00 (4 days before this request) ×2 / EXPORT / ");
        assertThat(recent).startsWith("09-29 Tue 13:52 (13 h before this request) / EXPORT / ");
        assertThat(PAST_RECORD.acceptsValue(recent)).isTrue();
    }

    /** W3-18: lines of the same time are ordered by the stored ID of their record, whatever the similarity. */
    @Test
    void linesOfTheSameTimeGoByTheStoredIdNotBySimilarity() {
        Map<String, Object> other = new LinkedHashMap<>(export("e5", "2026-09-25T10:30", 0.9).getMetadata());
        other.put("requestItems", 7);
        List<PromptListItem> items = PastRecordLines.items(List.of(
                Document.builder().id("doc-b").text("b").metadata(export("e4", "2026-09-25T10:30", 0.9).getMetadata())
                        .score(0.9).build(),
                Document.builder().id("doc-a").text("a").metadata(other).score(0.1).build()), REQUEST);

        assertThat(PromptListOrder.PAST_RECORD.sort(items)).extracting(PromptListItem::id).containsExactly("doc-a", "doc-b");
    }

    @Test
    void theLineLeavesTheAuditMetadataAndTheDocumentTextToTheSealedRecord() {
        String line = PastRecordLines.items(List.of(export("e1", "2026-09-25T10:30", 0.83)), REQUEST).get(0).text();

        assertThat(line).doesNotContain("artifact", "retrievalPolicy", "guard", "prov", "user=", "10.40.12.10",
                "User accessed");
    }

    @Test
    void aRecordOfTheRequestsTargetSaysSo() {
        Map<String, Object> metadata = new LinkedHashMap<>(export("e9", "2026-09-25T10:30", 0.5).getMetadata());
        metadata.put("requestPath", "/api/projects/GB-500/exports");

        PromptListItem item = PastRecordLines.items(List.of(new Document("e9", "same target", metadata)), REQUEST).get(0);

        assertThat(item.text()).contains(" / projectKey=GB-500 / ", " / same target: yes / ");
        assertThat(item.sameTarget()).isTrue();
    }

    private static Document export(String eventId, String timestamp, double score) {
        Map<String, Object> metadata = new LinkedHashMap<>();
        metadata.put("documentType", "behavior");
        metadata.put("eventId", eventId);
        metadata.put("artifactId", eventId);
        metadata.put("userId", "adm-a");
        metadata.put("sourceIp", "10.40.12.10");
        metadata.put("timestamp", timestamp);
        metadata.put("actionFamily", "EXPORT");
        metadata.put("requestPath", "/api/projects/PLM-OPS/exports");
        metadata.put("pathFamily", "/api/projects/{projectKey}/exports");
        metadata.put("requestItems", 23);
        metadata.put("resourceFamily", "NORMAL");
        metadata.put("ipBand", "10.40.12.0/24");
        metadata.put("networkZone", "CORPORATE");
        metadata.put("userAgentBrowser", "Chrome/140");
        metadata.put("userAgentOS", "WINDOWS");
        metadata.put("authenticationType", "PASSWORD");
        metadata.put("action", "ALLOW");
        metadata.put("authorizationDecision", "ALLOWED_USER_SCOPE");
        metadata.put("accessScope", "USER");
        metadata.put("tenantBound", true);
        metadata.put("purposeMatch", true);
        metadata.put("retrievalPolicySummary", "purpose=security_investigation");
        metadata.put("promptSafetyDecision", "ALLOWED_PROMPT_SAFE");
        metadata.put("provenanceSummary", "Security decision memory from runtime event");
        return Document.builder().id("doc-" + eventId).text("User accessed /api/projects/PLM-OPS/exports from 10.40.12.10")
                .metadata(metadata).score(score).build();
    }
}
