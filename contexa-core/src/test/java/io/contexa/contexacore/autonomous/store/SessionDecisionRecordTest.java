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
package io.contexa.contexacore.autonomous.store;

import io.contexa.contexacommon.domain.SecurityEvent;
import org.junit.jupiter.api.Test;

import java.time.Instant;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

/** W1-11: one decision of a session is one stored line that reads back as the same record. */
class SessionDecisionRecordTest {

    private static final Instant AT = Instant.parse("2026-09-30T03:17:00Z");

    @Test
    void anEventsDecisionKeepsItsRequestFactsAndReadsBack() {
        SecurityEvent event = SecurityEvent.builder().timestamp(AT).build();
        event.addMetadata("httpMethod", "POST");
        event.addMetadata("requestPath", "/api/projects/GB-500/exports");
        event.addMetadata("queryString", "limit=4831");
        event.addMetadata("actionFamily", "EXPORT");

        SessionDecisionRecord record = SessionDecisionRecord.of(event, "CHALLENGE");

        assertThat(record).isEqualTo(new SessionDecisionRecord(AT, "POST", "/api/projects/GB-500/exports",
                "limit=4831", "EXPORT", "CHALLENGE"));
        assertThat(SessionDecisionRecord.decode(record.encode())).isEqualTo(record);
        assertThat(record.describe())
                .isEqualTo("2026-09-30T03:17:00Z | POST /api/projects/GB-500/exports?limit=4831 | EXPORT | CHALLENGE");
    }

    @Test
    void missingFactsStayMissing() {
        SecurityEvent event = SecurityEvent.builder().timestamp(AT).build();
        event.addMetadata("fullPath", "/api/customers");
        event.addMetadata("currentActionFamily", "READ");

        SessionDecisionRecord record = SessionDecisionRecord.of(event, null);

        assertThat(record).isEqualTo(new SessionDecisionRecord(AT, null, "/api/customers", null, "READ", null));
        assertThat(SessionDecisionRecord.decode(record.encode())).isEqualTo(record);
        assertThat(record.describe()).isEqualTo("2026-09-30T03:17:00Z | /api/customers | READ | -");
    }

    @Test
    void theActionFamilyIsTheOneTheContextGivesTheRequest() {
        SecurityEvent event = SecurityEvent.builder().timestamp(AT).build();
        event.addMetadata("httpMethod", "POST");
        event.addMetadata("requestPath", "/api/projects/GB-500/exports");
        event.addMetadata("protectableMethod", "io.contexa.example.BusinessOperations.exportDocuments");

        // A bulk export sent as a POST is an export, not a write, when no host value names the family.
        assertThat(SessionDecisionRecord.of(event, "CHALLENGE").actionFamily()).isEqualTo("EXPORT");
        assertThat(SessionDecisionRecord.of(SecurityEvent.builder().timestamp(AT).build(), "ALLOW").actionFamily())
                .isNull();
    }

    @Test
    void aFamilyStoredBeforeTheOneVocabularyReadsAsTheFamilyItNames() {
        assertThat(SessionDecisionRecord.decode("2026-09-30T03:17:00Z\tPOST\t/api/projects\t\tCREATE\tALLOW")
                .actionFamily()).isEqualTo("WRITE");
    }

    @Test
    void aSeparatorInsideAFactDoesNotSplitTheLine() {
        SessionDecisionRecord record = new SessionDecisionRecord(AT, "GET", "/api/a\tb", "x=1\ny=2", "READ", "ALLOW");

        assertThat(SessionDecisionRecord.decode(record.encode()))
                .isEqualTo(new SessionDecisionRecord(AT, "GET", "/api/a b", "x=1 y=2", "READ", "ALLOW"));
    }

    @Test
    void anExportKeepsItsTargetAndItemCountAndALineOfTheSixFieldsWrittenBeforeStillReads() {
        SecurityEvent event = SecurityEvent.builder().timestamp(AT).build();
        event.addMetadata("httpMethod", "POST");
        event.addMetadata("requestPath", "/api/projects/GB-500/exports");
        event.addMetadata("protectableResourceUrl", "/api/projects/{projectKey}/exports");
        event.addMetadata("requestItems", 480);
        event.addMetadata("actionFamily", "EXPORT");

        SessionDecisionRecord record = SessionDecisionRecord.of(event, "ALLOW");

        // W2-5: what the session already exported under an approval is counted by target and item count.
        assertThat(record.target()).isEqualTo("projectKey=GB-500");
        assertThat(record.items()).isEqualTo(480);
        assertThat(record.encode().split("	", -1)).hasSize(8);
        assertThat(SessionDecisionRecord.decode(record.encode())).isEqualTo(record);
        assertThat(SessionDecisionRecord.decode("2026-09-30T03:17:00Z	POST	/api/projects/GB-500/exports		EXPORT	ALLOW"))
                .isEqualTo(new SessionDecisionRecord(AT, "POST", "/api/projects/GB-500/exports", null, "EXPORT",
                        "ALLOW"));
    }

    @Test
    void anItemCountThatIsNotAPositiveNumberIsNotKept() {
        SecurityEvent event = SecurityEvent.builder().timestamp(AT).build();
        event.addMetadata("requestPath", "/api/projects/GB-500/exports");
        event.addMetadata("requestItems", "12");
        assertThat(SessionDecisionRecord.of(event, "ALLOW").items()).isEqualTo(12);

        event.addMetadata("requestItems", "many");
        assertThat(SessionDecisionRecord.of(event, "ALLOW").items()).isNull();
        event.addMetadata("requestItems", 0);
        assertThat(SessionDecisionRecord.of(event, "ALLOW").items()).isNull();
        // Without the host's URL template the request has no target to count by.
        assertThat(SessionDecisionRecord.of(event, "ALLOW").target()).isNull();
    }

    @Test
    void theDecisionsAMetadataValueHoldsAreReadAsRecords() {
        SessionDecisionRecord record = new SessionDecisionRecord(AT, "GET", "/api/x", null, "READ", "ALLOW");

        assertThat(SessionDecisionRecord.listOf(List.of(record, "not a record"))).containsExactly(record);
        assertThat(SessionDecisionRecord.listOf("not a list")).isEmpty();
        assertThat(SessionDecisionRecord.listOf(null)).isEmpty();
    }

    @Test
    void aLineThatIsNotARecordReadsAsNothing() {
        assertThat(SessionDecisionRecord.decode(null)).isNull();
        assertThat(SessionDecisionRecord.decode("User accessed /api/x via GET, observed allow")).isNull();
        assertThat(SessionDecisionRecord.decode("yesterday\tGET\t/api/x\t\tREAD\tALLOW")).isNull();
    }
}
