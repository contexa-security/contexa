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
package io.contexa.contexacore.autonomous.context.enricher;

import io.contexa.contexacommon.domain.SecurityEvent;
import io.contexa.contexacommon.security.subject.SubjectKind;
import io.contexa.contexacore.autonomous.context.CanonicalSecurityContext;
import org.junit.jupiter.api.Test;

import java.util.HashMap;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

/** docs/agent A2-12: an agent's request is judged with the records of the person who answers for it. */
class RecordsHolderTest {

    @Test
    void aPersonsRequestIsJudgedWithThePersonsRecords() {
        assertThat(RecordsHolder.of(event("alice", Map.of()))).isEqualTo(new RecordsHolder("alice", RecordsHolder.SUBJECT));
    }

    @Test
    void anAgentOnItsOwnIsJudgedWithItsSponsorsRecords() {
        RecordsHolder holder = RecordsHolder.of(event("report-agent-client", Map.of(
                "executionSubjectKind", SubjectKind.AUTONOMOUS_AGENT.name(), "agentAccountableId", "bob")));

        assertThat(holder).isEqualTo(new RecordsHolder("bob", RecordsHolder.SPONSOR));
    }

    @Test
    void aDelegatedAgentIsJudgedWithTheDelegatorsRecords() {
        // The exchanged token's subject is the person: the person's own records.
        assertThat(RecordsHolder.of(event("alice", Map.of("executionSubjectKind", SubjectKind.DELEGATED_AGENT.name(),
                "agentAccountableId", "alice", "delegatorId", "alice"))))
                .isEqualTo(new RecordsHolder("alice", RecordsHolder.SUBJECT));
        // An agent's own account acting under a delegation of record: the delegator's records.
        assertThat(RecordsHolder.of(event("report-agent", Map.of("executionSubjectKind",
                SubjectKind.DELEGATED_AGENT.name(), "agentAccountableId", "alice", "delegatorId", "alice"))))
                .isEqualTo(new RecordsHolder("alice", RecordsHolder.DELEGATOR));
    }

    @Test
    void anAgentWithNoOneAccountableKeepsItsOwnIdAndThePersonsKindIsNotReadAsAnAgent() {
        assertThat(RecordsHolder.of(event("report-agent", Map.of("executionSubjectKind",
                SubjectKind.AUTONOMOUS_AGENT.name())))).isEqualTo(new RecordsHolder("report-agent", RecordsHolder.SUBJECT));
        assertThat(RecordsHolder.of(event("alice", Map.of("agentAccountableId", "bob"))))
                .isEqualTo(new RecordsHolder("alice", RecordsHolder.SUBJECT));
        assertThat(RecordsHolder.of(null)).isNull();
    }

    @Test
    void theHolderIsStatedOnTheCompanyFacts() {
        CanonicalSecurityContext context = new CanonicalSecurityContext();

        new RecordsHolder("bob", RecordsHolder.SPONSOR).stateOn(context);

        assertThat(context.getFrictionProfile().getRecordsHolderId()).isEqualTo("bob");
        assertThat(context.getFrictionProfile().getRecordsHolderRelation()).isEqualTo(RecordsHolder.SPONSOR);
    }

    private static SecurityEvent event(String userId, Map<String, Object> metadata) {
        SecurityEvent event = new SecurityEvent();
        event.setUserId(userId);
        event.setMetadata(new HashMap<>(metadata));
        return event;
    }
}
