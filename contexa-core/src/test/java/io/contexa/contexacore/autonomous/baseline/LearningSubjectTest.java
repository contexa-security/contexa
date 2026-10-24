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
package io.contexa.contexacore.autonomous.baseline;

import io.contexa.contexacommon.domain.SecurityEvent;
import io.contexa.contexacore.autonomous.context.CanonicalSecurityContext;
import io.contexa.contexacore.autonomous.context.decision.LearningPromotionPolicy;
import io.contexa.contexacore.autonomous.context.enricher.RecordedDelegationContextProvider;
import org.junit.jupiter.api.Test;

import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

/** docs/agent A3-1: whose learning a request belongs to. */
class LearningSubjectTest {

    @Test
    void aPersonsRequestKeepsThePersonsKey() {
        LearningSubject person = LearningSubject.of(event("alice", Map.of("tenantId", "t-1",
                "executionSubjectKind", "HUMAN_USER")));

        assertThat(person.key()).isEqualTo("alice");
        assertThat(person.agent()).isFalse();
        assertThat(person.tenantId()).isEqualTo("t-1");
        assertThat(person.subjectKind()).isEqualTo("HUMAN_USER");
        // An agent id a person's request carries is no agent of the person's.
        assertThat(LearningSubject.of(event("alice", Map.of("agentId", "report-agent"))).key()).isEqualTo("alice");
    }

    @Test
    void anAgentsRequestHasAKeyOfItsOwn() {
        LearningSubject delegated = LearningSubject.of(event("alice", Map.of("executionSubjectKind", "DELEGATED_AGENT",
                "agentId", "report-agent", "delegationId", "DLG-1")));
        LearningSubject alone = LearningSubject.of(event("report-client", Map.of("executionSubjectKind",
                "AUTONOMOUS_AGENT", "agentId", "report-agent")));

        assertThat(delegated.key()).isEqualTo("alice::agent::report-agent");
        assertThat(delegated.delegationId()).isEqualTo("DLG-1");
        assertThat(alone.key()).isEqualTo("report-client::agent::report-agent");
        assertThat(alone.delegationId()).isNull();
        assertThat(LearningSubject.agentKey("alice", "report-agent")).isEqualTo(delegated.key());
    }

    @Test
    void theDelegationOfRecordNamesTheDelegationWhenTheRequestDoesNot() {
        Map<String, Object> attributes = new LinkedHashMap<>();
        attributes.put(RecordedDelegationContextProvider.RECORD_ID_ATTRIBUTE, "DLG-9");
        CanonicalSecurityContext decided = CanonicalSecurityContext.builder().attributes(attributes).build();
        Map<String, Object> metadata = new HashMap<>(Map.of("executionSubjectKind", "DELEGATED_AGENT",
                "agentId", "report-agent"));
        metadata.put(LearningPromotionPolicy.DECIDED_CONTEXT, decided);

        assertThat(LearningSubject.of(event("alice", metadata)).delegationId()).isEqualTo("DLG-9");
        assertThat(LearningSubject.of(event(" ", Map.of()))).isNull();
        assertThat(LearningSubject.of(null)).isNull();
    }

    private static SecurityEvent event(String userId, Map<String, Object> metadata) {
        SecurityEvent event = new SecurityEvent();
        event.setUserId(userId);
        event.setMetadata(new HashMap<>(metadata));
        return event;
    }
}
