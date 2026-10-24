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
package io.contexa.contexacore.autonomous.repository;

import io.contexa.contexacommon.domain.SecurityEvent;
import io.contexa.contexacommon.security.bridge.stamp.DelegationStamp;
import io.contexa.contexacommon.security.subject.SubjectKind;
import org.junit.jupiter.api.Test;

import java.time.Instant;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

/** docs/agent A5-1: whose decision a request reads and writes. */
class ZeroTrustSubjectTest {

    @Test
    void aPersonAServiceClientAndAnAgentOnItsOwnKeepTheirUserId() {
        assertThat(ZeroTrustSubject.of("alice", (DelegationStamp) null).storageKey()).isEqualTo("alice");
        assertThat(ZeroTrustSubject.of(event("alice", Map.of("executionSubjectKind", "HUMAN_USER"))).storageKey())
                .isEqualTo("alice");
        assertThat(ZeroTrustSubject.of(event("batch-client", Map.of("executionSubjectKind", "SERVICE_CLIENT")))
                .storageKey()).isEqualTo("batch-client");
        ZeroTrustSubject alone = ZeroTrustSubject.of("report-client", stamp(false, "report-agent", null));
        assertThat(alone.kind()).isEqualTo(SubjectKind.AUTONOMOUS_AGENT);
        assertThat(alone.storageKey()).isEqualTo("report-client");
        assertThat(ZeroTrustSubject.of(event("report-client", Map.of("executionSubjectKind", "AUTONOMOUS_AGENT",
                "agentId", "report-agent"))).storageKey()).isEqualTo("report-client");
    }

    @Test
    void anAgentActingForAPersonIsKeyedApartFromThePersonTheSameWayOnTheRequestAndOnTheEvent() {
        ZeroTrustSubject onRequest = ZeroTrustSubject.of("alice", stamp(true, "report-agent", "DLG-7"));
        ZeroTrustSubject onEvent = ZeroTrustSubject.of(event("alice", Map.of("executionSubjectKind", "DELEGATED_AGENT",
                "agentId", "report-agent", "delegationId", "DLG-7", "tenantId", "t-1")));

        assertThat(onRequest.delegatedAgent()).isTrue();
        assertThat(onRequest.storageKey()).isEqualTo("alice::agent::report-agent");
        assertThat(onEvent.storageKey()).isEqualTo(onRequest.storageKey());
        assertThat(onEvent.delegationId()).isEqualTo("DLG-7");
        assertThat(onEvent.tenantId()).isEqualTo("t-1");
        // An authorization event's payload names the subject the same way.
        assertThat(ZeroTrustSubject.ofFacts("alice", Map.of("executionSubjectKind", "DELEGATED_AGENT",
                "agentId", "report-agent")).storageKey()).isEqualTo(onRequest.storageKey());
        assertThat(ZeroTrustSubject.ofFacts("alice", Map.of("executionSubjectKind", "HUMAN_USER",
                "agentId", "report-agent")).storageKey()).as("a person's request names no agent").isEqualTo("alice");
        // The delegation is not keyed: a token that names none reads the same decisions.
        assertThat(ZeroTrustSubject.of("alice", stamp(true, "report-agent", null)).storageKey())
                .isEqualTo(onRequest.storageKey());
    }

    @Test
    void aDelegationThatNamesNoAgentAndNoUserAreNoAgentKey() {
        assertThat(ZeroTrustSubject.of("alice", stamp(true, null, "DLG-7")).storageKey()).isEqualTo("alice");
        assertThat(ZeroTrustSubject.of(" ", (DelegationStamp) null)).isNull();
        assertThat(ZeroTrustSubject.of((SecurityEvent) null)).isNull();
    }

    private static DelegationStamp stamp(boolean delegated, String agentId, String delegationId) {
        return new DelegationStamp("alice", agentId, delegated, null, null, null, List.of(), List.of(), null, null,
                null, Instant.parse("2026-10-24T12:00:00Z"),
                delegationId != null ? Map.of("delegationId", delegationId) : Map.of());
    }

    private static SecurityEvent event(String userId, Map<String, Object> metadata) {
        SecurityEvent event = new SecurityEvent();
        event.setUserId(userId);
        event.setMetadata(new HashMap<>(metadata));
        return event;
    }
}
