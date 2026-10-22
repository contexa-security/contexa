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
package io.contexa.contexacore.autonomous.agent;

import io.contexa.contexacore.autonomous.event.domain.ZeroTrustEventCategory;
import io.contexa.contexacore.autonomous.event.domain.ZeroTrustSpringEvent;
import org.junit.jupiter.api.Test;

import java.time.Duration;
import java.time.Instant;
import java.util.HashMap;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/** A1-6: every agent request reaches the registry, so an agent is known before anyone registers it. */
class AgentRegistryRecorderTest {

    private static final Instant AT = Instant.parse("2026-10-22T05:00:00Z");

    @Test
    void anAgentRequestIsRecordedWithItsTenantKindAndClient() {
        InMemoryAgentRegistry registry = new InMemoryAgentRegistry();
        AgentRegistryRecorder recorder = new AgentRegistryRecorder(registry, Duration.ofMinutes(1));

        recorder.onZeroTrustEvent(event(Map.of("executionSubjectKind", "DELEGATED_AGENT", "agentId", "agent-7",
                "tenantId", "tenant-acme", "delegationTokenClientId", "agent-client")));

        AgentRegistration recorded = registry.find("tenant-acme", "agent-7").orElseThrow();
        assertThat(recorded.lastSubjectKind()).isEqualTo("DELEGATED_AGENT");
        assertThat(recorded.clientId()).isEqualTo("agent-client");
        assertThat(recorded.firstSeenAt()).isEqualTo(AT);
    }

    @Test
    void aPersonsRequestAndAnAgentWithoutAnIdAreNotRecorded() {
        AgentRegistry registry = mock(AgentRegistry.class);
        AgentRegistryRecorder recorder = new AgentRegistryRecorder(registry, Duration.ofMinutes(1));

        recorder.onZeroTrustEvent(event(Map.of("executionSubjectKind", "HUMAN_USER")));
        recorder.onZeroTrustEvent(event(Map.of("executionSubjectKind", "SERVICE_CLIENT", "agentId", "svc")));
        recorder.onZeroTrustEvent(event(Map.of("executionSubjectKind", "AUTONOMOUS_AGENT")));

        verify(registry, never()).observe(any());
    }

    @Test
    void theSameAgentIsWrittenOnceAnInterval() {
        AgentRegistry registry = mock(AgentRegistry.class);
        AgentRegistryRecorder recorder = new AgentRegistryRecorder(registry, Duration.ofMinutes(1));
        Map<String, Object> payload = Map.of("executionSubjectKind", "AUTONOMOUS_AGENT", "agentId", "agent-sp-1");

        recorder.onZeroTrustEvent(event(payload));
        recorder.onZeroTrustEvent(event(payload));
        recorder.onZeroTrustEvent(event(Map.of("executionSubjectKind", "AUTONOMOUS_AGENT", "agentId", "agent-sp-2")));

        verify(registry, times(2)).observe(any());
    }

    @Test
    void aFailingRegistryDoesNotFailTheRequest() {
        AgentRegistry registry = mock(AgentRegistry.class);
        when(registry.observe(any())).thenThrow(new IllegalStateException("database unavailable"));
        AgentRegistryRecorder recorder = new AgentRegistryRecorder(registry, Duration.ofMinutes(1));
        Map<String, Object> payload = Map.of("executionSubjectKind", "AUTONOMOUS_AGENT", "agentId", "agent-sp-1");

        assertThatCode(() -> recorder.onZeroTrustEvent(event(payload))).doesNotThrowAnyException();
        // A failed write is not counted as written; the next request tries again.
        recorder.onZeroTrustEvent(event(payload));
        verify(registry, times(2)).observe(any());
    }

    private static ZeroTrustSpringEvent event(Map<String, Object> payload) {
        return ZeroTrustSpringEvent.builder(AgentRegistryRecorderTest.class)
                .category(ZeroTrustEventCategory.AUTHORIZATION)
                .eventType(ZeroTrustSpringEvent.TYPE_AUTHORIZATION_METHOD)
                .userId("alice")
                .eventTimestamp(AT)
                .payload(new HashMap<>(payload))
                .build();
    }
}
