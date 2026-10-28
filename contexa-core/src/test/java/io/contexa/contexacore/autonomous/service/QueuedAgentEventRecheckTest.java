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
package io.contexa.contexacore.autonomous.service;

import io.contexa.contexacommon.domain.SecurityEvent;
import io.contexa.contexacommon.enums.ZeroTrustAction;
import io.contexa.contexacore.autonomous.agent.AgentAllowReuse;
import io.contexa.contexacore.autonomous.context.support.ActionFamily;
import io.contexa.contexacore.autonomous.repository.ZeroTrustActionRepository;
import org.junit.jupiter.api.Test;

import java.util.LinkedHashMap;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * RL-12 (QD): an agent's event that waited its turn in the queue is read against the stored state again when the turn
 * comes. A restriction stored meanwhile, or an ALLOW anchor that now reaches it, answers it without a new analysis.
 */
class QueuedAgentEventRecheckTest {

    private static final String SUBJECT = "agent-key";
    private static final String CONTEXT = "ctx-hash";

    private final ZeroTrustActionRepository repository = mock(ZeroTrustActionRepository.class);
    private final UnanalysedRequestRecorder recorder = mock(UnanalysedRequestRecorder.class);
    private final AgentAllowReuse reuse = new AgentAllowReuse(10, 3, 1, null);
    private final QueuedAgentEventRecheck recheck = new QueuedAgentEventRecheck(repository, reuse, recorder);

    private static SecurityEvent event(String kind, String path, String importance) {
        Map<String, Object> metadata = new LinkedHashMap<>();
        metadata.put("requestPath", path);
        metadata.put("httpMethod", "GET");
        metadata.put("executionSubjectKind", kind);
        metadata.put("contextBindingHash", CONTEXT);
        if (importance != null) {
            metadata.put("resourceImportance", importance);
        }
        return SecurityEvent.builder().eventId("event-" + path).userId(SUBJECT).sessionId("session-1")
                .metadata(metadata).build();
    }

    // QD-01
    @Test
    void aRestrictionStoredBeforeItsTurnAnswersTheEventWithoutAnAnalysis() {
        when(repository.getCurrentAction(SUBJECT, CONTEXT)).thenReturn(ZeroTrustAction.BLOCK);
        SecurityEvent event = event("DELEGATED_AGENT", "/api/projects/GB-500/exports", "SENSITIVE");

        assertThat(recheck.answeredWithoutAnalysis(event)).isTrue();

        verify(recorder).recordQueued(event, ZeroTrustAction.BLOCK);
    }

    @Test
    void everyRestrictionAnswersAndAPendingOrExpiredStateDoesNot() {
        for (ZeroTrustAction restriction : new ZeroTrustAction[] {ZeroTrustAction.BLOCK, ZeroTrustAction.CHALLENGE,
                ZeroTrustAction.ESCALATE}) {
            when(repository.getCurrentAction(SUBJECT, CONTEXT)).thenReturn(restriction);
            assertThat(recheck.answeredWithoutAnalysis(event("AUTONOMOUS_AGENT", "/api/docs/1", null)))
                    .as(restriction.name()).isTrue();
        }
        when(repository.getCurrentAction(SUBJECT, CONTEXT)).thenReturn(ZeroTrustAction.PENDING_ANALYSIS);
        assertThat(recheck.answeredWithoutAnalysis(event("AUTONOMOUS_AGENT", "/api/docs/1", null))).isFalse();
    }

    // QD-02
    @Test
    void anAllowAnchorThatReachesTheEventNowAnswersItWithoutAnAnalysis() {
        when(repository.getCurrentAction(SUBJECT, CONTEXT)).thenReturn(ZeroTrustAction.ALLOW);
        reuse.decided(SUBJECT, CONTEXT, ActionFamily.READ, "/api/docs/1", false);
        SecurityEvent event = event("DELEGATED_AGENT", "/api/docs/2", "NON_SENSITIVE");

        assertThat(recheck.answeredWithoutAnalysis(event)).isTrue();

        verify(recorder).recordQueued(event, ZeroTrustAction.ALLOW);
    }

    // QD-03
    @Test
    void anEventNothingAnswersIsAnalysed() {
        when(repository.getCurrentAction(SUBJECT, CONTEXT)).thenReturn(ZeroTrustAction.ALLOW);
        reuse.decided(SUBJECT, CONTEXT, ActionFamily.READ, "/api/docs/1", false);

        // a sensitive record is not answered by the ALLOW of a general resource
        SecurityEvent sensitive = event("DELEGATED_AGENT", "/api/customers/CUS-1", "SENSITIVE");
        assertThat(recheck.answeredWithoutAnalysis(sensitive)).isFalse();
        // nor is another operation
        Map<String, Object> exportMetadata = new LinkedHashMap<>(event("DELEGATED_AGENT", "/api/projects/1/exports", null)
                .getMetadata());
        exportMetadata.put("httpMethod", "POST");
        SecurityEvent export = SecurityEvent.builder().eventId("export").userId(SUBJECT).sessionId("session-1")
                .metadata(exportMetadata).build();
        assertThat(recheck.answeredWithoutAnalysis(export)).isFalse();

        verify(recorder, never()).recordQueued(any(SecurityEvent.class), any(ZeroTrustAction.class));
    }

    @Test
    void aPersonsEventIsNeverAnsweredHere() {
        when(repository.getCurrentAction(any(), any())).thenReturn(ZeroTrustAction.BLOCK);

        assertThat(recheck.answeredWithoutAnalysis(event("HUMAN_USER", "/api/docs/1", null))).isFalse();

        verify(repository, never()).getCurrentAction(eq(SUBJECT), any());
    }

    @Test
    void anUnreadableStateLeavesTheEventToItsAnalysis() {
        when(repository.getCurrentAction(SUBJECT, CONTEXT)).thenThrow(new IllegalStateException("store down"));

        assertThat(recheck.answeredWithoutAnalysis(event("DELEGATED_AGENT", "/api/docs/1", null))).isFalse();
    }

    @Test
    void anEventWithoutAContextOrAUserIsAnalysed() {
        SecurityEvent noUser = SecurityEvent.builder().eventId("e").metadata(Map.of("executionSubjectKind",
                "DELEGATED_AGENT")).build();

        assertThat(recheck.answeredWithoutAnalysis(noUser)).isFalse();
        assertThat(recheck.answeredWithoutAnalysis(null)).isFalse();
    }
}
