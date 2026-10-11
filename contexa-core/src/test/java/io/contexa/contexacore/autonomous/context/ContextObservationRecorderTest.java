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
package io.contexa.contexacore.autonomous.context;

import io.contexa.contexacommon.domain.SecurityEvent;
import io.contexa.contexacore.autonomous.context.collector.ContextObservationRecorder;
import io.contexa.contexacore.autonomous.store.InMemorySecurityContextDataStore;
import io.contexa.contexacore.autonomous.store.SessionDecisionRecord;
import org.junit.jupiter.api.Test;

import java.time.Instant;
import java.util.ArrayList;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

/** W2-7: what the collectors observed about a request is recorded once, under the request's final outcome. */
class ContextObservationRecorderTest {

    @Test
    void aRequestIsKnownByItsRequestIdElseItsCorrelationIdElseItsEventId() {
        SecurityEvent event = SecurityEvent.builder().eventId("event-1").build();
        assertThat(ContextObservationRecorder.requestKey(event)).isEqualTo("event-1");
        event.addMetadata("correlationId", "correlation-1");
        assertThat(ContextObservationRecorder.requestKey(event)).isEqualTo("correlation-1");
        event.addMetadata("requestId", "request-1");
        assertThat(ContextObservationRecorder.requestKey(event)).isEqualTo("request-1");
        assertThat(ContextObservationRecorder.requestKey(null)).isNull();
        // A protected method's call is a request of its own within the HTTP request (P2 correction 4).
        event.addMetadata("resourceId", "ops#readDocument");
        assertThat(ContextObservationRecorder.requestKey(event)).isEqualTo("request-1|ops#readDocument");
        event.addMetadata("protectableResourceId", "ops#exportDocuments");
        assertThat(ContextObservationRecorder.requestKey(event)).isEqualTo("request-1|ops#exportDocuments");
    }

    @Test
    void eachProtectedCallOfOneHttpRequestIsStagedAndRecordedOnItsOwn() {
        InMemorySecurityContextDataStore store = new InMemorySecurityContextDataStore();
        ContextObservationRecorder recorder = new ContextObservationRecorder(store);
        SecurityEvent read = event("request-1");
        read.addMetadata("protectableResourceId", "ops#readDocument");
        SecurityEvent export = event("request-1");
        export.addMetadata("protectableResourceId", "ops#exportDocuments");
        List<String> recorded = new ArrayList<>();

        recorder.stage(read, ContextObservationRecorder.WORK_PROFILE, "read snapshot", commit -> recorded.add("read "
                + commit.outcome()));
        recorder.commit(read, "ALLOW", true);
        // The second call of the request is not answered with the first call's snapshot, and is recorded itself.
        assertThat(recorder.resolved(export, ContextObservationRecorder.WORK_PROFILE, String.class)).isEmpty();
        recorder.stage(export, ContextObservationRecorder.WORK_PROFILE, "export snapshot", commit -> recorded.add(
                "export " + commit.outcome()));
        recorder.commit(export, "CHALLENGE", true);

        assertThat(recorded).containsExactly("read ALLOW", "export CHALLENGE");
        assertThat(recorder.resolved(export, ContextObservationRecorder.WORK_PROFILE, String.class))
                .contains("export snapshot");
        assertThat(store.getRecentSessionDecisions("session-1", 10)).hasSize(2);
    }

    @Test
    void theStagedSnapshotAnswersASecondResolutionAndTheObservationsAreRecordedOnce() {
        InMemorySecurityContextDataStore store = new InMemorySecurityContextDataStore();
        ContextObservationRecorder recorder = new ContextObservationRecorder(store);
        SecurityEvent event = event("request-1");
        List<String> recorded = new ArrayList<>();

        recorder.stage(event, ContextObservationRecorder.WORK_PROFILE, "snapshot",
                commit -> recorded.add(commit.outcome() + " learnable=" + commit.learnable()));

        assertThat(recorder.resolved(event, ContextObservationRecorder.WORK_PROFILE, String.class)).contains("snapshot");
        assertThat(recorder.resolved(event, ContextObservationRecorder.ROLE_SCOPE, String.class)).isEmpty();
        assertThat(recorded).isEmpty();
        assertThat(recorder.committed(event)).isFalse();

        recorder.commit(event, "ALLOW", true);
        recorder.commit(event, "BLOCK", true);
        // Staging after the commit (a resolution after the decision) changes nothing and records nothing.
        recorder.stage(event, ContextObservationRecorder.WORK_PROFILE, "later", commit -> recorded.add("later"));

        assertThat(recorded).containsExactly("ALLOW learnable=true");
        assertThat(recorder.committed(event)).isTrue();
        assertThat(recorder.resolved(event, ContextObservationRecorder.WORK_PROFILE, String.class)).contains("snapshot");
        assertThat(store.getRecentSessionDecisions("session-1", 10)).singleElement()
                .satisfies(line -> assertThat(SessionDecisionRecord.decode(line).outcome()).isEqualTo("ALLOW"));
    }

    @Test
    void onlyAnEnforcedAllowIsLearnableAndNoDecisionMeansNoDecisionLine() {
        InMemorySecurityContextDataStore store = new InMemorySecurityContextDataStore();
        ContextObservationRecorder recorder = new ContextObservationRecorder(store);
        List<String> recorded = new ArrayList<>();

        for (String[] outcome : new String[][]{{"request-allow-shadow", "ALLOW", "false"},
                {"request-challenge", "CHALLENGE", "true"}, {"request-denied", "AUTHORIZATION_DENIED", "true"},
                {"request-none", null, "false"}}) {
            SecurityEvent event = event(outcome[0]);
            recorder.stage(event, ContextObservationRecorder.ROLE_SCOPE, null, commit -> recorded.add(outcome[0]
                    + " learnable=" + commit.learnable() + " denied=" + commit.authorizationDenied()));
            recorder.commit(event, outcome[1], Boolean.parseBoolean(outcome[2]));
        }

        assertThat(recorded).containsExactly(
                "request-allow-shadow learnable=false denied=false",
                "request-challenge learnable=false denied=false",
                "request-denied learnable=false denied=true",
                "request-none learnable=false denied=false");
        assertThat(store.getRecentSessionDecisions("session-1", 10)).hasSize(3);
    }

    private static SecurityEvent event(String requestId) {
        SecurityEvent event = SecurityEvent.builder()
                .sessionId("session-1")
                .timestamp(Instant.parse("2026-09-30T03:17:00Z"))
                .build();
        event.addMetadata("requestId", requestId);
        event.addMetadata("requestPath", "/api/projects/GB-500/exports");
        event.addMetadata("httpMethod", "POST");
        return event;
    }
}
