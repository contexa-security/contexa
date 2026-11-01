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
package io.contexa.contexacore.autonomous.context.collector;

import io.contexa.contexacommon.domain.SecurityEvent;
import io.contexa.contexacore.autonomous.store.InMemorySecurityContextDataStore;
import org.junit.jupiter.api.Test;

import java.time.Instant;
import java.util.ArrayList;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * QF-42: a committed request keeps its committed mark and the snapshots it was resolved with, not the observations that
 * ran at the commit (they hold the whole event); it is still recorded once.
 */
class ContextObservationRecorderReleaseTest {

    @Test
    void theCommitReleasesTheStagedObservationsAndKeepsTheSnapshotAndTheMark() {
        ContextObservationRecorder recorder = new ContextObservationRecorder(new InMemorySecurityContextDataStore());
        SecurityEvent event = SecurityEvent.builder()
                .sessionId("session-1")
                .timestamp(Instant.parse("2026-10-30T03:17:00Z"))
                .build();
        event.addMetadata("requestId", "request-1");
        List<String> recorded = new ArrayList<>();
        recorder.stage(event, ContextObservationRecorder.WORK_PROFILE, "snapshot",
                commit -> recorded.add("work profile " + commit.outcome() + " " + event.getSessionId()));
        recorder.stage(event, "decisionDocument", null, commit -> recorded.add("document " + commit.outcome()));
        assertThat(recorder.stagedObservations(event)).isEqualTo(2);

        recorder.commit(event, "ALLOW", true);

        assertThat(recorded).containsExactly("work profile ALLOW session-1", "document ALLOW");
        assertThat(recorder.stagedObservations(event)).isZero();
        assertThat(recorder.committed(event)).isTrue();
        assertThat(recorder.resolved(event, ContextObservationRecorder.WORK_PROFILE, String.class)).contains("snapshot");

        recorder.commit(event, "BLOCK", true);
        recorder.stage(event, ContextObservationRecorder.WORK_PROFILE, "later", commit -> recorded.add("later"));
        assertThat(recorded).hasSize(2);
        assertThat(recorder.stagedObservations(event)).isZero();
        assertThat(recorder.resolved(event, ContextObservationRecorder.WORK_PROFILE, String.class)).contains("snapshot");
    }
}
