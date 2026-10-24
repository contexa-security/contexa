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
package io.contexa.contexacore.verification.inspection;

import io.contexa.contexacore.autonomous.company.CompanyRecordSet;
import io.contexa.contexacore.autonomous.company.CompanyRecordSet.Assignment;
import io.contexa.contexacore.autonomous.company.CompanyRecordSet.OnCall;
import io.contexa.contexacore.autonomous.company.CompanyRecordSet.Person;
import io.contexa.contexacore.autonomous.company.CompanyRecordsFactSourceVerifier;
import io.contexa.contexacore.autonomous.company.InMemoryCompanyRecordStore;
import io.contexa.contexacore.autonomous.context.CanonicalSecurityContext;
import io.contexa.contexacore.autonomous.context.CanonicalSecurityContext.AssignmentRecord;
import io.contexa.contexacore.autonomous.context.CanonicalSecurityContext.FrictionProfile;
import io.contexa.contexacore.autonomous.context.CanonicalSecurityContext.OnCallRecord;
import org.junit.jupiter.api.Test;

import java.time.Duration;
import java.time.Instant;
import java.util.HashMap;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/** docs/agent OC-4: with Contexa's own records as its source, a line that says otherwise is a mismatch. */
class CompanyRecordsFactSourceVerifierTest {

    private static final Instant AT = Instant.parse("2026-09-30T05:30:00Z");

    @Test
    void aLineThatSaysOtherwiseThanContexasRecordsIsAMismatch() {
        InMemoryCompanyRecordStore store = new InMemoryCompanyRecordStore();
        store.put(null, new CompanyRecordSet(List.of(new Person("alice", "eng-k", null)), null,
                List.of(new Assignment("alice", "HX-310", "DESIGN", null, null)), null, null,
                List.of(new OnCall("ONC-1", "alice", "PLATFORM", AT.minus(Duration.ofHours(1)),
                        AT.plus(Duration.ofHours(4)))), null, null, null, null, null), "hr-sync", AT);
        CanonicalSecurityContext context = new CanonicalSecurityContext();
        context.setActor(CanonicalSecurityContext.Actor.builder().userId("alice").build());
        context.setRequestObservedAt(AT);
        context.setAttributes(new HashMap<>());
        FrictionProfile friction = new FrictionProfile();
        friction.setAssignment(new AssignmentRecord("HX-310", true, "DESIGN"));
        friction.setOnCall(OnCallRecord.builder().onCall(true).build());
        friction.setRecordsHolderId("alice");
        context.setFrictionProfile(friction);
        PromptInspectionSubject subject = mock(PromptInspectionSubject.class);
        when(subject.canonicalContext()).thenReturn(context);
        when(subject.prompt()).thenReturn(InspectedPrompt.parse("""
                === DECISION FACTS ===
                [F4] Assignment: assigned to HX-310 (DESIGN)
                [F8] OnCall: not on call
                """));
        PromptInspectionTally tally = new PromptInspectionTally(SourceTruthCheck.CODE, subject);

        new SourceTruthCheck(new CompanyRecordsFactSourceVerifier(store, null)).inspect(tally);

        assertThat(tally.result().matched()).isEqualTo(1);
        assertThat(tally.result().mismatched()).isEqualTo(1);
        assertThat(tally.result().findings()).singleElement().satisfies(finding -> {
            assertThat(finding.entry()).isEqualTo("OnCall");
            assertThat(finding.factId()).isEqualTo("F8");
            assertThat(finding.sourceRef()).isEqualTo("contexa company records on call");
        });
    }
}
