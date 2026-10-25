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
package io.contexa.contexacore.autonomous.context.support;

import io.contexa.contexacore.autonomous.context.CanonicalSecurityContext;
import io.contexa.contexacore.autonomous.store.SessionDecisionRecord;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

/** RL-6: what an agent exported in its session, counted in one place for the prompt's line and the delegation's limits. */
class SessionExportsTest {

    private static SessionDecisionRecord record(String action, String outcome, Integer items) {
        return new SessionDecisionRecord(null, "POST", "/api/x", null, action, outcome, "T", items);
    }

    @Test
    void onlyTheExportsThatRanAreCountedByTheirItems() {
        CanonicalSecurityContext context = CanonicalSecurityContext.builder()
                .sessionNarrativeProfile(CanonicalSecurityContext.SessionNarrativeProfile.builder()
                        .sessionDecisions(List.of(
                                record("EXPORT", "ALLOW", 100),
                                record("export", "CHALLENGE", 50),
                                record("EXPORT", SessionDecisionRecord.AUTHORIZATION_DENIED, 900),
                                record("EXPORT", "BLOCK", 900),
                                record("EXPORT", "ALLOW", null),
                                record("READ", "ALLOW", 7)))
                        .build())
                .build();

        assertThat(SessionExports.exportedItems(context)).isEqualTo(150);
        assertThat(SessionExports.ran(record("EXPORT", "BLOCK", 1))).isFalse();
        assertThat(SessionExports.ran(record("EXPORT", SessionDecisionRecord.AUTHORIZATION_DENIED, 1))).isFalse();
        assertThat(SessionExports.ran(record("EXPORT", "ALLOW", 1))).isTrue();
        assertThat(SessionExports.ran(null)).isFalse();
    }

    @Test
    void aContextWithoutASessionExportedNothing() {
        assertThat(SessionExports.exportedItems(null)).isZero();
        assertThat(SessionExports.exportedItems(CanonicalSecurityContext.builder().build())).isZero();
    }
}
