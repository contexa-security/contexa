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
package io.contexa.contexaiam.admin.promptquality.governance;

import io.contexa.contexaiam.admin.promptquality.inspection.JdbcPromptInspectionQueries;
import io.contexa.contexaiam.admin.promptquality.version.PromptVersionConsole;
import io.contexa.contexaiam.admin.promptquality.version.PromptVersionConsoleDtos.ShadowCase;
import io.contexa.contexaiam.admin.promptquality.version.PromptVersionConsoleDtos.ShadowResults;
import io.contexa.contexaiam.admin.promptquality.version.PromptVersionRecord;
import io.contexa.contexaiam.admin.promptquality.version.PromptVersionService;
import org.junit.jupiter.api.Test;
import org.springframework.jdbc.core.JdbcTemplate;

import java.time.Clock;
import java.time.Instant;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyBoolean;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/**
 * Plan 3.9 and 6-6 (5): before the release screens go, the shadow results of their comparison (N-SHD-1) are what the
 * version screens' results of running alongside count from the same shadow pairs: the runs, the pairs that found their
 * decision, those answered otherwise, and the requests per decision and shadow action.
 */
class PromptVersionShadowResultsEquivalenceTest {

    private static final Instant AT = Instant.parse("2026-11-17T01:00:00Z");

    private static JdbcPromptInspectionQueries.ShadowPair pair(String request, String shadowAction, String decisionPackage,
                                                               String decisionAction) {
        return new JdbcPromptInspectionQueries.ShadowPair(request, AT, "shadow-" + request, "v3.0", shadowAction,
                decisionPackage, "v2.0", decisionAction);
    }

    private static PromptVersionRecord version(int number) {
        return new PromptVersionRecord(number, "PLATFORM_GLOBAL", "cortex.security-decision", number, "v" + number, null,
                1, "base", PromptVersionRecord.ORGANIZATION, PromptVersionRecord.SCREEN, "screen:" + number, "origin",
                "hash-" + number, "prompt: cortex.security-decision", false, "admin", AT);
    }

    @Test
    void theResultsOfRunningAlongsideCountAsTheReleaseComparisonDid() {
        List<JdbcPromptInspectionQueries.ShadowPair> pairs = List.of(
                pair("r1", "ALLOW", "d1", "ALLOW"), pair("r2", "CHALLENGE", "d2", "ALLOW"),
                pair("r3", "CHALLENGE", "d3", "ALLOW"), pair("r4", "BLOCK", "d4", "BLOCK"),
                pair("r5", "ALLOW", null, null), pair("r6", "ESCALATE", "d6", "CHALLENGE"));
        PromptReleaseConsole.ShadowCases before = PromptReleaseConsole.cases(pairs);

        JdbcPromptInspectionQueries queries = mock(JdbcPromptInspectionQueries.class);
        when(queries.shadowPairs(any(), any(), any())).thenReturn(pairs);
        PromptVersionService versions = mock(PromptVersionService.class);
        when(versions.prompts()).thenReturn(List.of("cortex.security-decision"));
        when(versions.list(any(), any(), anyBoolean())).thenReturn(List.of(version(3), version(2)));
        PromptVersionConsole console = new PromptVersionConsole(versions, () -> null, () -> null,
                () -> mock(JdbcTemplate.class), () -> null, () -> null, () -> null, () -> null, () -> queries,
                () -> null, () -> null, null, () -> null, null, Clock.systemUTC());
        ShadowResults after = console.shadowResults(null, "cortex.security-decision", AT.minusSeconds(3600), AT);

        assertThat(after.shadows()).isEqualTo(before.shadows()).isEqualTo(6);
        assertThat(after.paired()).isEqualTo(before.paired()).isEqualTo(5);
        assertThat(after.changed()).isEqualTo(before.changed()).isEqualTo(3);
        assertThat(after.changes()).extracting(change -> change.decisionAction() + ">" + change.shadowAction() + "="
                + change.requests()).containsExactlyElementsOf(before.changes().stream()
                .map(change -> change.decisionAction() + ">" + change.shadowAction() + "=" + change.requests()).toList());
        // The pairs answered otherwise come first, as the comparison listed them.
        assertThat(after.cases()).extracting(ShadowCase::requestId)
                .containsExactlyElementsOf(before.pairs().stream().map(JdbcPromptInspectionQueries.ShadowPair::requestId)
                        .toList());
    }
}
