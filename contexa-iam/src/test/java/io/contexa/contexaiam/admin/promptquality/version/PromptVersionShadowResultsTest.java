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
package io.contexa.contexaiam.admin.promptquality.version;

import io.contexa.contexaiam.admin.promptquality.inspection.JdbcPromptInspectionQueries;
import io.contexa.contexaiam.admin.promptquality.version.PromptVersionConsoleDtos.ShadowCase;
import io.contexa.contexaiam.admin.promptquality.version.PromptVersionConsoleDtos.ShadowResults;
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
 * Plan 3.9 and 6-6: the results of running alongside count the shadow pairs as the comparison of the release screens
 * did (N-SHD-1), which the version screens took over: the runs, the pairs that found their decision, those answered
 * otherwise, the requests per decision and shadow action, most first, and the pairs answered otherwise listed first.
 * The numbers are the ones the release comparison gave for the same pairs before it went (6-6 (5)).
 */
class PromptVersionShadowResultsTest {

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
        JdbcPromptInspectionQueries queries = mock(JdbcPromptInspectionQueries.class);
        when(queries.shadowPairs(any(), any(), any())).thenReturn(pairs);
        when(queries.bundleOutcomes(any(), any(), any())).thenReturn(List.of(
                new JdbcPromptInspectionQueries.BundleOutcome("v2.0", "DECISION", "ALLOW", 5, 0, 4, 1),
                new JdbcPromptInspectionQueries.BundleOutcome("v3.0", "SHADOW", "CHALLENGE", 3, 1, 1, 1)));
        PromptVersionService versions = mock(PromptVersionService.class);
        when(versions.prompts()).thenReturn(List.of("cortex.security-decision"));
        when(versions.list(any(), any(), anyBoolean())).thenReturn(List.of(version(3), version(2)));
        PromptVersionConsole console = new PromptVersionConsole(versions, () -> null, () -> null,
                () -> mock(JdbcTemplate.class), () -> null, () -> null, () -> null, () -> null, () -> queries,
                () -> null, () -> null, null, () -> null, null, Clock.systemUTC());

        ShadowResults results = console.shadowResults(null, "cortex.security-decision", AT.minusSeconds(3600), AT);

        assertThat(results.shadows()).isEqualTo(6);
        assertThat(results.paired()).isEqualTo(5);
        assertThat(results.changed()).isEqualTo(3);
        assertThat(results.changes()).extracting(change -> change.decisionAction() + ">" + change.shadowAction() + "="
                + change.requests()).containsExactly("ALLOW>CHALLENGE=2", "ALLOW>ALLOW=1", "BLOCK>BLOCK=1",
                "CHALLENGE>ESCALATE=1");
        assertThat(results.cases()).extracting(ShadowCase::requestId).containsExactly("r2", "r3", "r6", "r1", "r4");
        // Plan 3.9 (K56): each pair keeps its sealed packages, and the sealed decisions are counted per version, stage
        // and action with their inspection, as the release comparison showed them.
        assertThat(results.cases().get(0).shadowPackageId()).isEqualTo("shadow-r2");
        assertThat(results.cases().get(0).decisionPackageId()).isEqualTo("d2");
        assertThat(results.outcomes()).extracting(outcome -> outcome.version() + " " + outcome.stage() + " "
                + outcome.action() + " " + outcome.packages() + "/" + outcome.failed() + "/" + outcome.passed() + "/"
                + outcome.notInspected()).containsExactly("v2.0 DECISION ALLOW 5/0/4/1", "v3.0 SHADOW CHALLENGE 3/1/1/1");
    }
}
