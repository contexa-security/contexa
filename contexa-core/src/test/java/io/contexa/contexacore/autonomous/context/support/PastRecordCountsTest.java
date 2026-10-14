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

import org.junit.jupiter.api.Test;

import java.time.LocalDateTime;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * W3-18: the counted facts of a request's past allowed records of its action family, from the store's groups of one
 * path template, path and HTTP method: on the request's target, on other targets, and through the request's entry point.
 */
class PastRecordCountsTest {

    private static final LocalDateTime NOW = LocalDateTime.of(2026, 10, 12, 21, 0);
    private static final String EXPORTS = "/api/projects/{projectKey}/exports";
    private static final String ASYNC_EXPORTS = "/api/projects/{projectKey}/exports/async";

    private static PastRecordRelevance.Subject request(String path) {
        return PastRecordRelevance.Subject.ofRequest(
                Map.of("requestPath", path, "resourceUrlTemplate", EXPORTS, "httpMethod", "POST", "actionFamily", "EXPORT"), null);
    }

    @Test
    void theRecordsOfTheActionAreCountedOnTheTargetOnOtherTargetsAndThroughTheEntryPoint() {
        List<PastRecordGroup> groups = List.of(
                new PastRecordGroup(EXPORTS, "/api/projects/GB-500/exports", "POST", 2, NOW.minusHours(2)),
                new PastRecordGroup(EXPORTS, "/api/projects/PLM-OPS/exports", "POST", 3, NOW.minusDays(1)),
                // Another entry point that names the same project is the same target.
                new PastRecordGroup(ASYNC_EXPORTS, "/api/projects/GB-500/exports/async", "POST", 1, NOW.minusMinutes(30)));

        PastRecordCounts counts = PastRecordCounts.of(request("/api/projects/GB-500/exports"), groups);

        assertThat(counts.action()).isEqualTo("EXPORT");
        assertThat(counts.entryPoint()).isEqualTo("POST " + EXPORTS);
        assertThat(counts.sameTarget()).isEqualTo(3);
        assertThat(counts.sameTargetLast()).isEqualTo(NOW.minusMinutes(30));
        assertThat(counts.otherTargets()).isEqualTo(3);
        assertThat(counts.otherTargetsLast()).isEqualTo(NOW.minusDays(1));
        assertThat(counts.targetNotKnown()).isZero();
        assertThat(counts.entryPointRecords()).isEqualTo(5);
        assertThat(counts.line(NOW)).isEqualTo("EXPORT on this target 3 (last 30 min before this request); "
                + "on other targets 3 (last 24 h before this request); entry point POST " + EXPORTS + " used 5 times before");
    }

    @Test
    void anEntryPointWithoutRecordsIsFirstUsedNow() {
        List<PastRecordGroup> groups = List.of(
                new PastRecordGroup(EXPORTS, "/api/projects/GB-500/exports", "POST", 4, NOW.minusHours(5)));

        PastRecordCounts counts = PastRecordCounts.of(PastRecordRelevance.Subject.ofRequest(Map.of(
                "requestPath", "/api/projects/GB-500/exports/async", "resourceUrlTemplate", ASYNC_EXPORTS, "httpMethod", "POST",
                "actionFamily", "EXPORT"), null), groups);

        assertThat(counts.entryPointRecords()).isZero();
        assertThat(counts.line(NOW)).isEqualTo("EXPORT on this target 4 (last 5 h before this request); "
                + "on other targets 0; entry point POST " + ASYNC_EXPORTS + " first used now");
    }

    @Test
    void noRecordsAreCountedAsNone() {
        PastRecordCounts counts = PastRecordCounts.of(request("/api/projects/GB-500/exports"), List.of());

        assertThat(counts.line(NOW)).isEqualTo("EXPORT on this target 0; on other targets 0; entry point POST "
                + EXPORTS + " first used now");
    }

    @Test
    void aRecordWhoseTargetCannotBeComparedIsCountedApart() {
        List<PastRecordGroup> groups = List.of(
                new PastRecordGroup(EXPORTS, null, "POST", 2, null),
                new PastRecordGroup(EXPORTS, "/api/projects/GB-500/exports", "POST", 1, null));

        PastRecordCounts counts = PastRecordCounts.of(request("/api/projects/GB-500/exports"), groups);

        assertThat(counts.targetNotKnown()).isEqualTo(2);
        assertThat(counts.entryPointRecords()).isEqualTo(3);
        assertThat(counts.line(NOW)).isEqualTo("EXPORT on this target 1 (last time not recorded); on other targets 0; "
                + "target not known 2; entry point POST " + EXPORTS + " used 3 times before");
    }

    @Test
    void oneRecordIsWrittenInTheSingular() {
        PastRecordCounts counts = PastRecordCounts.of(request("/api/projects/GB-500/exports"), List.of(
                new PastRecordGroup(EXPORTS, "/api/projects/GB-500/exports", "POST", 1, NOW.minusHours(1))));

        assertThat(counts.line(NOW)).endsWith("entry point POST " + EXPORTS + " used 1 time before");
    }

    @Test
    void theCountsTravelAsMetadataAndReadBackTheSame() {
        PastRecordCounts counts = PastRecordCounts.of(request("/api/projects/GB-500/exports"), List.of(
                new PastRecordGroup(EXPORTS, "/api/projects/GB-500/exports", "POST", 2, NOW.minusHours(2)),
                new PastRecordGroup(EXPORTS, "/api/projects/PLM-OPS/exports", "POST", 3, NOW.minusDays(1))));

        assertThat(PastRecordCounts.fromMetadata(counts.toMetadata())).isEqualTo(counts);
        assertThat(PastRecordCounts.fromMetadata(null)).isNull();
        assertThat(PastRecordCounts.fromMetadata(Map.of("action", "EXPORT"))).isNull();
    }
}
