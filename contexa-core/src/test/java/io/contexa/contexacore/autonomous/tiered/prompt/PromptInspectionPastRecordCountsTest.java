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
package io.contexa.contexacore.autonomous.tiered.prompt;

import io.contexa.contexacore.autonomous.context.CanonicalSecurityContext;
import io.contexa.contexacore.autonomous.context.support.PastRecordCounts;
import io.contexa.contexacore.verification.evidence.SealedEvidencePackage;
import io.contexa.contexacore.verification.inspection.PastRecordNotationCheck;
import io.contexa.contexacore.verification.inspection.PromptInspectionCheckResult;
import io.contexa.contexacore.verification.inspection.PromptInspectionFinding;
import io.contexa.contexacore.verification.inspection.PromptInspectionOutcome;
import io.contexa.contexacore.verification.inspection.PromptInspectionResult;
import io.contexa.contexacore.verification.inspection.PromptInspector;
import org.junit.jupiter.api.Test;

import java.time.Instant;
import java.time.LocalDateTime;
import java.time.ZoneId;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * W3-18: the past record check compares the drawn PastRecordCounts line with the counted facts sealed with the render,
 * the times measured from the sealed request time.
 */
class PromptInspectionPastRecordCountsTest {

    private static final PromptInspector INSPECTOR =
            new PromptInspector(List.of(new PastRecordNotationCheck()), InspectionGolden.JSON);
    private static final String SOURCE = "executionMetadata.promptPastRecordCounts";
    private static final Instant REQUEST = Instant.parse("2026-10-12T03:17:00Z");
    private static final String EXPORTS = "POST /api/projects/{projectKey}/exports";

    @Test
    void aCountsLineThatIsTheSealedCountsMatches() {
        InspectionGolden.Render render = withState();
        PastRecordCounts counts = counts(render, 2);

        PromptInspectionCheckResult check = check(sealed(render, counts, line(render, counts)));

        assertThat(countFindings(check)).isEmpty();
    }

    @Test
    void aCountsLineWithAnotherCountThanTheSealedCountsIsPointedAt() {
        InspectionGolden.Render render = withState();
        PastRecordCounts counts = counts(render, 2);
        String drawn = line(render, counts(render, 5));

        List<PromptInspectionFinding> found = countFindings(check(sealed(render, counts, drawn)));

        assertThat(found).hasSize(1);
        assertThat(found.get(0).outcome()).isEqualTo(PromptInspectionOutcome.MISMATCH);
        assertThat(found.get(0).entry()).isEqualTo("PastRecordCounts");
        assertThat(found.get(0).expected()).isEqualTo(line(render, counts));
        assertThat(found.get(0).actual()).isEqualTo(drawn);
    }

    @Test
    void sealedCountsTheLinesDoNotDrawArePointedAt() {
        InspectionGolden.Render render = withState();
        PastRecordCounts counts = counts(render, 2);

        List<PromptInspectionFinding> found = countFindings(check(sealed(render, counts, null)));

        assertThat(found).hasSize(1);
        assertThat(found.get(0).outcome()).isEqualTo(PromptInspectionOutcome.MISMATCH);
        assertThat(found.get(0).entry()).isEqualTo("PastRecordCounts");
        assertThat(found.get(0).expected()).isEqualTo(line(render, counts));
        assertThat(found.get(0).actual()).isNull();
    }

    @Test
    void aCountsLineWithoutSealedCountsCannotBeComparedAndSaysSo() {
        InspectionGolden.Render render = withState();

        List<PromptInspectionFinding> found = countFindings(check(sealed(render, null,
                line(render, counts(render, 2)))));

        assertThat(found).hasSize(1);
        assertThat(found.get(0).outcome()).isEqualTo(PromptInspectionOutcome.UNVERIFIABLE);
        assertThat(found.get(0).reason()).contains("seals no counted past record facts");
    }

    private static InspectionGolden.Render withState() {
        return InspectionGolden.render(user -> user.contains("\nPastRecordsState: "));
    }

    private static PastRecordCounts counts(InspectionGolden.Render render, long sameTarget) {
        LocalDateTime request = LocalDateTime.ofInstant(REQUEST, zone(render));
        return new PastRecordCounts("EXPORT", EXPORTS, sameTarget, request.minusMinutes(30), 1, null, 0, 3);
    }

    private static String line(InspectionGolden.Render render, PastRecordCounts counts) {
        return counts.line(LocalDateTime.ofInstant(REQUEST, zone(render)));
    }

    private static ZoneId zone(InspectionGolden.Render render) {
        return ZoneId.of(String.valueOf(render.executionMetadata().get("eventTimeZone")));
    }

    /** The render sealed with the request time, the counts in its execution metadata and the counts line drawn. */
    private static SealedEvidencePackage sealed(InspectionGolden.Render render, PastRecordCounts counts,
                                                String countsLine) {
        CanonicalSecurityContext used = InspectionGolden.SERIALIZER.deserialize(
                InspectionGolden.SERIALIZER.serialize(render.used()));
        used.setRequestObservedAt(REQUEST);
        Map<String, Object> metadata = new LinkedHashMap<>(render.executionMetadata());
        if (counts != null) {
            metadata.put("promptPastRecordCounts", counts.toMetadata());
        }
        String state = Arrays.stream(render.userPrompt().split("\n"))
                .filter(candidate -> candidate.startsWith("PastRecordsState: ")).findFirst().orElseThrow();
        String user = countsLine == null ? render.userPrompt()
                : render.userPrompt().replace(state + "\n", state + "\nPastRecordCounts: " + countsLine + "\n");
        return new InspectionGolden.Render(render.caseKey(), render.profile(), render.systemPrompt(), user, used,
                metadata, render.ragResultsJson(), render.requestFactsJson()).sealed();
    }

    private static List<PromptInspectionFinding> countFindings(PromptInspectionCheckResult check) {
        return check.findings().stream().filter(finding -> SOURCE.equals(finding.sourceRef())).toList();
    }

    private static PromptInspectionCheckResult check(SealedEvidencePackage sealed) {
        PromptInspectionResult result = INSPECTOR.inspect(sealed);
        assertThat(result.checks()).hasSize(1);
        return result.checks().get(0);
    }
}
