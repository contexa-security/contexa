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
import io.contexa.contexacore.autonomous.context.prompt.PromptListItem;
import io.contexa.contexacore.autonomous.context.support.PastDeniedDecisions;
import io.contexa.contexacore.verification.evidence.SealedEvidencePackage;
import io.contexa.contexacore.verification.inspection.FactAccuracyCheck;
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
 * W5-4: the past record check compares the drawn PastDeniedDecision lines with the decisions that did not allow sealed
 * with the render, drawn again the way the render draws them, the times measured from the sealed request time.
 */
class PromptInspectionPastDeniedDecisionsTest {

    private static final PromptInspector INSPECTOR =
            new PromptInspector(List.of(new PastRecordNotationCheck()), InspectionGolden.JSON);
    private static final String SOURCE = "executionMetadata.promptPastDeniedDecisions";
    private static final Instant REQUEST = Instant.parse("2026-10-12T03:17:00Z");

    @Test
    void theDeniedEntryIsInspectedByThePastRecordCheck() {
        assertThat(FactAccuracyCheck.INSPECTED_ELSEWHERE)
                .containsEntry("PAST_RECORDS.PastDeniedDecision{i}", PastRecordNotationCheck.CODE);
        assertThat(FactAccuracyCheck.NOT_COMPARABLE).doesNotContainKey("PAST_RECORDS.PastDeniedDecision{i}");
    }

    @Test
    void aDeniedLineThatIsTheSealedDecisionMatches() {
        InspectionGolden.Render render = withState();
        PastDeniedDecisions denied = denied(render, PastDeniedDecisions.NOT_VERIFIED);

        assertThat(deniedFindings(check(sealed(render, denied, line(render, denied))))).isEmpty();
    }

    @Test
    void aDeniedLineWithAnotherOutcomeThanTheSealedDecisionIsPointedAt() {
        InspectionGolden.Render render = withState();
        PastDeniedDecisions denied = denied(render, PastDeniedDecisions.NOT_VERIFIED);
        String drawn = line(render, denied(render, PastDeniedDecisions.VERIFIED_BY_STEP_UP));

        List<PromptInspectionFinding> found = deniedFindings(check(sealed(render, denied, drawn)));

        assertThat(found).hasSize(1);
        assertThat(found.get(0).outcome()).isEqualTo(PromptInspectionOutcome.MISMATCH);
        assertThat(found.get(0).expected()).isEqualTo(line(render, denied));
        assertThat(found.get(0).actual()).isEqualTo(drawn);
    }

    @Test
    void aSealedDecisionTheLinesDoNotDrawIsPointedAt() {
        InspectionGolden.Render render = withState();
        PastDeniedDecisions denied = denied(render, PastDeniedDecisions.NOT_VERIFIED);

        List<PromptInspectionFinding> found = deniedFindings(check(sealed(render, denied, null)));

        assertThat(found).hasSize(1);
        assertThat(found.get(0).outcome()).isEqualTo(PromptInspectionOutcome.MISMATCH);
        assertThat(found.get(0).expected()).isEqualTo(line(render, denied));
        assertThat(found.get(0).actual()).isNull();
    }

    @Test
    void aDeniedLineWithoutSealedDecisionsCannotBeComparedAndSaysSo() {
        InspectionGolden.Render render = withState();

        List<PromptInspectionFinding> found = deniedFindings(check(sealed(render, null,
                line(render, denied(render, PastDeniedDecisions.NOT_VERIFIED)))));

        assertThat(found).hasSize(1);
        assertThat(found.get(0).outcome()).isEqualTo(PromptInspectionOutcome.UNVERIFIABLE);
        assertThat(found.get(0).reason()).contains("seals no decisions that did not allow");
    }

    private static InspectionGolden.Render withState() {
        return InspectionGolden.render(user -> user.contains("\nPastRecordsState: "));
    }

    private static PastDeniedDecisions denied(InspectionGolden.Render render, String outcome) {
        LocalDateTime request = LocalDateTime.ofInstant(REQUEST, zone(render));
        return new PastDeniedDecisions(List.of(new PastDeniedDecisions.Entry(request.minusDays(2), "EXPORT",
                "projectKey=GB-500", "CHALLENGE", outcome)));
    }

    private static String line(InspectionGolden.Render render, PastDeniedDecisions denied) {
        List<PromptListItem> items = PastDeniedLines.items(denied, LocalDateTime.ofInstant(REQUEST, zone(render)));
        return items.isEmpty() ? null : items.get(0).text();
    }

    private static ZoneId zone(InspectionGolden.Render render) {
        return ZoneId.of(String.valueOf(render.executionMetadata().get("eventTimeZone")));
    }

    /** The render sealed with the request time, the decisions in its execution metadata and the line drawn. */
    private static SealedEvidencePackage sealed(InspectionGolden.Render render, PastDeniedDecisions denied,
                                                String deniedLine) {
        CanonicalSecurityContext used = InspectionGolden.SERIALIZER.deserialize(
                InspectionGolden.SERIALIZER.serialize(render.used()));
        used.setRequestObservedAt(REQUEST);
        Map<String, Object> metadata = new LinkedHashMap<>(render.executionMetadata());
        if (denied != null) {
            metadata.put("promptPastDeniedDecisions", denied.toMetadata());
        }
        String state = Arrays.stream(render.userPrompt().split("\n"))
                .filter(candidate -> candidate.startsWith("PastRecordsState: ")).findFirst().orElseThrow();
        String user = deniedLine == null ? render.userPrompt()
                : render.userPrompt().replace(state + "\n", state + "\nPastDeniedDecision1: " + deniedLine + "\n");
        return new InspectionGolden.Render(render.caseKey(), render.profile(), render.systemPrompt(), user, used,
                metadata, render.ragResultsJson(), render.requestFactsJson()).sealed();
    }

    private static List<PromptInspectionFinding> deniedFindings(PromptInspectionCheckResult check) {
        return check.findings().stream().filter(finding -> SOURCE.equals(finding.sourceRef())).toList();
    }

    private static PromptInspectionCheckResult check(SealedEvidencePackage sealed) {
        PromptInspectionResult result = INSPECTOR.inspect(sealed);
        assertThat(result.checks()).hasSize(1);
        return result.checks().get(0);
    }
}
