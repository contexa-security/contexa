package io.contexa.contexacore.autonomous.tiered.prompt;

import io.contexa.contexacore.std.components.prompt.PromptExecutionMetadata;
import io.contexa.contexacore.verification.evidence.SealedEvidencePackage;
import io.contexa.contexacore.verification.inspection.PastRecordNotationCheck;
import io.contexa.contexacore.verification.inspection.PromptInspectionCheckResult;
import io.contexa.contexacore.verification.inspection.PromptInspectionFinding;
import io.contexa.contexacore.verification.inspection.PromptInspectionOutcome;
import io.contexa.contexacore.verification.inspection.PromptInspectionResult;
import io.contexa.contexacore.verification.inspection.PromptInspector;
import org.junit.jupiter.api.Test;

import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * The past record check compares each drawn record line with the sealed retrieval summary: the records the render drew
 * are the sealed records, field by field, grouped, ordered and capped as the render does.
 */
class PromptInspectionPastRecordSourceTest {

    private static final PromptInspector INSPECTOR =
            new PromptInspector(List.of(new PastRecordNotationCheck()), InspectionGolden.JSON);

    @Test
    void everyV20RenderOfTheGoldenCasesDrawsTheSealedPastRecords() {
        int compared = 0;
        for (InspectionGolden.Render render : InspectionGolden.renders()) {
            PromptInspectionCheckResult check = check(render.sealed());
            // The golden inputs predate the sealed request time: only the distances are left uncompared.
            assertThat(check.findings()).as(render.caseKey() + " " + render.profile())
                    .allMatch(finding -> finding.outcome() == PromptInspectionOutcome.UNVERIFIABLE
                            && "canonicalContext.requestObservedAt".equals(finding.sourceRef()));
            compared += records(render.userPrompt()).size();
        }
        assertThat(compared).isPositive();
    }

    @Test
    void aRecordLineWithAnotherDecisionThanTheSealedRecordIsPointedAt() {
        InspectionGolden.Render render = withRecords();
        String record = records(render.userPrompt()).get(0);
        String decision = Arrays.stream(record.split(" / ")).filter(field -> field.equals("allowed")
                || field.equals("challenged") || field.equals("escalated") || field.equals("blocked")
                || field.equals("decision not recorded")).findFirst().orElseThrow();
        String other = "blocked".equals(decision) ? "allowed" : "blocked";
        String broken = render.userPrompt().replace(record, record.replace(" / " + decision + " / ", " / " + other + " / "));

        List<PromptInspectionFinding> found = sourceFindings(check(render.sealed(broken)));
        assertThat(found).hasSize(1);
        assertThat(found.get(0).entry()).isEqualTo(InspectionGolden.labelOf(record));
        assertThat(found.get(0).sourceRef()).isEqualTo("ragResultsJson.relatedDocuments");
        // The record's time relative to the request is part of the line the inspector draws (W3-13).
        assertThat(found.get(0).expected()).isEqualTo(record.substring(record.indexOf(": ") + 2));
    }

    @Test
    void aRecordTheSealedSummaryDoesNotHoldIsPointedAt() {
        InspectionGolden.Render render = withRecords();
        List<String> records = records(render.userPrompt());
        String last = records.get(records.size() - 1);
        String stem = InspectionGolden.labelOf(last).replaceAll("\\d+$", "");
        int next = Integer.parseInt(InspectionGolden.labelOf(last).substring(stem.length())) + 1;
        String outside = stem + next + ": 01-01 Mon 00:00 / READ / /outside/scope / no target / items not recorded / "
                + "class not recorded / network not recorded / device not recorded / login not recorded / allowed / "
                + "same target: no / authorized as not recorded";
        String broken = render.userPrompt().replace(last + "\n", last + "\n" + outside + "\n");

        List<PromptInspectionFinding> found = sourceFindings(check(render.sealed(broken)));
        assertThat(found).isNotEmpty();
        assertThat(found).extracting(PromptInspectionFinding::entry).contains(stem + next);
    }

    @Test
    void aStateLineOtherThanTheSealedRetrievalStateIsPointedAt() {
        InspectionGolden.Render render = withRecords();
        String state = Arrays.stream(render.userPrompt().split("\n")).filter(line -> InspectionGolden.bare(line).startsWith("PastRecordsState: "))
                .findFirst().orElseThrow();
        String broken = render.userPrompt().replace(state + "\n",
                InspectionGolden.factIdOf(state) + "PastRecordsState: none found (ZERO_RESULTS)\n");

        List<PromptInspectionFinding> found = check(render.sealed(broken)).findings().stream()
                .filter(finding -> "executionMetadata.promptRagState".equals(finding.sourceRef())).toList();
        assertThat(found).hasSize(1);
        assertThat(found.get(0).outcome()).isEqualTo(PromptInspectionOutcome.MISMATCH);
        assertThat(found.get(0).entry()).isEqualTo("PastRecordsState");
        assertThat(found.get(0).expected()).isEqualTo(InspectionGolden.bare(state).substring("PastRecordsState: ".length()));
        assertThat(found.get(0).actual()).isEqualTo("none found (ZERO_RESULTS)");
    }

    /**
     * N-INS-4: the state line needs only the retrieval state the render kept, so a package sealed before the event
     * clock was kept still has its state line compared (its record lines cannot be timed).
     */
    @Test
    void aStateLineIsComparedWithoutTheEventClock() {
        InspectionGolden.Render render = withRecords();
        Map<String, Object> withoutClock = new LinkedHashMap<>(render.executionMetadata());
        assertThat(withoutClock.remove(PromptExecutionMetadata.EVENT_TIME_ZONE)).isNotNull();
        InspectionGolden.Render unclocked = new InspectionGolden.Render(render.caseKey(), render.profile(),
                render.systemPrompt(), render.userPrompt(), render.used(), withoutClock, render.ragResultsJson(),
                render.requestFactsJson());
        String state = Arrays.stream(unclocked.userPrompt().split("\n"))
                .filter(line -> InspectionGolden.bare(line).startsWith("PastRecordsState: ")).findFirst().orElseThrow();
        String broken = unclocked.userPrompt().replace(state + "\n",
                InspectionGolden.factIdOf(state) + "PastRecordsState: none found (ZERO_RESULTS)\n");

        List<PromptInspectionFinding> found = check(unclocked.sealed(broken)).findings().stream()
                .filter(finding -> "executionMetadata.promptRagState".equals(finding.sourceRef())).toList();
        assertThat(found).hasSize(1);
        assertThat(found.get(0).outcome()).isEqualTo(PromptInspectionOutcome.MISMATCH);
        assertThat(found.get(0).entry()).isEqualTo("PastRecordsState");
        assertThat(found.get(0).actual()).isEqualTo("none found (ZERO_RESULTS)");
    }

    @Test
    void aPackageSealedBeforeThePastRecordFieldsWereKeptIsOfAnEarlierBundleAndIsNotRead() {
        // Packages sealed before the record fields were kept are of an earlier bundle's dictionary (R1b-7): the past
        // record lines are not read against this one.
        SealedEvidencePackage sealed = InspectionGolden.showcaseSealedOfAnEarlierBundle().stream()
                .filter(candidate -> candidate.getUserPromptText().contains("\nPastRecord1: "))
                .findFirst().orElseThrow();

        assertThat(check(sealed).findings()).singleElement().satisfies(finding -> {
            assertThat(finding.outcome()).isEqualTo(PromptInspectionOutcome.UNVERIFIABLE);
            assertThat(finding.sourceRef()).isEqualTo("executionMetadata.governanceDescriptor.promptBundleVersion");
        });
    }

    private static InspectionGolden.Render withRecords() {
        return InspectionGolden.renders().stream()
                .filter(render -> records(render.userPrompt()).size() >= 2)
                .findFirst().orElseThrow();
    }

    private static List<String> records(String userPrompt) {
        return Arrays.stream(userPrompt.split("\n")).filter(line -> InspectionGolden.bare(line).matches("PastRecord\\d+: .*")
                && !line.matches("PastRecord\\d+: \\+\\d+ more")).toList();
    }

    private static List<PromptInspectionFinding> sourceFindings(PromptInspectionCheckResult check) {
        return check.findings().stream().filter(finding -> "ragResultsJson.relatedDocuments".equals(finding.sourceRef()))
                .toList();
    }

    private static PromptInspectionCheckResult check(SealedEvidencePackage sealed) {
        PromptInspectionResult result = INSPECTOR.inspect(sealed);
        assertThat(result.checks()).hasSize(1);
        return result.checks().get(0);
    }
}
