package io.contexa.contexacore.autonomous.tiered.prompt;

import io.contexa.contexacore.verification.inspection.InspectedPrompt;
import io.contexa.contexacore.verification.inspection.PromptInspectionCheckResult;
import io.contexa.contexacore.verification.inspection.PromptInspectionFinding;
import io.contexa.contexacore.verification.inspection.PromptInspectionOutcome;
import io.contexa.contexacore.verification.inspection.PromptInspectionResult;
import io.contexa.contexacore.verification.inspection.PromptInspector;
import org.junit.jupiter.api.Test;

import java.util.HashSet;
import java.util.List;
import java.util.Objects;
import java.util.Set;
import java.util.stream.Collectors;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * The lines each check matched, which the inspection detail draws line by line (the store keeps counts only): the
 * dictionary contract accounts for every header and entry line, and no check names a line both matched and found.
 */
class PromptInspectionMatchedLinesTest {

    private static final PromptInspector INSPECTOR = new PromptInspector(PromptInspector.coreChecks(),
            InspectionGolden.JSON);

    @Test
    void theDictionaryContractMatchesOrFindsEveryHeaderAndEntryLine() {
        for (InspectionGolden.Render render : InspectionGolden.renders()) {
            PromptInspectionCheckResult contract = check(INSPECTOR.inspect(render.sealed()), "DICTIONARY_CONTRACT");
            Set<Integer> accounted = new HashSet<>(contract.matchedLines());
            contract.findings().stream().map(PromptInspectionFinding::lineNumber).filter(Objects::nonNull)
                    .forEach(accounted::add);

            Set<Integer> drawn = InspectedPrompt.parse(render.userPrompt()).lines().stream()
                    .filter(line -> line.kind() == InspectedPrompt.Kind.HEADER || line.kind() == InspectedPrompt.Kind.ENTRY)
                    .map(InspectedPrompt.Line::number).collect(Collectors.toSet());
            assertThat(accounted).as(render.caseKey() + " " + render.profile()).containsAll(drawn);
        }
    }

    @Test
    void aCheckNeverNamesALineBothMatchedAndFound() {
        int matched = 0;
        for (InspectionGolden.Render render : InspectionGolden.renders()) {
            PromptInspectionResult result = INSPECTOR.inspect(render.sealed());
            for (PromptInspectionCheckResult check : result.checks()) {
                Set<Integer> found = check.findings().stream()
                        .filter(finding -> finding.outcome() == PromptInspectionOutcome.MISMATCH)
                        .map(PromptInspectionFinding::lineNumber).filter(Objects::nonNull).collect(Collectors.toSet());
                assertThat(check.matchedLines().stream().filter(found::contains).toList())
                        .as(render.caseKey() + " " + check.checkCode()).isEmpty();
                matched += check.matchedLines().size();
            }
        }
        assertThat(matched).isPositive();
    }

    @Test
    void theFactAccuracyCheckNamesTheRequestLinesItMatched() {
        InspectionGolden.Render render = InspectionGolden.render(text -> InspectionGolden.hasLine(text, "Action: "));
        PromptInspectionResult result = INSPECTOR.inspect(render.sealed());
        List<String> lines = List.of(render.userPrompt().split("\n", -1));
        int action = lines.indexOf(lines.stream().filter(line -> InspectionGolden.bare(line).startsWith("Action: ")).findFirst().orElseThrow()) + 1;

        assertThat(check(result, "FACT_ACCURACY").matchedLines()).contains(action);
    }

    private static PromptInspectionCheckResult check(PromptInspectionResult result, String code) {
        return result.checks().stream().filter(check -> code.equals(check.checkCode())).findFirst().orElseThrow();
    }
}
