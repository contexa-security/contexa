package io.contexa.contexacore.autonomous.tiered.prompt;

import io.contexa.contexacore.verification.evidence.SealedEvidencePackage;
import io.contexa.contexacore.verification.inspection.PromptInspectionCheckResult;
import io.contexa.contexacore.verification.inspection.PromptInspectionFinding;
import io.contexa.contexacore.verification.inspection.PromptInspectionOutcome;
import io.contexa.contexacore.verification.inspection.PromptInspector;
import io.contexa.contexacore.verification.inspection.ReasonMatchCheck;
import org.junit.jupiter.api.Test;

import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * W4-8 (VR-5, redesign 3.2): REASON_MATCH checks each reason code of the sealed decision against the fact it cites, by
 * the response checker's function (the codes of the output contract the v1.0 answer uses); a golden render sealed with
 * the decision the model might have given.
 */
class PromptInspectionReasonMatchTest {

    private static final PromptInspector INSPECTOR =
            new PromptInspector(List.of(new ReasonMatchCheck()), InspectionGolden.JSON);
    private static final Pattern LINE_ID = Pattern.compile("^\\[([A-Z][0-9]+)] ([A-Za-z0-9]+): ");
    private static final String DIFFERENCES = "DeviationsFromBaseline";

    /**
     * A measured difference cited on the differences line and a missing fact cited on its UNKNOWN ID hold; the same code
     * on a line it may not cite or on an ID the prompt does not give is pointed at; a code whose condition the sealed
     * facts cannot decide (the baseline state is not in the canonical context) is counted unverifiable.
     */
    @Test
    void eachReasonCodeOfTheSealedDecisionIsCheckedAgainstTheFactItCites() throws Exception {
        InspectionGolden.Render render = InspectionGolden.renders().stream()
                .filter(candidate -> candidate.used() != null && candidate.used().getDecisionFacts() != null
                        && measuredDifference(candidate) != null && idOf(candidate.userPrompt(), DIFFERENCES) != null
                        && idOf(candidate.userPrompt(), "BaselineStatus") != null
                        && candidate.userPrompt().contains("Unknown: not-integrated: [U1] "))
                .findFirst().orElseThrow();
        String differences = idOf(render.userPrompt(), DIFFERENCES);
        String baseline = idOf(render.userPrompt(), "BaselineStatus");
        String other = Arrays.stream(render.userPrompt().split("\n")).map(LINE_ID::matcher).filter(Matcher::find)
                .map(found -> found.group(1)).filter(id -> !id.equals(differences)).findFirst().orElseThrow();
        String holding = measuredDifference(render);

        PromptInspectionCheckResult check = check(render, List.of(
                Map.of("code", holding, "fact", differences),
                Map.of("code", "MATERIAL_MISSING_EVIDENCE", "fact", "U1"),
                Map.of("code", holding, "fact", other),
                Map.of("code", holding, "fact", "F99"),
                Map.of("code", "BASELINE_NOT_ESTABLISHED", "fact", baseline)));

        assertThat(check.matched()).isEqualTo(2);
        assertThat(check.mismatched()).isEqualTo(2);
        assertThat(check.unverifiable()).isEqualTo(1);
        assertThat(check.findings()).extracting(PromptInspectionFinding::outcome).containsExactly(
                PromptInspectionOutcome.MISMATCH, PromptInspectionOutcome.MISMATCH, PromptInspectionOutcome.UNVERIFIABLE);
        assertThat(check.findings().get(0).reason()).startsWith("the code does not cite ");
        assertThat(check.findings().get(1).reason()).isEqualTo("the prompt gives no fact this ID");
        assertThat(check.findings().get(2).entry()).isEqualTo("BASELINE_NOT_ESTABLISHED");
    }

    /** A difference code the sealed differences fact holds, or null when it holds none. */
    private static String measuredDifference(InspectionGolden.Render render) {
        return render.used().getDecisionFacts().fact(DIFFERENCES)
                .flatMap(fact -> fact.codes().stream().filter(code -> code.startsWith("DEVIATION_")).findFirst())
                .orElse(null);
    }

    @Test
    void aDecisionWithoutReasonCodesHasNothingToCheck() throws Exception {
        PromptInspectionCheckResult check = check(InspectionGolden.renders().get(0), List.of());

        assertThat(check.matched() + check.mismatched() + check.unverifiable()).isZero();
    }

    private static PromptInspectionCheckResult check(InspectionGolden.Render render, List<Map<String, String>> codes)
            throws Exception {
        SealedEvidencePackage sealed = render.sealed();
        sealed.setDecisionJson(InspectionGolden.JSON.writeValueAsString(codes.isEmpty()
                ? Map.of("action", "ALLOW") : Map.of("action", "CHALLENGE", "reasonCodes", codes)));
        List<PromptInspectionCheckResult> checks = INSPECTOR.inspect(sealed).checks();
        assertThat(checks).hasSize(1);
        assertThat(checks.get(0).checkCode()).isEqualTo(ReasonMatchCheck.CODE);
        return checks.get(0);
    }

    private static String idOf(String userPrompt, String label) {
        return Arrays.stream(userPrompt.split("\n")).map(LINE_ID::matcher)
                .filter(found -> found.find() && found.group(2).equals(label))
                .map(found -> found.group(1)).findFirst().orElse(null);
    }
}
