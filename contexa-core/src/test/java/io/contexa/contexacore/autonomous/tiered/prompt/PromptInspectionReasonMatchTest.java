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
 * the response checker's function; a golden render sealed with the decision the model might have given.
 */
class PromptInspectionReasonMatchTest {

    private static final PromptInspector INSPECTOR =
            new PromptInspector(List.of(new ReasonMatchCheck()), InspectionGolden.JSON);
    private static final Pattern LINE_ID = Pattern.compile("^\\[([A-Z][0-9]+)] ([A-Za-z0-9]+): ");

    @Test
    void eachReasonCodeOfTheSealedDecisionIsCheckedAgainstTheFactItCites() throws Exception {
        InspectionGolden.Render render = InspectionGolden.renders().stream()
                .filter(candidate -> candidate.used() != null && candidate.used().getDecisionFacts() != null
                        && candidate.used().getDecisionFacts().policy().satisfied() != null
                        && idOf(candidate.userPrompt(), "PolicySatisfied") != null
                        && candidate.userPrompt().contains("Unknown: not-integrated: [U1] "))
                .findFirst().orElseThrow();
        String policy = idOf(render.userPrompt(), "PolicySatisfied");
        String other = Arrays.stream(render.userPrompt().split("\n")).map(LINE_ID::matcher).filter(Matcher::find)
                .map(found -> found.group(1)).filter(id -> !id.equals(policy)).findFirst().orElseThrow();
        Boolean satisfied = render.used().getDecisionFacts().policy().satisfied();
        String holding = satisfied ? "POLICY_SATISFIED" : render.used().getDecisionFacts().policy().reason().code();

        PromptInspectionCheckResult check = check(render, List.of(
                Map.of("code", holding, "fact", policy),
                Map.of("code", "MATERIAL_MISSING_EVIDENCE", "fact", "U1"),
                Map.of("code", holding, "fact", other),
                Map.of("code", holding, "fact", "F99"),
                Map.of("code", "MIN_P3_POLICY_NOT_SATISFIED", "fact", policy)));

        assertThat(check.matched()).isEqualTo(2);
        assertThat(check.mismatched()).isEqualTo(2);
        assertThat(check.unverifiable()).isEqualTo(1);
        assertThat(check.findings()).extracting(PromptInspectionFinding::outcome).containsExactly(
                PromptInspectionOutcome.MISMATCH, PromptInspectionOutcome.MISMATCH, PromptInspectionOutcome.UNVERIFIABLE);
        assertThat(check.findings().get(0).reason()).startsWith("the code does not cite ");
        assertThat(check.findings().get(1).reason()).isEqualTo("the prompt gives no fact this ID");
        assertThat(check.findings().get(2).entry()).isEqualTo("MIN_P3_POLICY_NOT_SATISFIED");
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
