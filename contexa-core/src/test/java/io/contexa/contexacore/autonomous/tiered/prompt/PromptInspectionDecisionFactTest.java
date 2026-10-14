package io.contexa.contexacore.autonomous.tiered.prompt;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import io.contexa.contexacore.autonomous.context.decision.DecisionFact;
import io.contexa.contexacore.verification.evidence.SealedEvidencePackage;
import io.contexa.contexacore.verification.inspection.DecisionFactMatchCheck;
import io.contexa.contexacore.verification.inspection.PromptInspectionCheckResult;
import io.contexa.contexacore.verification.inspection.PromptInspectionFinding;
import io.contexa.contexacore.verification.inspection.PromptInspectionOutcome;
import io.contexa.contexacore.verification.inspection.PromptInspectionResult;
import io.contexa.contexacore.verification.inspection.PromptInspector;
import org.junit.jupiter.api.Test;

import java.util.Arrays;
import java.util.List;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * The decision fact check of the prompt inspector: every decision fact line of the resolver says what the sealed
 * decision facts say, letter for letter, with the sealed fact id, and the sealed facts are what the resolver gives
 * from the sealed context again (but the two that compare the request with the learned baseline, which is not sealed).
 */
class PromptInspectionDecisionFactTest {

    private static final PromptInspector INSPECTOR =
            new PromptInspector(List.of(new DecisionFactMatchCheck()), InspectionGolden.JSON);
    private static final String LEARNED_BASELINE = "learningContextEvidence";
    private static final Set<String> LEARNED_BASELINE_FACTS = Set.of("DeviationsFromBaseline", "SameAsBaseline");

    @Test
    void everyV20RenderOfTheGoldenCasesStatesTheSealedDecisionFacts() {
        int matched = 0;
        for (InspectionGolden.Render render : InspectionGolden.renders()) {
            PromptInspectionCheckResult check = check(render.sealed());
            // Only the facts that compare the request with the learned baseline cannot be computed again.
            assertThat(check.findings()).as(render.caseKey() + " " + render.profile())
                    .allMatch(finding -> finding.outcome() == PromptInspectionOutcome.UNVERIFIABLE
                            && LEARNED_BASELINE.equals(finding.sourceRef())
                            && LEARNED_BASELINE_FACTS.contains(finding.entry()));
            assertThat(check.findings()).extracting(PromptInspectionFinding::entry)
                    .as(render.caseKey() + " " + render.profile())
                    .containsExactlyInAnyOrderElementsOf(LEARNED_BASELINE_FACTS);
            matched += check.matched();
        }
        assertThat(matched).isPositive();
    }

    @Test
    void aSealedDecisionFactOtherThanTheSealedContextGivesIsPointedAtWithTheComputedFact() {
        InspectionGolden.Render render = InspectionGolden.render(text -> text.contains("RepeatInSession: "));
        DecisionFact sealed = sealedFact(render, "RepeatInSession");
        String line = lineContaining(render.userPrompt(), "RepeatInSession: ");
        // The prompt and the sealed fact agree; the sealed context the fact was computed from does not give it.
        String prompt = render.userPrompt().replace(line + "\n",
                line.substring(0, line.indexOf(": ") + 2) + "repeated 9 times in this session\n");
        SealedEvidencePackage evidencePackage = render.sealed(prompt);
        evidencePackage.setCanonicalContextJson(withFactValue(evidencePackage.getCanonicalContextJson(),
                "RepeatInSession", "repeated 9 times in this session"));

        List<PromptInspectionFinding> found = mismatches(check(evidencePackage));
        assertThat(found).hasSize(1);
        assertThat(found.get(0).entry()).isEqualTo("RepeatInSession");
        assertThat(found.get(0).factId()).isEqualTo(sealed.id());
        assertThat(found.get(0).sourceRef()).isEqualTo("canonicalContext");
        assertThat(found.get(0).expected()).startsWith(sealed.value() + " (");
        assertThat(found.get(0).actual()).startsWith("repeated 9 times in this session (");
        assertThat(found.get(0).reason()).contains("not what the sealed context gives");
    }

    @Test
    void aFactTheSealedContextGivesButTheSealedFactsLeaveOutIsPointedAt() {
        InspectionGolden.Render render = InspectionGolden.render(text -> text.contains("RepeatInSession: "));
        SealedEvidencePackage evidencePackage = render.sealed();
        evidencePackage.setCanonicalContextJson(withoutFact(evidencePackage.getCanonicalContextJson(), "RepeatInSession"));

        List<PromptInspectionFinding> found = mismatches(check(evidencePackage));
        assertThat(found).hasSize(1);
        assertThat(found.get(0).entry()).isEqualTo("RepeatInSession");
        assertThat(found.get(0).expected()).startsWith(sealedFact(render, "RepeatInSession").value() + " (");
        assertThat(found.get(0).actual()).isEqualTo("no fact");
    }

    @Test
    void theShowcaseEngineSealedFactsAreWhatItsSealedContextGivesAgain() {
        // Packages of the current bundle (R1b-7): an earlier bundle's packages are not read against this dictionary.
        for (SealedEvidencePackage evidencePackage : InspectionGolden.showcaseSealed()) {
            assertThat(mismatches(check(evidencePackage)).stream()
                    .filter(finding -> "canonicalContext".equals(finding.sourceRef())))
                    .as(evidencePackage.getPackageId()).isEmpty();
        }
    }

    @Test
    void withoutTheSealedEventClockTheFactsCannotBeComputedAgainAndSaysSo() {
        InspectionGolden.Render render = InspectionGolden.renders().get(0);
        SealedEvidencePackage evidencePackage = InspectionGolden.sealed(render.userPrompt(),
                InspectionGolden.SERIALIZER.serialize(render.used()));

        PromptInspectionCheckResult check = check(evidencePackage);
        assertThat(check.findings()).hasSize(1);
        assertThat(check.findings().get(0).outcome()).isEqualTo(PromptInspectionOutcome.UNVERIFIABLE);
        assertThat(check.findings().get(0).sourceRef()).isEqualTo("executionMetadata.eventTimeZone");
    }

    @Test
    void aDecisionFactLineSayingOtherThanTheSealedFactIsPointedAtWithTheSealedValue() {
        InspectionGolden.Render render = InspectionGolden.render(text -> text.contains("RepeatInSession: "));
        DecisionFact sealed = sealedFact(render, "RepeatInSession");
        String line = lineContaining(render.userPrompt(), "RepeatInSession: ");
        String broken = render.userPrompt().replace(line + "\n",
                line.substring(0, line.indexOf(": ") + 2) + "repeated 9 times in this session\n");

        PromptInspectionFinding finding = single(check(render.sealed(broken)));
        assertThat(finding.outcome()).isEqualTo(PromptInspectionOutcome.MISMATCH);
        assertThat(finding.block()).isEqualTo("DECISION FACTS");
        assertThat(finding.entry()).isEqualTo("RepeatInSession");
        assertThat(finding.expected()).isEqualTo(sealed.value());
        assertThat(finding.actual()).isEqualTo("repeated 9 times in this session");
        assertThat(finding.sourceRef()).isEqualTo("canonicalContext.decisionFacts.RepeatInSession");
        assertThat(finding.lineNumber()).isPositive();
    }

    @Test
    void aSealedDecisionFactMissingFromThePromptIsPointedAt() {
        InspectionGolden.Render render = InspectionGolden.render(text -> text.contains("RepeatInSession: "));
        String line = lineContaining(render.userPrompt(), "RepeatInSession: ");
        String broken = render.userPrompt().replace(line + "\n", "");

        PromptInspectionFinding finding = single(check(render.sealed(broken)));
        assertThat(finding.entry()).isEqualTo("RepeatInSession");
        assertThat(finding.actual()).isNull();
        assertThat(finding.reason()).contains("not in the prompt");
    }

    @Test
    void aDecisionFactLineWithAnotherFactIdThanTheSealedOneIsPointedAt() {
        // Fact ids of the resolver's facts are sealed with the facts; the two swapped lines must be such facts.
        InspectionGolden.Render render = InspectionGolden.renders().stream()
                .filter(candidate -> candidate.used() != null && candidate.used().getDecisionFacts() != null
                        && candidate.used().getDecisionFacts().facts().stream().map(DecisionFact::id)
                        .filter(id -> "F1".equals(id) || "F2".equals(id)).count() == 2)
                .findFirst().orElseThrow();
        String broken = render.userPrompt().replace("[F1] ", "[FX] ").replace("[F2] ", "[F1] ").replace("[FX] ", "[F2] ");

        List<PromptInspectionFinding> findings = mismatches(check(render.sealed(broken)));
        assertThat(findings).hasSize(2).allMatch(finding -> finding.reason().contains("fact id"));
        assertThat(findings).extracting(PromptInspectionFinding::expected).containsExactlyInAnyOrder("F1", "F2");
    }

    @Test
    void withoutSealedDecisionFactsTheCheckCannotTellAndSaysSo() {
        InspectionGolden.Render render = InspectionGolden.renders().get(0);
        SealedEvidencePackage evidencePackage = InspectionGolden.sealed(render.userPrompt(), null);

        PromptInspectionResult result = INSPECTOR.inspect(evidencePackage);
        PromptInspectionFinding finding = single(result.checks().get(0));
        assertThat(finding.outcome()).isEqualTo(PromptInspectionOutcome.UNVERIFIABLE);
        assertThat(finding.sourceRef()).isEqualTo("canonicalContext.decisionFacts");
        assertThat(result.verdict().name()).isEqualTo("INCOMPLETE");
    }

    private static PromptInspectionCheckResult check(SealedEvidencePackage evidencePackage) {
        PromptInspectionResult result = INSPECTOR.inspect(evidencePackage);
        assertThat(result.checks()).hasSize(1);
        assertThat(result.checks().get(0).checkCode()).isEqualTo(DecisionFactMatchCheck.CODE);
        return result.checks().get(0);
    }

    private static PromptInspectionFinding single(PromptInspectionCheckResult check) {
        List<PromptInspectionFinding> lineFindings = check.findings().stream()
                .filter(finding -> !LEARNED_BASELINE.equals(finding.sourceRef())).toList();
        assertThat(lineFindings).hasSize(1);
        return lineFindings.get(0);
    }

    private static List<PromptInspectionFinding> mismatches(PromptInspectionCheckResult check) {
        return check.findings().stream().filter(finding -> finding.outcome() == PromptInspectionOutcome.MISMATCH).toList();
    }

    /** The sealed canonical context with the named decision fact saying the value (the cached render is untouched). */
    private static String withFactValue(String canonicalJson, String name, String value) {
        ObjectNode context = read(canonicalJson);
        for (JsonNode fact : context.path("decisionFacts").path("facts")) {
            if (name.equals(fact.path("name").asText())) {
                ((ObjectNode) fact).put("value", value);
            }
        }
        return context.toString();
    }

    private static String withoutFact(String canonicalJson, String name) {
        ObjectNode context = read(canonicalJson);
        ArrayNode facts = (ArrayNode) context.path("decisionFacts").path("facts");
        for (int index = facts.size() - 1; index >= 0; index--) {
            if (name.equals(facts.get(index).path("name").asText())) {
                facts.remove(index);
            }
        }
        return context.toString();
    }

    private static ObjectNode read(String json) {
        try {
            return (ObjectNode) InspectionGolden.JSON.readTree(json);
        }
        catch (Exception exception) {
            throw new IllegalStateException(exception);
        }
    }

    private static DecisionFact sealedFact(InspectionGolden.Render render, String name) {
        return render.used().getDecisionFacts().fact(name).orElseThrow();
    }

    private static String lineContaining(String text, String part) {
        return Arrays.stream(text.split("\n")).filter(line -> line.contains(part)).findFirst().orElseThrow();
    }
}
