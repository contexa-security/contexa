package io.contexa.contexacore.autonomous.tiered.prompt;

import io.contexa.contexacore.autonomous.context.CanonicalSecurityContext;
import io.contexa.contexacore.autonomous.context.decision.DecisionFacts;
import io.contexa.contexacore.verification.inspection.PromptInspectionCheckResult;
import io.contexa.contexacore.verification.inspection.PromptInspectionFinding;
import io.contexa.contexacore.verification.inspection.PromptInspectionOutcome;
import io.contexa.contexacore.verification.inspection.PromptInspectionResult;
import io.contexa.contexacore.verification.inspection.PromptInspector;
import io.contexa.contexacore.verification.inspection.UnknownDeclaredCheck;
import org.junit.jupiter.api.Test;

import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * The unknown check of the prompt inspector: the facts the engine could not establish are named in the UNKNOWN block
 * with their kind, a fact named unknown is not drawn with a value, and an entry the dictionary always draws has a line
 * or an UNKNOWN name.
 */
class PromptInspectionUnknownTest {

    private static final PromptInspector INSPECTOR =
            new PromptInspector(List.of(new UnknownDeclaredCheck()), InspectionGolden.JSON);

    @Test
    void everyV20RenderOfTheGoldenCasesNamesItsUnknownFactsAsTheDictionaryRules() {
        int matched = 0;
        for (InspectionGolden.Render render : InspectionGolden.renders()) {
            PromptInspectionCheckResult check = check(render.userPrompt(), render);
            assertThat(check.findings()).as(render.caseKey() + " " + render.profile()).isEmpty();
            matched += check.matched();
        }
        assertThat(matched).isPositive();
    }

    @Test
    void aSealedUnknownFactMissingFromTheUnknownLineIsPointedAt() {
        InspectionGolden.Render render = withSealedUnknown(false);
        String name = sealedUnknown(render, false);
        String unknown = lineStarting(render.userPrompt(), "Unknown: ");
        String broken = render.userPrompt().replace(unknown, withoutName(unknown, name));
        assertThat(broken).isNotEqualTo(render.userPrompt());

        PromptInspectionFinding finding = single(check(broken, render));
        assertThat(finding.outcome()).isEqualTo(PromptInspectionOutcome.MISMATCH);
        assertThat(finding.block()).isEqualTo("UNKNOWN");
        assertThat(finding.entry()).isEqualTo(name);
        assertThat(finding.expected()).isEqualTo("not-integrated");
        assertThat(finding.sourceRef()).isEqualTo("canonicalContext.decisionFacts.unknown");
        assertThat(finding.reason()).contains("not named");
    }

    @Test
    void anUnavailableFactNamedAsNotIntegratedIsPointedAtWithItsKindAndReason() {
        InspectionGolden.Render render = withSealedUnknown(true);
        String name = sealedUnknown(render, true);
        String reason = render.used().getDecisionFacts().unavailable().get(name);
        String unknown = lineStarting(render.userPrompt(), "Unknown: ");
        String moved = withoutName(unknown, name + " (" + reason + ")");
        moved = moved.contains("not-integrated: ")
                ? moved.replace("not-integrated: ", "not-integrated: " + name + ", ")
                : moved.replace("Unknown: ", "Unknown: not-integrated: " + name + "; ");
        String broken = render.userPrompt().replace(unknown, moved);

        PromptInspectionFinding finding = single(check(broken, render));
        assertThat(finding.entry()).isEqualTo(name);
        assertThat(finding.expected()).isEqualTo("unavailable-now (" + reason + ")");
        assertThat(finding.actual()).isEqualTo("not-integrated");
    }

    /**
     * R1b-3: the UNKNOWN line writes only the kinds of {@link io.contexa.contexacore.autonomous.context.prompt.PromptUnknownKind}
     * (dictionary 1.4: a fact that does not apply is not written), so a line naming another kind is pointed at.
     */
    @Test
    void aKindTheRenderDoesNotWriteIsPointedAt() {
        InspectionGolden.Render render = withSealedUnknown(false);
        String unknown = lineStarting(render.userPrompt(), "Unknown: ");
        String broken = render.userPrompt().replace(unknown, unknown + "; not-applicable: Delegation");

        PromptInspectionFinding finding = single(check(broken, render));
        assertThat(finding.outcome()).isEqualTo(PromptInspectionOutcome.MISMATCH);
        assertThat(finding.block()).isEqualTo("UNKNOWN");
        assertThat(finding.entry()).isEqualTo("Unknown");
        assertThat(finding.reason()).contains("kind");
    }

    /** R1b-3: the line states a sealed reason the way the render writes it, without the spaces around it. */
    @Test
    void aSealedReasonIsComparedAsTheRenderWritesIt() {
        InspectionGolden.Render render = withSealedUnknown(true);
        String name = sealedUnknown(render, true);
        CanonicalSecurityContext context = InspectionGolden.SERIALIZER.deserialize(
                InspectionGolden.SERIALIZER.serialize(render.used()));
        DecisionFacts facts = context.getDecisionFacts();
        Map<String, String> padded = new LinkedHashMap<>(facts.unavailable());
        padded.put(name, " " + padded.get(name) + " ");
        context.setDecisionFacts(new DecisionFacts(facts.facts(), facts.deviations(), facts.policy(), facts.unknown(),
                padded));
        var sealed = render.sealed(render.userPrompt());
        sealed.setCanonicalContextJson(InspectionGolden.SERIALIZER.serialize(context));

        PromptInspectionResult result = INSPECTOR.inspect(sealed);
        assertThat(result.checks().get(0).findings().stream().filter(finding -> name.equals(finding.entry()))).isEmpty();
    }

    @Test
    void aFactNamedUnknownButDrawnWithAValueIsPointedAtOnTheDrawnLine() {
        InspectionGolden.Render render = withSealedUnknown(false);
        String name = sealedUnknown(render, false);
        String broken = render.userPrompt().replace("=== DECISION FACTS ===\n",
                "=== DECISION FACTS ===\n" + name + ": made up\n");
        assertThat(broken).isNotEqualTo(render.userPrompt());

        PromptInspectionFinding finding = single(check(broken, render));
        assertThat(finding.entry()).isEqualTo(name);
        assertThat(finding.lineNumber()).isEqualTo(lineNumberOf(broken, name + ": made up"));
        assertThat(finding.reason()).contains("names the fact unknown");
    }

    @Test
    void anEntryTheDictionaryAlwaysDrawsWithNeitherALineNorAnUnknownNameIsPointedAt() {
        InspectionGolden.Render render = InspectionGolden.render(text -> InspectionGolden.hasLine(text, "Time: "));
        String time = lineStarting(render.userPrompt(), "Time: ");
        String broken = render.userPrompt().replace(time + "\n", "");

        PromptInspectionFinding finding = single(check(broken, render));
        assertThat(finding.block()).isEqualTo("REQUEST");
        assertThat(finding.entry()).isEqualTo("Time");
        assertThat(finding.reason()).contains("neither a line nor an UNKNOWN name");
    }

    @Test
    void withoutSealedDecisionFactsOnlyTheSealedUnknownsCannotBeTold() {
        InspectionGolden.Render render = withSealedUnknown(false);

        PromptInspectionResult result = INSPECTOR.inspect(InspectionGolden.sealed(render.userPrompt(), null));
        PromptInspectionFinding finding = single(result.checks().get(0));
        assertThat(finding.outcome()).isEqualTo(PromptInspectionOutcome.UNVERIFIABLE);
        assertThat(finding.sourceRef()).isEqualTo("canonicalContext.decisionFacts.unknown");
        assertThat(result.checks().get(0).matched()).isPositive();
    }

    private static PromptInspectionCheckResult check(String userPrompt, InspectionGolden.Render render) {
        PromptInspectionResult result = INSPECTOR.inspect(render.sealed(userPrompt));
        assertThat(result.checks()).hasSize(1);
        assertThat(result.checks().get(0).checkCode()).isEqualTo(UnknownDeclaredCheck.CODE);
        return result.checks().get(0);
    }

    private static InspectionGolden.Render withSealedUnknown(boolean unavailable) {
        return InspectionGolden.renders().stream()
                .filter(render -> render.used() != null && render.used().getDecisionFacts() != null
                        && sealedUnknownOrNull(render, unavailable) != null)
                .findFirst().orElseThrow();
    }

    private static String sealedUnknown(InspectionGolden.Render render, boolean unavailable) {
        String name = sealedUnknownOrNull(render, unavailable);
        assertThat(name).isNotNull();
        return name;
    }

    /** A sealed unknown decision fact the dictionary draws, of the wanted kind. */
    private static String sealedUnknownOrNull(InspectionGolden.Render render, boolean unavailable) {
        DecisionFacts facts = render.used().getDecisionFacts();
        Map<String, String> reasons = facts.unavailable();
        return facts.unknown().stream()
                .filter(name -> unavailable == reasons.containsKey(name))
                .filter(name -> SecurityDecisionPromptDictionary.ENTRIES.stream()
                        .anyMatch(entry -> entry.block().name().equals("DECISION_FACTS") && entry.matchesLabel(name)))
                .filter(name -> render.userPrompt().contains("Unknown: "))
                .findFirst().orElse(null);
    }

    /** The UNKNOWN line without one name (with its reason, when given), keeping the separators right. */
    private static String withoutName(String line, String named) {
        String result = line.replace(", " + named + ",", ",")
                .replace(": " + named + ", ", ": ")
                .replace(", " + named + ";", ";")
                .replace(", " + named + "\n", "\n");
        if (result.endsWith(", " + named)) {
            result = result.substring(0, result.length() - named.length() - 2);
        }
        result = result.replace("not-integrated: " + named + "; ", "").replace("; unavailable-now: " + named, "")
                .replace("unavailable-now: " + named + "; ", "");
        if (result.endsWith(": " + named)) {
            result = result.substring(0, result.length() - named.length() - 2);
        }
        return result;
    }

    private static PromptInspectionFinding single(PromptInspectionCheckResult check) {
        assertThat(check.findings()).hasSize(1);
        return check.findings().get(0);
    }

    private static String lineStarting(String text, String start) {
        return Arrays.stream(text.split("\n")).filter(line -> InspectionGolden.bare(line).startsWith(start)).findFirst().orElseThrow();
    }

    private static int lineNumberOf(String text, String line) {
        List<String> lines = Arrays.asList(text.split("\n", -1));
        return lines.indexOf(line) + 1;
    }
}
