package io.contexa.contexacore.autonomous.tiered.prompt;

import io.contexa.contexacore.autonomous.context.CanonicalSecurityContext;
import io.contexa.contexacore.autonomous.context.decision.DecisionFacts;
import io.contexa.contexacore.std.components.prompt.PromptExecutionMetadata;
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
import java.util.function.Consumer;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * The unknown check of the prompt inspector: the facts the engine could not establish are named in the UNKNOWN block
 * with their kind, a fact named unknown is not drawn with a value, and an entry without a value is drawn as its missing
 * notation says (N-INS-2).
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

        PromptInspectionCheckResult check = check(broken, render);
        PromptInspectionFinding finding = check.findings().stream().filter(found -> "Unknown".equals(found.entry()))
                .findFirst().orElseThrow();
        assertThat(finding.outcome()).isEqualTo(PromptInspectionOutcome.MISMATCH);
        assertThat(finding.block()).isEqualTo("UNKNOWN");
        assertThat(finding.reason()).contains("kind");
        // N-INS-2: a fact that does not apply is not written (dictionary 1.4); the delegation's line is left out by its
        // notation, so its name on the UNKNOWN line is pointed at as well.
        assertThat(check.findings()).hasSize(2).anySatisfy(found -> {
            assertThat(found.outcome()).isEqualTo(PromptInspectionOutcome.MISMATCH);
            assertThat(found.block()).isEqualTo("DECISION FACTS");
            assertThat(found.entry()).isEqualTo("Delegation");
            // N-INS-3: the name is read under the word in its kind's place, not under the kind before it.
            assertThat(found.actual()).isEqualTo("not-applicable");
            assertThat(found.reason()).contains("leaves the line out");
        });
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
        // The header names the time zone when a fact of the block is on the event clock (W3-13).
        String header = lineStarting(render.userPrompt(), "=== DECISION FACTS");
        String broken = render.userPrompt().replace(header + "\n", header + "\n" + name + ": made up\n");
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

    /**
     * N-INS-2: an entry with a missing text draws a line, its value or that text; an UNKNOWN name in its place, or no
     * line at all, is not its notation.
     */
    @Test
    void anEntryWithAMissingTextNamedUnknownInPlaceOfItsLineIsPointedAt() {
        InspectionGolden.Render render = InspectionGolden.render(text -> InspectionGolden.hasLine(text,
                "ChallengeVerified: ") && InspectionGolden.hasLine(text, "Unknown: "));
        String challenge = lineStarting(render.userPrompt(), "ChallengeVerified: ");
        String unknown = lineStarting(render.userPrompt(), "Unknown: ");
        String named = withNotIntegrated(unknown, "ChallengeVerified");
        String broken = render.userPrompt().replace(challenge + "\n", "").replace(unknown, named);

        PromptInspectionFinding finding = single(check(broken, render));
        assertThat(finding.outcome()).isEqualTo(PromptInspectionOutcome.MISMATCH);
        assertThat(finding.block()).isEqualTo("SESSION");
        assertThat(finding.entry()).isEqualTo("ChallengeVerified");
        assertThat(finding.expected()).isEqualTo("a line: a value or its missing text 'none'");
        assertThat(finding.actual()).isEqualTo("not-integrated");
        assertThat(finding.lineNumber()).isEqualTo(lineNumberOf(broken, named));
        assertThat(finding.reason()).contains("names the entry", "draws its missing text");

        PromptInspectionFinding left = single(check(render.userPrompt().replace(challenge + "\n", ""), render));
        assertThat(left.entry()).isEqualTo("ChallengeVerified");
        assertThat(left.expected()).isEqualTo("a line: a value or its missing text 'none'");
        assertThat(left.actual()).isNull();
        assertThat(left.reason()).contains("has no line");
    }

    /** N-INS-2: an entry whose line the dictionary leaves out without a value is not named on the UNKNOWN line. */
    @Test
    void anEntryWhoseLineIsLeftOutNamedOnTheUnknownLineIsPointedAt() {
        InspectionGolden.Render render = InspectionGolden.render(text -> !InspectionGolden.hasLine(text,
                "RecentMfaElsewhere: ") && InspectionGolden.hasLine(text, "Unknown: "));
        String unknown = lineStarting(render.userPrompt(), "Unknown: ");
        String named = withNotIntegrated(unknown, "RecentMfaElsewhere");
        String broken = render.userPrompt().replace(unknown, named);

        PromptInspectionFinding finding = single(check(broken, render));
        assertThat(finding.outcome()).isEqualTo(PromptInspectionOutcome.MISMATCH);
        assertThat(finding.block()).isEqualTo("SESSION");
        assertThat(finding.entry()).isEqualTo("RecentMfaElsewhere");
        assertThat(finding.expected()).isEqualTo("no UNKNOWN name: a line, or no line without a value");
        assertThat(finding.actual()).isEqualTo("not-integrated");
        assertThat(finding.lineNumber()).isEqualTo(lineNumberOf(broken, named));
        assertThat(finding.reason()).contains("leaves the line out");
    }

    /**
     * N-INS-2 (dictionary 1.4): the render's caller names the past records unknown now when the sealed search did not
     * retrieve them; past records a search found none of draw no line, PastRecordsState says why, and an UNKNOWN name
     * of them is pointed at.
     */
    @Test
    void pastRecordsAreNamedUnknownOnlyWhenTheSealedSearchDidNotRetrieveThem() {
        InspectionGolden.Render timedOut = InspectionGolden.renderWithTimedOutSearch(InspectionGolden.renders().get(0));
        assertThat(lineStarting(timedOut.userPrompt(), "Unknown: ")).contains("PastRecord (not retrieved, TIMEOUT)");
        assertThat(check(timedOut.userPrompt(), timedOut).findings()).isEmpty();
        // A package that seals no search state (a Layer2 second pass keeps the first prompt as it was sent) is read by
        // the state line the prompt draws.
        Map<String, Object> unsealed = new LinkedHashMap<>(timedOut.executionMetadata());
        assertThat(unsealed.remove(PromptExecutionMetadata.PROMPT_RAG_STATE)).isNotNull();
        InspectionGolden.Render withoutState = new InspectionGolden.Render(timedOut.caseKey(), timedOut.profile(),
                timedOut.systemPrompt(), timedOut.userPrompt(), timedOut.used(), unsealed, timedOut.ragResultsJson(),
                timedOut.requestFactsJson());
        assertThat(check(withoutState.userPrompt(), withoutState).findings()).isEmpty();

        InspectionGolden.Render noneFound = InspectionGolden.render(text -> InspectionGolden.hasLine(text,
                "PastRecordsState: none found") && InspectionGolden.hasLine(text, "Unknown: "));
        String unknown = lineStarting(noneFound.userPrompt(), "Unknown: ");
        String named = withUnavailableNow(unknown, "PastRecord (not retrieved, TIMEOUT)");
        String broken = noneFound.userPrompt().replace(unknown, named);

        PromptInspectionFinding finding = single(check(broken, noneFound));
        assertThat(finding.outcome()).isEqualTo(PromptInspectionOutcome.MISMATCH);
        assertThat(finding.block()).isEqualTo("PAST RECORDS");
        assertThat(finding.entry()).isEqualTo("PastRecord{i}");
        assertThat(finding.actual()).isEqualTo("unavailable-now (not retrieved, TIMEOUT)");
        assertThat(finding.lineNumber()).isEqualTo(lineNumberOf(broken, named));
        assertThat(finding.reason()).contains("leaves the line out");
    }

    /**
     * N-INS-4: the past records the render names unknown now for a search the sealed state says did not finish are
     * named with the kind and the reason it writes from that state; another reason is pointed at.
     */
    @Test
    void thePastRecordsReasonOnTheUnknownLineIsTheSealedSearchState() {
        InspectionGolden.Render timedOut = InspectionGolden.renderWithTimedOutSearch(InspectionGolden.renders().get(0));
        String unknown = lineStarting(timedOut.userPrompt(), "Unknown: ");
        assertThat(unknown).contains("PastRecord (not retrieved, TIMEOUT)");
        String broken = timedOut.userPrompt().replace(unknown,
                unknown.replace("PastRecord (not retrieved, TIMEOUT)", "PastRecord (not retrieved, DISABLED)"));

        PromptInspectionFinding finding = single(check(broken, timedOut));
        assertThat(finding.outcome()).isEqualTo(PromptInspectionOutcome.MISMATCH);
        assertThat(finding.block()).isEqualTo("PAST RECORDS");
        assertThat(finding.entry()).isEqualTo("PastRecord{i}");
        assertThat(finding.expected()).isEqualTo("unavailable-now (not retrieved, TIMEOUT)");
        assertThat(finding.actual()).isEqualTo("unavailable-now (not retrieved, DISABLED)");
        assertThat(finding.sourceRef()).isEqualTo("executionMetadata.promptRagState");
    }

    /** N-INS-2: an entry left out with its block when it has no value is not named on the UNKNOWN line either. */
    @Test
    void anEntryLeftOutWithItsBlockNamedOnTheUnknownLineIsPointedAt() {
        InspectionGolden.Render render = InspectionGolden.render(text -> !InspectionGolden.hasLine(text,
                "FirstPassVerdict: ") && InspectionGolden.hasLine(text, "Unknown: "));
        String unknown = lineStarting(render.userPrompt(), "Unknown: ");
        Map.of("FirstPassVerdict", "FirstPassVerdict", "NewPastRecord", "NewPastRecord{i}").forEach((name, entry) -> {
            String named = withNotIntegrated(unknown, name);
            String broken = render.userPrompt().replace(unknown, named);

            PromptInspectionFinding finding = single(check(broken, render));
            assertThat(finding.outcome()).as(name).isEqualTo(PromptInspectionOutcome.MISMATCH);
            assertThat(finding.block()).as(name).isEqualTo("SECOND PASS");
            assertThat(finding.entry()).as(name).isEqualTo(entry);
            assertThat(finding.expected()).as(name).isEqualTo("no UNKNOWN name: a line, or no line without a value");
            assertThat(finding.lineNumber()).as(name).isEqualTo(lineNumberOf(broken, named));
            assertThat(finding.reason()).as(name).contains("leaves it out with its block");
        });
    }

    /**
     * N-INS-2 (R1b): the render names the entries with a missing text unknown when the context has no source for them
     * (P3 review 169): the challenge without a session, the session's requests without its decision history and the
     * target the request does not name; it draws no line of them then. (The repeat goes without the decision facts,
     * which the prompt sections compute whenever there is a context, W2-5: only a render without any context names it.)
     */
    @Test
    void theRenderNamesTheEntriesWithoutASourceUnknownInPlaceOfTheirMissingText() {
        withoutSource().forEach((name, change) -> {
            InspectionGolden.Render lacking = InspectionGolden.renderWith(baseWithLines(name), change);
            assertThat(InspectionGolden.hasLine(lacking.userPrompt(), name + ": ")).as(name).isFalse();
            assertThat(names(lineStarting(lacking.userPrompt(), "Unknown: "), name)).as(name).isTrue();
        });
    }

    @Test
    void theChallengeIsNamedUnknownOnlyWhenTheSealedContextHasNoSession() {
        namedUnknownOnlyForWantOfItsSource("ChallengeVerified");
    }

    @Test
    void theSessionsRequestsAreNamedUnknownOnlyWhenTheSealedContextHasNoDecisionHistory() {
        namedUnknownOnlyForWantOfItsSource("RequestsInSession");
    }

    @Test
    void theTargetIsNamedUnknownOnlyWhenTheSealedResourceNamesNone() {
        namedUnknownOnlyForWantOfItsSource("Target");
    }

    /**
     * N-INS-2 (R1b): the repeat named unknown in place of its line is allowed when the sealed context has no decision
     * facts and pointed at when it has them. The prompt sections compute the facts whenever there is a context (W2-5),
     * so the sealed context here is the render's own with its facts taken out.
     */
    @Test
    void theRepeatIsNamedUnknownOnlyWhenTheSealedContextHasNoDecisionFacts() {
        InspectionGolden.Render base = baseWithLines("RepeatInSession");
        String line = lineStarting(base.userPrompt(), "RepeatInSession: ");
        String unknown = lineStarting(base.userPrompt(), "Unknown: ");
        String named = withNotIntegrated(unknown, "RepeatInSession");
        String broken = base.userPrompt().replace(line + "\n", "").replace(unknown, named);
        CanonicalSecurityContext withoutFacts = InspectionGolden.SERIALIZER.deserialize(
                InspectionGolden.SERIALIZER.serialize(base.used()));
        withoutFacts.setDecisionFacts(null);
        assertThat(UnknownLineValues.withoutSource(withoutFacts)).contains("DECISION_FACTS.RepeatInSession");
        var sealed = base.sealed(broken);
        sealed.setCanonicalContextJson(InspectionGolden.SERIALIZER.serialize(withoutFacts));
        assertThat(INSPECTOR.inspect(sealed).checks().get(0).findings())
                .noneMatch(finding -> "RepeatInSession".equals(finding.entry()));

        assertThat(UnknownLineValues.withoutSource(base.used())).doesNotContain("DECISION_FACTS.RepeatInSession");
        PromptInspectionFinding finding = single(check(broken, base));
        assertThat(finding.outcome()).isEqualTo(PromptInspectionOutcome.MISMATCH);
        assertThat(finding.entry()).isEqualTo("RepeatInSession");
        assertThat(finding.lineNumber()).isEqualTo(lineNumberOf(broken, named));
        assertThat(finding.reason()).contains("names the entry", "the sealed context gives its source");
    }

    /**
     * N-INS-2: without a sealed context that reads, whether the render named an entry with a missing text unknown for
     * want of a source cannot be told; it is said so, not pointed at.
     */
    @Test
    void anEntryNamedUnknownForWantOfASourceCannotBeToldWithoutASealedContext() {
        InspectionGolden.Render base = baseWithLines("ChallengeVerified");
        String line = lineStarting(base.userPrompt(), "ChallengeVerified: ");
        String unknown = lineStarting(base.userPrompt(), "Unknown: ");
        String named = withNotIntegrated(unknown, "ChallengeVerified");
        String broken = base.userPrompt().replace(line + "\n", "").replace(unknown, named);

        PromptInspectionResult result = INSPECTOR.inspect(InspectionGolden.sealed(broken, null));
        assertThat(result.checks().get(0).findings()).filteredOn(found -> "ChallengeVerified".equals(found.entry()))
                .singleElement().satisfies(found -> {
                    assertThat(found.outcome()).isEqualTo(PromptInspectionOutcome.UNVERIFIABLE);
                    assertThat(found.sourceRef()).isEqualTo("canonicalContextJson");
                    assertThat(found.lineNumber()).isEqualTo(lineNumberOf(broken, named));
                    assertThat(found.reason()).contains("for want of a source");
                });
    }

    /**
     * N-INS-2 (R1b): the shared rule names the entry without a source on the context the render used, and the unknown
     * check allows the UNKNOWN name then; with the source sealed, the same name in place of the line is pointed at.
     */
    private static void namedUnknownOnlyForWantOfItsSource(String name) {
        InspectionGolden.Render base = baseWithLines(name);
        InspectionGolden.Render lacking = InspectionGolden.renderWith(base, withoutSource().get(name));
        assertThat(UnknownLineValues.withoutSource(lacking.used())).as(name).anyMatch(key -> key.endsWith("." + name));
        assertThat(check(lacking.userPrompt(), lacking).findings()).as(name)
                .noneMatch(finding -> name.equals(finding.entry()));

        assertThat(UnknownLineValues.withoutSource(base.used())).as(name).noneMatch(key -> key.endsWith("." + name));
        String line = lineStarting(base.userPrompt(), name + ": ");
        String unknown = lineStarting(base.userPrompt(), "Unknown: ");
        String named = withNotIntegrated(unknown, name);
        String broken = base.userPrompt().replace(line + "\n", "").replace(unknown, named);
        PromptInspectionFinding finding = single(check(broken, base));
        assertThat(finding.outcome()).as(name).isEqualTo(PromptInspectionOutcome.MISMATCH);
        assertThat(finding.entry()).as(name).isEqualTo(name);
        assertThat(finding.lineNumber()).as(name).isEqualTo(lineNumberOf(broken, named));
        assertThat(finding.reason()).as(name).contains("names the entry", "the sealed context gives its source");
    }

    /** The context changes that take the source of each such entry away, as a render with a context can lack it. */
    private static Map<String, Consumer<CanonicalSecurityContext>> withoutSource() {
        Map<String, Consumer<CanonicalSecurityContext>> changes = new LinkedHashMap<>();
        changes.put("ChallengeVerified", context -> context.setSession(null));
        changes.put("RequestsInSession", context -> context.getSessionNarrativeProfile().setSessionDecisions(null));
        changes.put("Target", context -> {
            context.getResource().setPathFamily(null);
            context.getResource().setBusinessLabel(null);
        });
        return changes;
    }

    /** A golden render that draws the entry's line and an UNKNOWN line. */
    private static InspectionGolden.Render baseWithLines(String name) {
        return InspectionGolden.render(text -> InspectionGolden.hasLine(text, name + ": ")
                && InspectionGolden.hasLine(text, "Unknown: "));
    }

    /** Whether the UNKNOWN line names the fact after the ID it gives it. */
    private static boolean names(String unknownLine, String name) {
        for (String part : unknownLine.split("[,;] ")) {
            if (part.endsWith("] " + name) || part.contains("] " + name + " (")) {
                return true;
            }
        }
        return false;
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

    /** The UNKNOWN line without one name (with its ID and reason, when given), keeping the separators right. */
    private static String withoutName(String line, String name) {
        // N-UID-1: a name stands after the ID the line gives it; the ID goes with the name.
        Matcher withId = Pattern.compile("\\[U[0-9]+] " + Pattern.quote(name)).matcher(line);
        String named = withId.find() ? withId.group() : name;
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

    /** The UNKNOWN line with one more name of the kind not-integrated, first among them. */
    private static String withNotIntegrated(String line, String name) {
        return line.contains("not-integrated: ")
                ? line.replace("not-integrated: ", "not-integrated: " + name + ", ")
                : line.replace("Unknown: ", "Unknown: not-integrated: " + name + "; ");
    }

    /** The UNKNOWN line with one more name of the kind unavailable-now, its reason with it. */
    private static String withUnavailableNow(String line, String named) {
        return line.contains("unavailable-now: ")
                ? line.replace("unavailable-now: ", "unavailable-now: " + named + ", ")
                : line + "; unavailable-now: " + named;
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
