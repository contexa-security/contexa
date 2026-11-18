package io.contexa.contexacore.autonomous.tiered.prompt;

import io.contexa.contexacore.autonomous.context.support.PastRecordCounts;
import io.contexa.contexacore.std.components.prompt.PromptExecutionMetadata;
import io.contexa.contexacore.verification.inspection.PromptInspectionCheckResult;
import io.contexa.contexacore.verification.inspection.PromptInspectionFinding;
import io.contexa.contexacore.verification.inspection.PromptInspectionOutcome;
import io.contexa.contexacore.verification.inspection.PromptInspector;
import io.contexa.contexacore.verification.inspection.SameFactCheck;
import org.junit.jupiter.api.Test;

import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.function.Predicate;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * R1b-8 (plan 2 C2): one fact the prompt states twice has one value. A REQUEST, SESSION or usual line and the past
 * record state are compared with what the sealed decision facts and past record counts say of the same fact: the values
 * the differences, same and counts lines drew from them.
 */
class PromptInspectionSameFactTest {

    private static final PromptInspector INSPECTOR =
            new PromptInspector(List.of(new SameFactCheck()), InspectionGolden.JSON);

    /**
     * The golden cases of a user with a learned baseline (a differences line) have facts to compare; every render states
     * each fact with one value.
     */
    @Test
    void everyGoldenRenderStatesEachFactWithOneValue() {
        int learned = 0;
        for (InspectionGolden.Render render : InspectionGolden.renders()) {
            PromptInspectionCheckResult check = check(render.userPrompt(), render);
            assertThat(mismatches(check)).as(render.caseKey() + " " + render.profile()).isEmpty();
            if (!valueOf(render.userPrompt(), "DeviationsFromBaseline: ").isEmpty()) {
                learned++;
                assertThat(check.matched()).as(render.caseKey() + " " + render.profile()).isPositive();
            }
        }
        assertThat(learned).isPositive();
    }

    /** Plan 6-2 (decision D7): the showcase engine's v20 packages are of a bundle this build no longer ships. */
    @Test
    void theShowcaseEnginesV20PackagesAreNotReadAgain() {
        assertThat(EarlierBundleInspection.assertNotReadAgain(INSPECTOR, InspectionGolden.showcaseSealed())).isPositive();
    }

    @Test
    void aRequestLineOtherThanTheValueTheDifferencesLineStatesIsPointedAt() {
        InspectionGolden.Render render = learned(text -> valueOf(text, "DeviationsFromBaseline: ").contains("class "));
        String line = InspectionGolden.lineStarting(render.userPrompt(), "ResourceClass: ");
        String drawn = valueOf(line).split(" ")[0];

        PromptInspectionFinding finding = single(check(render, line,
                line.replace("ResourceClass: " + drawn, "ResourceClass: PUBLIC")));
        assertThat(finding.entry()).isEqualTo("ResourceClass");
        assertThat(finding.expected()).isEqualTo(drawn);
        assertThat(finding.actual()).isEqualTo("PUBLIC");
        assertThat(finding.sourceRef()).isEqualTo("DECISION FACTS.DeviationsFromBaseline");
    }

    @Test
    void aUsualListThatHoldsAValueTheDifferencesLineCallsNewIsPointedAt() {
        InspectionGolden.Render render = learned(text -> valueOf(text, "DeviationsFromBaseline: ").contains("time ")
                && valueOf(text, "UsualHours: ").contains("(seen "));
        String time = valueOf(InspectionGolden.lineStarting(render.userPrompt(), "Time: "));
        String hour = String.valueOf(Integer.parseInt(time.substring(4, 6)));
        String line = InspectionGolden.lineStarting(render.userPrompt(), "UsualHours: ");

        PromptInspectionFinding finding = single(check(render, line, line.replace("(seen ", "(seen " + hour + ",")));
        assertThat(finding.entry()).isEqualTo("UsualHours");
        assertThat(finding.sourceRef()).isEqualTo("DECISION FACTS.DeviationsFromBaseline");
    }

    @Test
    void aUsualListWithoutAValueTheSameLineCallsUsualIsPointedAt() {
        InspectionGolden.Render render = learned(text -> valueOf(text, "SameAsBaseline: ").contains("network")
                && valueOf(text, "UsualNetworks: ").contains("/"));
        String line = InspectionGolden.lineStarting(render.userPrompt(), "UsualNetworks: ");

        PromptInspectionFinding finding = single(check(render, line,
                InspectionGolden.factIdOf(line) + "UsualNetworks: 192.0.2.0/24"));
        assertThat(finding.entry()).isEqualTo("UsualNetworks");
        assertThat(finding.sourceRef()).isEqualTo("DECISION FACTS.SameAsBaseline");
    }

    /** A golden render of a user with a learned baseline whose prompt has the wanted lines. */
    private static InspectionGolden.Render learned(Predicate<String> wanted) {
        return InspectionGolden.render(wanted);
    }

    /** The render's check result with one drawn line changed. */
    private static PromptInspectionCheckResult check(InspectionGolden.Render render, String line, String changed) {
        assertThat(changed).isNotEqualTo(line);
        return check(render.userPrompt().replace(line, changed), render);
    }

    /**
     * The golden renders count no past record facts (the UNKNOWN line names them not counted), so the counts are sealed
     * here with the candidates the state line names, and the counts line is drawn.
     */
    @Test
    void thePastRecordStateNamesTheCandidatesTheCountsLineCounts() {
        InspectionGolden.Render render = InspectionGolden.render(text ->
                CANDIDATES.matcher(valueOf(text, "PastRecordsState: ")).find());
        String state = InspectionGolden.lineStarting(render.userPrompt(), "PastRecordsState: ");
        Matcher candidates = CANDIDATES.matcher(state);
        assertThat(candidates.find()).isTrue();
        long total = Long.parseLong(candidates.group(1));
        PastRecordCounts counts = new PastRecordCounts("READ", "GET /api/documents/{documentKey}", 1, null, total - 1,
                null, 0, total);
        Map<String, Object> metadata = new LinkedHashMap<>(render.executionMetadata());
        metadata.put(PromptExecutionMetadata.PROMPT_PAST_RECORD_COUNTS, counts.toMetadata());
        String counted = render.userPrompt().replace(state + "\n", state + "\nPastRecordCounts: " + counts.line(null)
                + "\n");
        InspectionGolden.Render withCounts = new InspectionGolden.Render(render.caseKey(), render.profile(),
                render.systemPrompt(), counted, render.used(), metadata, render.ragResultsJson(), render.requestFactsJson());
        assertThat(mismatches(check(counted, withCounts))).isEmpty();

        String changed = state.replace(candidates.group(), "of " + (total + 7) + " candidates");
        PromptInspectionFinding finding = single(check(counted.replace(state, changed), withCounts));
        assertThat(finding.entry()).isEqualTo("PastRecordsState");
        assertThat(finding.expected()).isEqualTo(total + " candidates");
        assertThat(finding.sourceRef()).isEqualTo("PAST RECORDS.PastRecordCounts");
    }

    private static final Pattern CANDIDATES = Pattern.compile("of (\\d+) candidates");

    private static PromptInspectionCheckResult check(String userPrompt, InspectionGolden.Render render) {
        PromptInspectionCheckResult check = INSPECTOR.inspect(render.sealed(userPrompt)).checks().get(0);
        assertThat(check.checkCode()).isEqualTo(SameFactCheck.CODE);
        return check;
    }

    private static List<PromptInspectionFinding> mismatches(PromptInspectionCheckResult check) {
        return check.findings().stream().filter(finding -> finding.outcome() == PromptInspectionOutcome.MISMATCH).toList();
    }

    private static PromptInspectionFinding single(PromptInspectionCheckResult check) {
        List<PromptInspectionFinding> mismatches = mismatches(check);
        assertThat(mismatches).hasSize(1);
        return mismatches.get(0);
    }

    /** The value of the first drawn line with the label, or an empty text. */
    private static String valueOf(String text, String label) {
        return Arrays.stream(text.split("\n")).filter(line -> InspectionGolden.bare(line).startsWith(label)).findFirst()
                .map(PromptInspectionSameFactTest::valueOf).orElse("");
    }

    /** The value of a drawn line, without its fact id and label. */
    private static String valueOf(String line) {
        String bare = InspectionGolden.bare(line);
        return bare.substring(bare.indexOf(": ") + 2);
    }
}
