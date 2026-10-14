package io.contexa.contexacore.autonomous.tiered.prompt;

import io.contexa.contexacore.verification.inspection.PastRecordNotationCheck;
import io.contexa.contexacore.verification.inspection.PromptInspectionCheckResult;
import io.contexa.contexacore.verification.inspection.PromptInspectionFinding;
import io.contexa.contexacore.verification.inspection.PromptInspectionOutcome;
import io.contexa.contexacore.verification.inspection.PromptInspectionResult;
import io.contexa.contexacore.verification.inspection.PromptInspector;
import org.junit.jupiter.api.Test;

import java.util.Arrays;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * The past record check of the prompt inspector: the state line counts the drawn records, each record line has the
 * twelve fields, and the lines are ordered same target first, then latest first. These are the findings read from
 * the lines alone (no source); the comparison with the sealed records is {@link PromptInspectionPastRecordSourceTest}.
 */
class PromptInspectionPastRecordTest {

    private static final PromptInspector INSPECTOR =
            new PromptInspector(List.of(new PastRecordNotationCheck()), InspectionGolden.JSON);
    private static final Pattern STATE = Pattern.compile("PastRecordsState: (\\d+) (records?) of");
    private static final Pattern OVERFLOW = Pattern.compile("\nPastRecord\\d+: \\+\\d+ more");

    @Test
    void everyV20RenderOfTheGoldenCasesKeepsThePastRecordNotation() {
        int matched = 0;
        for (InspectionGolden.Render render : InspectionGolden.renders()) {
            PromptInspectionCheckResult check = check(render.userPrompt(), render);
            assertThat(check.findings()).as(render.caseKey() + " " + render.profile())
                    .noneMatch(finding -> finding.outcome() == PromptInspectionOutcome.MISMATCH);
            matched += check.matched();
        }
        assertThat(matched).isPositive();
    }

    @Test
    void aStateLineCountingOtherThanTheDrawnRecordsIsPointedAt() {
        InspectionGolden.Render render = InspectionGolden.render(text -> STATE.matcher(text).find() && !OVERFLOW.matcher(text).find());
        Matcher state = STATE.matcher(render.userPrompt());
        assertThat(state.find()).isTrue();
        int count = Integer.parseInt(state.group(1));
        String broken = render.userPrompt().replace(state.group(), "PastRecordsState: " + (count + 3) + " records of");

        PromptInspectionFinding finding = single(check(broken, render));
        assertThat(finding.block()).isEqualTo("PAST RECORDS");
        assertThat(finding.entry()).isEqualTo("PastRecordsState");
        assertThat(finding.expected()).isEqualTo(count + " records");
        assertThat(finding.reason()).contains("count");
    }

    @Test
    void underAMoreLineOnlyACountBelowTheDrawnRecordsIsPointedAtTheRestIsLeftToTheSealedCount() {
        InspectionGolden.Render render = InspectionGolden.render(text -> STATE.matcher(text).find() && OVERFLOW.matcher(text).find());
        Matcher state = STATE.matcher(render.userPrompt());
        assertThat(state.find()).isTrue();
        int count = Integer.parseInt(state.group(1));

        String more = render.userPrompt().replace(state.group(), "PastRecordsState: " + (count + 3) + " records of");
        PromptInspectionCheckResult kept = check(more, render);
        assertThat(structural(kept)).isEmpty();
        assertThat(kept.findings()).extracting(PromptInspectionFinding::sourceRef)
                .contains("executionMetadata.promptRagState");

        String fewer = render.userPrompt().replace(state.group(), "PastRecordsState: 1 record of");
        PromptInspectionFinding finding = single(check(fewer, render));
        assertThat(finding.expected()).startsWith("at least ");
    }

    @Test
    void recordLinesUnderAStateOfNoRecordsArePointedAt() {
        InspectionGolden.Render render = InspectionGolden.render(text -> InspectionGolden.hasLine(text, "PastRecord1: "));
        String stateLine = lineStarting(render.userPrompt(), "PastRecordsState: ");
        String broken = render.userPrompt().replace(stateLine, InspectionGolden.factIdOf(stateLine) + "PastRecordsState: none found (ZERO_RESULTS)");

        PromptInspectionFinding finding = single(check(broken, render));
        assertThat(finding.entry()).isEqualTo("PastRecordsState");
        assertThat(finding.reason()).contains("count");
    }

    /** R1b-5: sealed past records that do not read leave the record lines unchecked, not compared with none. */
    @Test
    void sealedPastRecordsThatDoNotReadLeaveTheRecordLinesUnchecked() {
        InspectionGolden.Render render = InspectionGolden.render(text -> InspectionGolden.hasLine(text, "PastRecord1: "));
        var sealed = render.sealed(render.userPrompt());
        sealed.setRagResultsJson("[1,");

        List<PromptInspectionFinding> records = INSPECTOR.inspect(sealed).checks().get(0).findings().stream()
                .filter(finding -> finding.entry() != null && finding.entry().matches("PastRecord\\d+")).toList();
        assertThat(records).isNotEmpty()
                .allMatch(finding -> finding.outcome() == PromptInspectionOutcome.UNVERIFIABLE);
    }

    @Test
    void aRecordLineWithoutItsTwelveFieldsIsPointedAt() {
        InspectionGolden.Render render = InspectionGolden.render(text -> InspectionGolden.hasLine(text, "PastRecord1: "));
        String record = lineStarting(render.userPrompt(), "PastRecord1: ");
        String shortened = record.substring(0, record.lastIndexOf(" / "));
        String broken = render.userPrompt().replace(record + "\n", shortened + "\n");

        PromptInspectionFinding finding = single(check(broken, render));
        assertThat(finding.entry()).isEqualTo("PastRecord1");
        assertThat(finding.expected()).isEqualTo("12 fields");
        assertThat(finding.actual()).isEqualTo("11 fields");
    }

    @Test
    void aRecordOfTheSameTargetAfterOneOfAnotherTargetIsPointedAt() {
        InspectionGolden.Render render = InspectionGolden.render(text -> recordLines(text).size() >= 2
                && !sameTarget(recordLines(text).get(recordLines(text).size() - 1)).equals("same target: yes"));
        List<String> records = recordLines(render.userPrompt());
        String last = records.get(records.size() - 1);
        String moved = last.replace(sameTarget(last), "same target: yes");
        String broken = render.userPrompt().replace(last + "\n", moved + "\n");

        PromptInspectionFinding finding = single(check(broken, render));
        assertThat(finding.entry()).isEqualTo(InspectionGolden.labelOf(last));
        assertThat(finding.reason()).contains("same target first");
    }

    @Test
    void anOlderRecordBeforeANewerOneOfTheSameKindIsPointedAt() {
        InspectionGolden.Render render = InspectionGolden.render(PromptInspectionPastRecordTest::hasTwoOrderedRecordsOfOneKind);
        String broken = swapFirstTwoOfOneKind(render.userPrompt());

        assertThat(structural(check(broken, render))).extracting(PromptInspectionFinding::reason)
                .anyMatch(reason -> reason.contains("latest first"));
    }

    private static PromptInspectionCheckResult check(String userPrompt, InspectionGolden.Render render) {
        PromptInspectionResult result = INSPECTOR.inspect(render.sealed(userPrompt));
        assertThat(result.checks()).hasSize(1);
        assertThat(result.checks().get(0).checkCode()).isEqualTo(PastRecordNotationCheck.CODE);
        return result.checks().get(0);
    }

    /** The one finding the notation of the lines gives; the sealed sources are compared in their own test. */
    private static PromptInspectionFinding single(PromptInspectionCheckResult check) {
        List<PromptInspectionFinding> structural = structural(check);
        assertThat(structural).hasSize(1);
        return structural.get(0);
    }

    private static List<PromptInspectionFinding> structural(PromptInspectionCheckResult check) {
        return check.findings().stream().filter(finding -> finding.sourceRef() == null).toList();
    }

    private static String lineStarting(String text, String start) {
        return Arrays.stream(text.split("\n")).filter(line -> InspectionGolden.bare(line).startsWith(start)).findFirst().orElseThrow();
    }

    private static List<String> recordLines(String text) {
        return Arrays.stream(text.split("\n")).filter(line -> InspectionGolden.bare(line).matches("PastRecord\\d+: .*")
                && !line.matches("PastRecord\\d+: \\+\\d+ more")).toList();
    }

    private static String valueOf(String line) {
        return line.substring(line.indexOf(": ") + 2);
    }

    private static String sameTarget(String line) {
        return valueOf(line).split(" / ")[10];
    }

    private static String swapValues(String text, String a, String b) {
        String[] lines = text.split("\n", -1);
        int ai = Arrays.asList(lines).indexOf(a);
        int bi = Arrays.asList(lines).indexOf(b);
        lines[ai] = a.substring(0, a.indexOf(": ") + 2) + valueOf(b);
        lines[bi] = b.substring(0, b.indexOf(": ") + 2) + valueOf(a);
        return String.join("\n", lines);
    }

    private static boolean hasTwoOrderedRecordsOfOneKind(String text) {
        List<String> records = recordLines(text);
        for (int index = 0; index + 1 < records.size(); index++) {
            if (sameTarget(records.get(index)).equals(sameTarget(records.get(index + 1)))
                    && !minutesBefore(records.get(index)).equals(minutesBefore(records.get(index + 1)))) {
                return true;
            }
        }
        return false;
    }

    /** Swaps the values of two neighbouring record lines of one same-target kind whose times differ. */
    private static String swapFirstTwoOfOneKind(String text) {
        List<String> records = recordLines(text);
        for (int index = 0; index + 1 < records.size(); index++) {
            String a = records.get(index);
            String b = records.get(index + 1);
            if (sameTarget(a).equals(sameTarget(b)) && !minutesBefore(a).equals(minutesBefore(b))) {
                return swapValues(text, a, b);
            }
        }
        throw new IllegalStateException("no two records of one kind");
    }

    private static String minutesBefore(String line) {
        Matcher matcher = Pattern.compile("\\((\\d+) (min|h|days) before this request\\)").matcher(valueOf(line));
        return matcher.find() ? matcher.group(1) + matcher.group(2) : "none";
    }
}
