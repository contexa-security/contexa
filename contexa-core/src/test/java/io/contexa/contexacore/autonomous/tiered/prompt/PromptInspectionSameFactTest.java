package io.contexa.contexacore.autonomous.tiered.prompt;

import io.contexa.contexacore.verification.evidence.SealedEvidencePackage;
import io.contexa.contexacore.verification.inspection.PromptInspectionCheckResult;
import io.contexa.contexacore.verification.inspection.PromptInspectionFinding;
import io.contexa.contexacore.verification.inspection.PromptInspectionOutcome;
import io.contexa.contexacore.verification.inspection.PromptInspector;
import io.contexa.contexacore.verification.inspection.SameFactCheck;
import org.junit.jupiter.api.Test;

import java.util.Arrays;
import java.util.List;
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

    /** The golden cases have no learned baseline, so their differences are unknown: nothing is pointed at. */
    @Test
    void everyGoldenRenderStatesEachFactWithOneValue() {
        for (InspectionGolden.Render render : InspectionGolden.renders()) {
            assertThat(mismatches(check(render.userPrompt(), render))).as(render.caseKey() + " " + render.profile())
                    .isEmpty();
        }
    }

    /** The real packages: those of a user with a learned baseline (a differences line) have facts to compare. */
    @Test
    void theShowcaseEnginesPackagesStateEachFactWithOneValue() {
        int learned = 0;
        for (SealedEvidencePackage sealed : InspectionGolden.showcaseSealed()) {
            PromptInspectionCheckResult check = INSPECTOR.inspect(sealed).checks().get(0);
            assertThat(mismatches(check)).as(sealed.getPackageId()).isEmpty();
            if (!valueOf(sealed.getUserPromptText(), "DeviationsFromBaseline: ").isEmpty()) {
                learned++;
                assertThat(check.matched()).as(sealed.getPackageId()).isPositive();
            }
        }
        assertThat(learned).isPositive();
    }

    @Test
    void aRequestLineOtherThanTheValueTheDifferencesLineStatesIsPointedAt() {
        SealedEvidencePackage sealed = learned(text -> valueOf(text, "DeviationsFromBaseline: ").contains("class "));
        String line = InspectionGolden.lineStarting(sealed.getUserPromptText(), "ResourceClass: ");
        String drawn = valueOf(line).split(" ")[0];

        PromptInspectionFinding finding = single(check(sealed, line,
                line.replace("ResourceClass: " + drawn, "ResourceClass: PUBLIC")));
        assertThat(finding.entry()).isEqualTo("ResourceClass");
        assertThat(finding.expected()).isEqualTo(drawn);
        assertThat(finding.actual()).isEqualTo("PUBLIC");
        assertThat(finding.sourceRef()).isEqualTo("DECISION FACTS.DeviationsFromBaseline");
    }

    @Test
    void aUsualListThatHoldsAValueTheDifferencesLineCallsNewIsPointedAt() {
        SealedEvidencePackage sealed = learned(text -> valueOf(text, "DeviationsFromBaseline: ").contains("time ")
                && valueOf(text, "UsualHours: ").contains("(seen "));
        String time = valueOf(InspectionGolden.lineStarting(sealed.getUserPromptText(), "Time: "));
        String hour = String.valueOf(Integer.parseInt(time.substring(4, 6)));
        String line = InspectionGolden.lineStarting(sealed.getUserPromptText(), "UsualHours: ");

        PromptInspectionFinding finding = single(check(sealed, line, line.replace("(seen ", "(seen " + hour + ",")));
        assertThat(finding.entry()).isEqualTo("UsualHours");
        assertThat(finding.sourceRef()).isEqualTo("DECISION FACTS.DeviationsFromBaseline");
    }

    @Test
    void aUsualListWithoutAValueTheSameLineCallsUsualIsPointedAt() {
        SealedEvidencePackage sealed = learned(text -> valueOf(text, "SameAsBaseline: ").contains("network")
                && valueOf(text, "UsualNetworks: ").contains("/"));
        String line = InspectionGolden.lineStarting(sealed.getUserPromptText(), "UsualNetworks: ");

        PromptInspectionFinding finding = single(check(sealed, line,
                InspectionGolden.factIdOf(line) + "UsualNetworks: 192.0.2.0/24"));
        assertThat(finding.entry()).isEqualTo("UsualNetworks");
        assertThat(finding.sourceRef()).isEqualTo("DECISION FACTS.SameAsBaseline");
    }

    /** A real package of a user with a learned baseline whose prompt has the wanted lines. */
    private static SealedEvidencePackage learned(Predicate<String> wanted) {
        return InspectionGolden.showcaseSealed().stream().filter(sealed -> wanted.test(sealed.getUserPromptText()))
                .findFirst().orElseThrow();
    }

    /** The package's check result with one drawn line changed. */
    private static PromptInspectionCheckResult check(SealedEvidencePackage sealed, String line, String changed) {
        assertThat(changed).isNotEqualTo(line);
        sealed.setUserPromptText(sealed.getUserPromptText().replace(line, changed));
        sealed.setRawUserPrompt(sealed.getUserPromptText());
        return INSPECTOR.inspect(sealed).checks().get(0);
    }

    @Test
    void thePastRecordStateNamesTheCandidatesTheCountsLineCounts() {
        SealedEvidencePackage sealed = InspectionGolden.showcaseSealed().stream()
                .filter(candidate -> valueOf(candidate.getUserPromptText(), "PastRecordCounts: ").length() > 0
                        && CANDIDATES.matcher(valueOf(candidate.getUserPromptText(), "PastRecordsState: ")).find())
                .findFirst().orElseThrow();
        String text = sealed.getUserPromptText();
        String line = InspectionGolden.lineStarting(text, "PastRecordsState: ");
        Matcher candidates = CANDIDATES.matcher(line);
        assertThat(candidates.find()).isTrue();
        String changed = line.replace(candidates.group(), "of " + (Integer.parseInt(candidates.group(1)) + 7) + " candidates");
        sealed.setUserPromptText(text.replace(line, changed));
        sealed.setRawUserPrompt(sealed.getUserPromptText());

        PromptInspectionFinding finding = single(INSPECTOR.inspect(sealed).checks().get(0));
        assertThat(finding.entry()).isEqualTo("PastRecordsState");
        assertThat(finding.expected()).isEqualTo(candidates.group(1) + " candidates");
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
