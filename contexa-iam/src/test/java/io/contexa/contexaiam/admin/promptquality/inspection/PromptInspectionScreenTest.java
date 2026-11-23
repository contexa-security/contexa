package io.contexa.contexaiam.admin.promptquality.inspection;

import io.contexa.contexacore.verification.inspection.PromptInspectionCheck;
import io.contexa.contexacore.verification.inspection.PromptInspector;
import io.contexa.contexacore.verification.inspection.PromptInspectionVerdict;
import io.contexa.contexacore.verification.inspection.SealIntegrityCheck;
import io.contexa.contexacore.verification.inspection.SourceTruthCheck;
import org.junit.jupiter.api.Test;

import java.time.Duration;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * The inspection screens' lists and defaults in one place (R1b-3): every verdict once with what needs work first, one
 * chip tone per verdict, the codes of the checks, the last seven days and twenty packages a page. The sealed evidence
 * and its API read them; the sealed prompt screens that drew them went (P50).
 */
class PromptInspectionScreenTest {

    @Test
    void theScreensOfferEveryVerdictOnceWhatNeedsWorkFirst() {
        List<String> expected = new ArrayList<>(Arrays.stream(PromptInspectionVerdict.values()).map(Enum::name).toList());
        expected.add(JdbcPromptInspectionQueries.NOT_INSPECTED);

        assertThat(PromptInspectionScreen.VERDICTS).containsExactlyInAnyOrderElementsOf(expected)
                .startsWith(PromptInspectionVerdict.FAIL.name(), PromptInspectionVerdict.INCOMPLETE.name());
    }

    @Test
    void everyVerdictHasOneChipTone() {
        assertThat(PromptInspectionScreen.TONES).containsOnlyKeys(PromptInspectionScreen.VERDICTS)
                .containsEntry("PASS", "matched").containsEntry("FAIL", "mismatch")
                .containsEntry("INCOMPLETE", "unverifiable").containsEntry("ERROR", "error")
                .containsEntry("NOT_APPLICABLE", "neutral").containsEntry(JdbcPromptInspectionQueries.NOT_INSPECTED, "neutral");
    }

    /**
     * The screens offer the codes of the checks the inspector runs, in its order: the core checks with the bundle trace
     * second and the source comparison last (PromptInspectionAutoConfiguration), the evidence audit of plan 2.1 of the
     * prompt quality redesign. A check added to the inspector shows on the screens with its name (W4-8 added REASON_MATCH
     * to the inspector, and the screens drew its message key; N-UI-3: the source comparison was added without, and the
     * detail screen showed its key). The checks the inspector no longer runs keep their names for the stored results.
     */
    @Test
    void theScreensOfferTheCodesTheChecksDeclare() {
        List<String> run = new ArrayList<>(PromptInspector.coreChecks().stream()
                .map(PromptInspectionCheck::code).toList());
        run.add(1, BundleTraceCheck.CODE);
        run.add(SourceTruthCheck.CODE);
        assertThat(PromptInspectionScreen.CHECKS).containsExactlyElementsOf(run)
                .containsExactly(SealIntegrityCheck.CODE, BundleTraceCheck.CODE, SourceTruthCheck.CODE);
        assertThat(PromptInspectionScreen.RETIRED_CHECKS).doesNotContainAnyElementsOf(PromptInspectionScreen.CHECKS)
                .containsExactly("DICTIONARY_CONTRACT", "DECISION_FACT_MATCH", "FACT_ACCURACY", "UNKNOWN_DECLARED",
                        "PAST_RECORD_NOTATION", "SAME_FACT", "REASON_MATCH");
    }

    @Test
    void theDefaultPeriodIsTheLastSevenDaysAndAPageHoldsTwentyPackages() {
        assertThat(PromptInspectionScreen.DEFAULT_PERIOD).isEqualTo(Duration.ofDays(7));
        assertThat(Integer.parseInt(PromptInspectionScreen.DEFAULT_PAGE_SIZE)).isEqualTo(20);
    }

}
