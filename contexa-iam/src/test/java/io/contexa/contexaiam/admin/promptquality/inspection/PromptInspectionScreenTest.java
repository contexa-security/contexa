package io.contexa.contexaiam.admin.promptquality.inspection;

import io.contexa.contexacore.verification.inspection.DecisionFactMatchCheck;
import io.contexa.contexacore.verification.inspection.DictionaryContractCheck;
import io.contexa.contexacore.verification.inspection.FactAccuracyCheck;
import io.contexa.contexacore.verification.inspection.PastRecordNotationCheck;
import io.contexa.contexacore.verification.inspection.SameFactCheck;
import io.contexa.contexacore.verification.inspection.PromptInspectionVerdict;
import io.contexa.contexacore.verification.inspection.SealIntegrityCheck;
import io.contexa.contexacore.verification.inspection.UnknownDeclaredCheck;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.LinkedHashSet;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * The inspection screens' lists and defaults in one place (R1b-3): every verdict once with what needs work first, one
 * chip tone per verdict, the codes of the checks, the last seven days and twenty packages a page; the screen
 * template, scripts and style sheet take them from there and hold no copy of their own.
 */
class PromptInspectionScreenTest {

    private static final String ROOT = "static/contexa/js/admin/prompt-inspection/";

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

    @Test
    void theScreensOfferTheCodesTheChecksDeclare() {
        assertThat(PromptInspectionScreen.CHECKS).containsExactly(SealIntegrityCheck.CODE, BundleTraceCheck.CODE,
                DictionaryContractCheck.CODE, DecisionFactMatchCheck.CODE, FactAccuracyCheck.CODE,
                UnknownDeclaredCheck.CODE, PastRecordNotationCheck.CODE, SameFactCheck.CODE);
    }

    @Test
    void theDefaultPeriodIsTheLastSevenDaysAndAPageHoldsTwentyPackages() {
        assertThat(PromptInspectionScreen.DEFAULT_PERIOD).isEqualTo(Duration.ofDays(7));
        assertThat(Integer.parseInt(PromptInspectionScreen.DEFAULT_PAGE_SIZE)).isEqualTo(20);
    }

    @Test
    void theScreenSourcesHoldNoCopyOfTheListsOrTheDefaults() throws IOException {
        String packages = resource("templates/contexa/admin/prompt-inspection/packages.html");
        for (String code : PromptInspectionScreen.VERDICTS) {
            assertThat(packages).doesNotContain("value=\"" + code + "\"");
        }
        for (String code : PromptInspectionScreen.CHECKS) {
            assertThat(packages).doesNotContain("value=\"" + code + "\"");
        }
        assertThat(packages).contains("th:each=\"verdict : ${verdicts}\"").contains("th:each=\"check : ${checks}\"");

        String scripts = resource(ROOT + "prompt-inspection-common.js") + resource(ROOT + "overview-page.js")
                + resource(ROOT + "packages-page.js");
        assertThat(scripts).doesNotContain("'NOT_INSPECTED'").doesNotContain("PAGE_SIZE = 20")
                .doesNotContain("6 * 24 * 3600");

        String style = resource("static/contexa/css/admin/prompt-inspection/prompt-inspection.css");
        for (String tone : new LinkedHashSet<>(PromptInspectionScreen.TONES.values())) {
            assertThat(style).contains(".pi-chip-" + tone);
        }
        assertThat(style).doesNotContain(".pi-chip-pass").doesNotContain(".pi-chip-fail")
                .doesNotContain(".pi-chip-incomplete");
    }

    private static String resource(String path) throws IOException {
        try (InputStream in = PromptInspectionScreenTest.class.getClassLoader().getResourceAsStream(path)) {
            assertThat(in).as(path).isNotNull();
            return new String(in.readAllBytes(), StandardCharsets.UTF_8);
        }
    }
}
