package io.contexa.contexaiam.admin.promptquality.inspection;

import io.contexa.contexacore.verification.inspection.DecisionFactMatchCheck;
import io.contexa.contexacore.verification.inspection.DictionaryContractCheck;
import io.contexa.contexacore.verification.inspection.FactAccuracyCheck;
import io.contexa.contexacore.verification.inspection.PastRecordNotationCheck;
import io.contexa.contexacore.verification.inspection.SameFactCheck;
import io.contexa.contexacore.verification.inspection.PromptInspectionVerdict;
import io.contexa.contexacore.verification.inspection.ReasonMatchCheck;
import io.contexa.contexacore.verification.inspection.SealIntegrityCheck;
import io.contexa.contexacore.verification.inspection.UnknownDeclaredCheck;

import java.time.Duration;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * The inspection screens' lists and defaults, kept in one place for the page controller, the API and the screen
 * scripts: the verdicts and the checks the screens offer, the tone of each verdict's chip, the default capture period
 * and the page size (R1b-3).
 */
public final class PromptInspectionScreen {

    /** Every verdict a package can show, in the order the screens list them: what needs work first. */
    public static final List<String> VERDICTS = List.of(PromptInspectionVerdict.FAIL.name(),
            PromptInspectionVerdict.INCOMPLETE.name(), PromptInspectionVerdict.PASS.name(),
            PromptInspectionVerdict.NOT_APPLICABLE.name(), PromptInspectionVerdict.ERROR.name(),
            JdbcPromptInspectionQueries.NOT_INSPECTED);

    /** The codes of the checks the inspector runs, in the order the screens offer them. */
    public static final List<String> CHECKS = List.of(SealIntegrityCheck.CODE, BundleTraceCheck.CODE,
            DictionaryContractCheck.CODE, DecisionFactMatchCheck.CODE, FactAccuracyCheck.CODE,
            UnknownDeclaredCheck.CODE, PastRecordNotationCheck.CODE, SameFactCheck.CODE, ReasonMatchCheck.CODE);

    /** The tone of each verdict's chip; a finding's outcome chip takes the tone of the same name. */
    public static final Map<String, String> TONES = tones();

    /** The capture period the screens and the API show when none is given. */
    public static final Duration DEFAULT_PERIOD = Duration.ofDays(7);

    /** The packages a list page holds when no size is given (a request parameter default, so a text). */
    public static final String DEFAULT_PAGE_SIZE = "20";

    private PromptInspectionScreen() {
    }

    private static Map<String, String> tones() {
        Map<String, String> tones = new LinkedHashMap<>();
        tones.put(PromptInspectionVerdict.FAIL.name(), "mismatch");
        tones.put(PromptInspectionVerdict.INCOMPLETE.name(), "unverifiable");
        tones.put(PromptInspectionVerdict.PASS.name(), "matched");
        tones.put(PromptInspectionVerdict.NOT_APPLICABLE.name(), "neutral");
        tones.put(PromptInspectionVerdict.ERROR.name(), "error");
        tones.put(JdbcPromptInspectionQueries.NOT_INSPECTED, "neutral");
        return Map.copyOf(tones);
    }

    /** What the screen scripts take from here, as one object. */
    static Map<String, Object> scriptSettings() {
        Map<String, Object> settings = new LinkedHashMap<>();
        settings.put("verdicts", VERDICTS);
        settings.put("notInspected", JdbcPromptInspectionQueries.NOT_INSPECTED);
        settings.put("tones", TONES);
        settings.put("periodDays", DEFAULT_PERIOD.toDays());
        settings.put("pageSize", Integer.parseInt(DEFAULT_PAGE_SIZE));
        return settings;
    }
}
