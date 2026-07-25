package io.contexa.contexacore.verification.runtime;

import java.util.Locale;

/**
 * Maps persisted verification states to presentation-only values.
 */
public record OfficialVerificationRunPresentation(
        String tone,
        String eventStatus,
        boolean successful,
        boolean notApplicable) {

    public static OfficialVerificationRunPresentation fromState(String state) {
        String normalized = normalize(state);
        return switch (normalized) {
            case "SUCCESS", "PASSED" -> new OfficialVerificationRunPresentation("success", "PASS", true, false);
            case "NOT_APPLICABLE" -> new OfficialVerificationRunPresentation("warning", "NOT_APPLICABLE", false, true);
            case "NOT_EVALUATED_INPUT_INVALID" -> new OfficialVerificationRunPresentation(
                    "warning", "NOT_EVALUATED_INPUT_INVALID", false, true);
            case "INSUFFICIENT" -> new OfficialVerificationRunPresentation("warning", "BLOCKED", false, false);
            default -> new OfficialVerificationRunPresentation("danger", "BLOCKED", false, false);
        };
    }

    public static boolean insufficient(String state) {
        return "INSUFFICIENT".equals(normalize(state));
    }

    private static String normalize(String state) {
        return state == null ? "" : state.trim().toUpperCase(Locale.ROOT);
    }
}
