package io.contexa.contexacore.verification.runtime;

import java.util.Locale;

/**
 * Canonical persisted and API state for one official verification check.
 */
public enum OfficialVerificationCheckState {
    PASS,
    FAIL,
    NOT_APPLICABLE,
    NOT_EVALUATED;

    public static OfficialVerificationCheckState resolve(
            String inputReadinessState,
            String purposeResult,
            boolean legacyPass) {
        String readiness = normalize(inputReadinessState);
        String purpose = normalize(purposeResult);
        if ("NOT_APPLICABLE".equals(readiness) || "NOT_APPLICABLE".equals(purpose)) {
            return NOT_APPLICABLE;
        }
        if (!"READY".equals(readiness)
                || (!isPassedPurpose(purpose) && !isFailedPurpose(purpose))) {
            return NOT_EVALUATED;
        }
        if (isPassedPurpose(purpose)) {
            return legacyPass ? PASS : FAIL;
        }
        return FAIL;
    }

    private static boolean isPassedPurpose(String purpose) {
        return "PASS".equals(purpose)
                || "PASSED".equals(purpose)
                || "PURPOSE_PASSED".equals(purpose);
    }

    private static boolean isFailedPurpose(String purpose) {
        return "FAIL".equals(purpose)
                || "FAILED".equals(purpose)
                || "PURPOSE_FAILED".equals(purpose);
    }

    private static String normalize(String value) {
        return value == null ? "" : value.trim().toUpperCase(Locale.ROOT);
    }
}
