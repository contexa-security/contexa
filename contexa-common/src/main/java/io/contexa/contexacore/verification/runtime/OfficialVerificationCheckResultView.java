package io.contexa.contexacore.verification.runtime;

public interface OfficialVerificationCheckResultView {

    default String checkCode() {
        return label();
    }

    String label();

    String expectedValue();

    String actualValue();

    boolean pass();

    String source();

    default String severity() {
        return pass() ? "INFO" : "BLOCKING";
    }

    default String failureType() {
        return pass() ? "" : "OFFICIAL_CHECK_FAILED";
    }

    default String remediationOwner() {
        return "PQA_RUNTIME";
    }

    default String operatorReason() {
        return "";
    }

    default String nextAction() {
        return "";
    }

    default String reverifyCriterion() {
        return "";
    }

    default String issueKey() {
        return source();
    }

    default boolean customerVisible() {
        String source = source();
        return source == null || !source.startsWith("internalGate.");
    }

    default String readinessScope() {
        return customerVisible() ? "CUSTOMER_PROMPT_QUALITY" : "INTERNAL_EXECUTION_GATE";
    }

    default String purposeVersion() {
        return "";
    }

    default String inputReadinessState() {
        return "READY";
    }

    default String purposeResult() {
        return pass() ? "PASSED" : "FAILED";
    }

    default String detectedSignalsJson() {
        return "[]";
    }

    default String interpretationLinksJson() {
        return "[]";
    }

    default String decisionUtility() {
        return "";
    }

    default String whyItMatters() {
        return "";
    }
}
