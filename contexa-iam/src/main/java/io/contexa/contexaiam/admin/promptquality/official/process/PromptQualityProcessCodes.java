package io.contexa.contexaiam.admin.promptquality.official.process;

import java.util.List;

public final class PromptQualityProcessCodes {

    public static final String MAIN = "PROMPT_QUALITY_ASSURANCE";

    public static final String PROTECTABLE_RESOURCES = "PROTECTABLE_RESOURCES";
    public static final String RUNTIME_EVIDENCE = "RUNTIME_EVIDENCE";
    public static final String OFFICIAL_VERIFICATION = "OFFICIAL_VERIFICATION";
    public static final String REMEDIATION = "REMEDIATION";
    public static final String PROMPT_GOVERNANCE = "PROMPT_GOVERNANCE";
    public static final String REVERIFICATION = "REVERIFICATION";
    public static final String CERTIFICATES_PROMOTION = "CERTIFICATES_PROMOTION";
    public static final String MONITORING = "MONITORING";
    public static final String AUDIT_REPORTS = "AUDIT_REPORTS";

    public static final String PENDING = "PENDING";
    public static final String RUNNING = "RUNNING";
    public static final String COMPLETED = "COMPLETED";
    public static final String FAILED = "FAILED";

    public static final List<String> ORDERED_STEPS = List.of(
            PROTECTABLE_RESOURCES,
            RUNTIME_EVIDENCE,
            OFFICIAL_VERIFICATION,
            REMEDIATION,
            PROMPT_GOVERNANCE,
            REVERIFICATION,
            CERTIFICATES_PROMOTION,
            MONITORING,
            AUDIT_REPORTS
    );

    private PromptQualityProcessCodes() {
    }
}
