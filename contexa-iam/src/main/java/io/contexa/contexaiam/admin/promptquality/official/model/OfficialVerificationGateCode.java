package io.contexa.contexaiam.admin.promptquality.official.model;

import java.util.Locale;

public enum OfficialVerificationGateCode {
    PACKAGE_ID,
    SEALED_EVIDENCE,
    EVIDENCE_INTEGRITY,
    RESOURCE_PATH,
    RESOURCE_ID,
    HTTP_METHOD,
    RAW_SYSTEM_PROMPT,
    RAW_USER_PROMPT,
    FINAL_LLM_PROMPT,
    PROMPT_HASH,
    /**
     * No longer evaluated: it compared the sealed prompt hash with the same hash carried by the replay, so it always
     * passed. The deterministic replay checks decide replay (DETERMINISTIC_REPLAY). Kept for stored verdicts.
     */
    REPLAY_HASH,
    GOVERNANCE_DESCRIPTOR,
    PROMPT_EVIDENCE_MANIFEST,
    PROMPT_SCORECARD,
    DETERMINISTIC_REPLAY,
    REQUIRED_METRICS,
    METRIC_RESULTS,
    PROMPT_CONSISTENCY,
    POLICY_CONTRACT,
    UNCLASSIFIED;

    public String messageKey() {
        return "official.verification.gate."
                + name().toLowerCase(Locale.ROOT).replace('_', '.');
    }
}
