package io.contexa.showcase.workload.contexa.observation;

import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

/** Two runs of the same request differ only in run identity and time; their normalised prompts are equal. */
class PromptFingerprintTest {

    private static final String RUN_X = "User v1a2b3c4d5e6f-eng-k in org-1a2b3c4d5e6f tenant-1a2b3c4d5e6f from 10.40.21.37 "
            + "at 2026-09-30T14:20:00Z request 0b6f3c2e-1111-4222-8333-944455556666 observed 1790000000000";
    private static final String RUN_Y = "User v9f8e7d6c5b4a-eng-k in org-9f8e7d6c5b4a tenant-9f8e7d6c5b4a from 10.40.21.201 "
            + "at 2026-09-30T14:21:05Z request 7c1d2e3f-aaaa-4bbb-8ccc-9ddddeeeefff observed 1790000065000";

    @Test
    void runIdentityAndTimeAreNormalisedAwayButTheRequestIsNot() {
        PromptFingerprint.Fingerprint x = PromptFingerprint.of(RUN_X);
        PromptFingerprint.Fingerprint y = PromptFingerprint.of(RUN_Y);

        assertThat(x.normalisedSha256()).isEqualTo(y.normalisedSha256());
        assertThat(x.principals()).containsExactly("v1a2b3c4d5e6f-eng-k");
        assertThat(PromptFingerprint.of(RUN_X.replace("eng-k", "adm-a")).normalisedSha256())
                .as("a different employee is a different context").isNotEqualTo(x.normalisedSha256());
        assertThat(PromptFingerprint.of(RUN_X.replace("10.40.21.37", "10.40.22.37")).normalisedSha256())
                .as("a different network is a different context").isNotEqualTo(x.normalisedSha256());
    }

    @Test
    void theSessionIdAndTheWallClockMinuteOfTheSignInAreNormalisedButTheCompanyTimeIsNot() {
        String x = "SessionId: 90363D2E358ABE8C5428F12C8F6A043C\n"
                + "  RecentSessionActionSample: 00:57 | MFA_COMPLETED (Zero Trust Challenge verified) | 10.40.21.x | 14:20 | GET /a";
        String y = "SessionId: B1077542FC3E7F950CAABEBB6037DA65\n"
                + "  RecentSessionActionSample: 00:58 | MFA_COMPLETED (Zero Trust Challenge verified) | 10.40.21.x | 14:20 | GET /a";

        assertThat(PromptFingerprint.of(x).normalisedSha256()).isEqualTo(PromptFingerprint.of(y).normalisedSha256());
        assertThat(PromptFingerprint.of(y.replace("14:20", "03:17")).normalisedSha256())
                .as("the observed request time is part of the context").isNotEqualTo(PromptFingerprint.of(x).normalisedSha256());
    }

    @Test
    void anotherRunsPrincipalInAPromptIsVisible() {
        assertThat(PromptFingerprint.of(RUN_X + " memory of v9f8e7d6c5b4a-eng-k").principals())
                .containsExactly("v1a2b3c4d5e6f-eng-k", "v9f8e7d6c5b4a-eng-k");
    }
}
