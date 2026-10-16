package io.contexa.contexacore.verification.inspection;

import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

class UnknownDeclaredCheckTest {

    /** N-UID-1 (Q-87): the UNKNOWN line is read by its names, with or without the IDs in front of them. */
    @Test
    void theUnknownLineIsReadByItsNamesWithOrWithoutTheirIds() {
        assertThat(UnknownDeclaredCheck.parse("not-integrated: [U1] ClientSignals, [U2] PeerCohort; unavailable-now: "
                + "[U3] PastRecord (not retrieved, TIMEOUT)"))
                .containsOnlyKeys("ClientSignals", "PeerCohort", "PastRecord");
        assertThat(UnknownDeclaredCheck.parse("not-integrated: ClientSignals; unavailable-now: PastRecord (not retrieved, "
                + "TIMEOUT)"))
                .containsOnlyKeys("ClientSignals", "PastRecord");
    }
}
