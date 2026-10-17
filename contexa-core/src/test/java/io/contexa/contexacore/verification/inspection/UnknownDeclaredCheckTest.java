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

    /**
     * N-INS-3: a word in a kind's place starts its part even when the render does not write it, so the names after it
     * are not read as names of the kind before it, nor its words as names.
     */
    @Test
    void theNamesAfterAKindWordTheRenderDoesNotWriteAreNotReadUnderTheKindBeforeIt() {
        assertThat(UnknownDeclaredCheck.parse("not-integrated: [U1] ClientSignals; not-applicable: Delegation"))
                .containsOnlyKeys("ClientSignals", "Delegation");
        assertThat(UnknownDeclaredCheck.declaredNames("unavailable-now: [U1] PastRecord (not retrieved, TIMEOUT); "
                + "not-applicable: Delegation")).containsExactly("PastRecord", "Delegation");
    }
}
