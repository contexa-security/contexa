package io.contexa.contexacore.autonomous.tiered.prompt;

import io.contexa.contexacore.autonomous.store.SessionDecisionRecord;
import io.contexa.contexacore.verification.inspection.FactAccuracyCheck;
import org.junit.jupiter.api.Test;

import java.lang.reflect.Method;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.Arrays;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

/** The session line values the render and the inspector share (P3-EXTRA-13, P3-EXTRA-34). */
class SessionLineValuesTest {

    private static final Instant NINE = Instant.parse("2026-10-14T09:00:00Z");

    /** P3-EXTRA-13: a denial without a method names its time and target only, never the word null. */
    @Test
    void aDenialWithoutAMethodNamesItsTimeAndTargetOnly() {
        SessionDecisionRecord withoutMethod = new SessionDecisionRecord(NINE, null, "/api/x", null, null,
                SessionDecisionRecord.AUTHORIZATION_DENIED);

        assertThat(SessionLineValues.recentDenied(List.of(withoutMethod), null, ZoneOffset.UTC))
                .isEqualTo("1 denied in this session (09:00 /api/x)");
    }

    /** P3-EXTRA-34: the session's type is trimmed, and a blank or equal type adds nothing to the head. */
    @Test
    void theLoginMethodHeadTrimsTheSessionsType() {
        assertThat(SessionLineValues.loginMethodHead("PASSWORD", "", null)).isEqualTo("PASSWORD");
        assertThat(SessionLineValues.loginMethodHead("PASSWORD", " PASSWORD ", null)).isEqualTo("PASSWORD");
        assertThat(SessionLineValues.loginMethodHead("PASSWORD", " TOKEN ", " HIGH "))
                .isEqualTo("PASSWORD (TOKEN) (assurance HIGH)");
    }

    /** The inspector keeps no copy of these two values: it reads them from the shared values (P3-CHANGE-36, 37). */
    @Test
    void theInspectorKeepsNoCopyOfTheSharedSessionValues() {
        assertThat(Arrays.stream(FactAccuracyCheck.class.getDeclaredMethods()).map(Method::getName))
                .doesNotContain("recentDenied", "clock");
    }
}
