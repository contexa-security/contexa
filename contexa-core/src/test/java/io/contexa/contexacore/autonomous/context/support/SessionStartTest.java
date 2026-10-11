package io.contexa.contexacore.autonomous.context.support;

import io.contexa.contexacommon.domain.SecurityEvent;
import org.junit.jupiter.api.Test;

import java.time.Instant;

import static org.assertj.core.api.Assertions.assertThat;

/** W1-10: a session starts at its sign-in, else at its creation, else at its first analysed request. */
class SessionStartTest {

    @Test
    void theSignInComesFirst() {
        SecurityEvent event = SecurityEvent.builder().build();
        event.addMetadata("authenticationTime", "2026-09-30T14:00:00Z");
        event.addMetadata("sessionCreatedAt", "2026-09-30T13:59:00Z");

        assertThat(SessionStart.of(event))
                .isEqualTo(new SessionStart(Instant.parse("2026-09-30T14:00:00Z"), SessionStart.LOGIN));
    }

    @Test
    void theSessionCreationIsTheNextBasis() {
        SecurityEvent event = SecurityEvent.builder().build();
        event.addMetadata("sessionCreatedAt", "2026-09-30T13:59:00Z");

        assertThat(SessionStart.of(event))
                .isEqualTo(new SessionStart(Instant.parse("2026-09-30T13:59:00Z"), SessionStart.SESSION_CREATED));
    }

    @Test
    void withNeitherTheCallerStartsAtTheFirstAnalysedRequest() {
        SecurityEvent event = SecurityEvent.builder().build();
        event.addMetadata("authenticationTime", "not a time");

        assertThat(SessionStart.of(event)).isNull();
        assertThat(SessionStart.of(null)).isNull();
    }
}
