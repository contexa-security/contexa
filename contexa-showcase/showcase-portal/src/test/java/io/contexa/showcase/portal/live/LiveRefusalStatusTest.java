package io.contexa.showcase.portal.live;

import org.junit.jupiter.api.Test;
import org.springframework.http.HttpStatus;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * The HTTP status of each reason the live gate refuses a start. Every limit a visitor can reach answers "too many
 * requests", so the screen says the day's sends are used up and not that something broke (docs/agent Agent중심-화면
 * AC-2 added the agent limit; the real-server check of 2026-10-27 found it answered as a forbidden request).
 */
class LiveRefusalStatusTest {

    @Test
    void everyLimitOfAVisitorAnswersTooManyRequests() {
        for (String reason : new String[]{"VISITOR_LIMIT", "ADDRESS_LIMIT", "AGENT_LIMIT"}) {
            assertThat(LiveController.statusOf(reason)).as(reason).isEqualTo(HttpStatus.TOO_MANY_REQUESTS);
        }
    }

    @Test
    void theOtherReasonsKeepTheirStatus() {
        assertThat(LiveController.statusOf("ALLOTMENT")).isEqualTo(HttpStatus.SERVICE_UNAVAILABLE);
        assertThat(LiveController.statusOf("TEMPLATE")).isEqualTo(HttpStatus.SERVICE_UNAVAILABLE);
        assertThat(LiveController.statusOf("BUSY")).isEqualTo(HttpStatus.CONFLICT);
        assertThat(LiveController.statusOf("AGENT_BUSY")).as("the agent runs at once are full: try again shortly")
                .isEqualTo(HttpStatus.CONFLICT);
        assertThat(LiveController.statusOf("TURNSTILE_MISSING")).isEqualTo(HttpStatus.FORBIDDEN);
    }
}
