package io.contexa.showcase.portal.journey;

import org.junit.jupiter.api.Test;

import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Part 4's wrap-up values (화면재편-구현계획 P-2): the visitor's resend of the timing part states the first request's
 * judgment, when it applied, how long it took, how many records went out before it, and whether the next request was
 * stopped. The values are copied from the stored rows; the sentence is chosen by the dictionary.
 */
class ActEndCardsTest {

    @Test
    void theTimingPartStatesTheFirstRequestsJudgmentAndTheNextRequest() {
        Map<String, Object> values = ActEndCards.timingValues(4831, "ESCALATE", "NEXT_REQUEST", 7382L, 4831L,
                "DENIED");

        assertThat(values).containsEntry("requested", 4831)
                .containsEntry("engineAction", "ESCALATE")
                .containsEntry("applied", "NEXT_REQUEST")
                .containsEntry("analysisMs", 7382L)
                .containsEntry("delivered", 4831L)
                .containsEntry("nextStopped", true);
    }

    @Test
    void aRunWithoutASecondRequestSaysNothingAboutIt() {
        Map<String, Object> values = ActEndCards.timingValues(4831, "ALLOW", "NEXT_REQUEST", 5000L, 4831L, null);

        assertThat(values).containsEntry("nextStopped", null);
        assertThat(ActEndCards.timingValues(4831, "ESCALATE", "NEXT_REQUEST", 5000L, 4831L, "DELIVERED"))
                .containsEntry("nextStopped", false);
    }

    @Test
    void part4StatesTheTimingCase() {
        assertThat(ActEndCards.ACT_CASES).containsEntry(4, "A3A");
    }
}
