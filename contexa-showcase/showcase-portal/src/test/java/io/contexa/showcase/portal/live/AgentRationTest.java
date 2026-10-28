package io.contexa.showcase.portal.live;

import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.concurrent.atomic.AtomicReference;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.offset;

/**
 * docs/agent Agent중심-화면 AC-6: the day's share of live agent runs ("진짜 실행") is what the day's allotment still holds
 * divided by what an agent run costs on average, read from the latest finished runs of visitors; with no such run yet,
 * from a set price. A share below one run means no agent run starts, and the visitor is led to the stored runs.
 */
class AgentRationTest {

    private static final double DEFAULT_UNIT = 0.03;

    @Test
    void theUnitCostIsTheAverageOfTheLatestFinishedAgentRunsAndTheSetPriceWithoutAny() {
        AgentRation none = new AgentRation(() -> 1.0, count -> List.of(), DEFAULT_UNIT);
        AgentRation some = new AgentRation(() -> 1.0, count -> List.of(0.02, 0.04, 0.06, 0.03, 0.05), DEFAULT_UNIT);

        assertThat(none.unitUsd()).isEqualTo(DEFAULT_UNIT);
        assertThat(some.unitUsd()).isCloseTo(0.04, offset(1e-12));
    }

    @Test
    void fewerThanFiveRunsWithACostAreTooFewToTrustSoTheSetPriceCounts() {
        // one cheap run (a case stopped before any analysis) must not make the day's share endless
        AgentRation four = new AgentRation(() -> 1.0, count -> List.of(0.0002, 0.0002, 0.0002, 0.0002), DEFAULT_UNIT);
        AgentRation five = new AgentRation(() -> 1.0, count -> List.of(0.0002, 0.0002, 0.0002, 0.0002, 0.0002),
                DEFAULT_UNIT);

        assertThat(AgentRation.MIN_RUNS).isEqualTo(5);
        assertThat(four.unitUsd()).isEqualTo(DEFAULT_UNIT);
        assertThat(four.ticketsLeft()).isEqualTo(33);
        assertThat(five.unitUsd()).isCloseTo(0.0002, offset(1e-12));
    }

    @Test
    void itAsksForTheLatestTwentyRunsOnly() {
        AtomicReference<Integer> asked = new AtomicReference<>();
        AgentRation ration = new AgentRation(() -> 1.0, count -> {
            asked.set(count);
            return List.of();
        }, DEFAULT_UNIT);

        ration.unitUsd();

        assertThat(asked.get()).isEqualTo(AgentRation.RECENT_RUNS).isEqualTo(20);
    }

    @Test
    void theShareIsWhatTheAllotmentStillHoldsDividedByTheUnitCostRoundedDown() {
        AgentRation ration = new AgentRation(() -> 0.50, count -> List.of(0.04, 0.04, 0.04, 0.04, 0.04), DEFAULT_UNIT);

        assertThat(ration.ticketsLeft()).as("0.50 / 0.04 = 12.5").isEqualTo(12);
    }

    @Test
    void aSpentOrOverspentAllotmentLeavesNoShare() {
        assertThat(new AgentRation(() -> 0.0, count -> List.of(), DEFAULT_UNIT).ticketsLeft()).isZero();
        assertThat(new AgentRation(() -> -0.2, count -> List.of(), DEFAULT_UNIT).ticketsLeft()).isZero();
        assertThat(new AgentRation(() -> 0.029, count -> List.of(), DEFAULT_UNIT).ticketsLeft())
                .as("less than one run's cost").isZero();
        assertThat(new AgentRation(() -> 0.03, count -> List.of(), DEFAULT_UNIT).ticketsLeft()).isEqualTo(1);
    }

    @Test
    void runsThatCostNothingRecordedDoNotMakeTheShareEndless() {
        // a ledger that has not caught up shows zero-cost runs: they are left out, and with none left the set price counts
        AgentRation ration = new AgentRation(() -> 1.0, count -> List.of(0.0, 0.0), DEFAULT_UNIT);

        assertThat(ration.unitUsd()).isEqualTo(DEFAULT_UNIT);
        assertThat(ration.ticketsLeft()).isEqualTo(33);
    }

    @Test
    void aRunWithNoCostYetIsLeftOutOfTheAverage() {
        AgentRation ration = new AgentRation(() -> 1.0, count -> List.of(0.0, 0.04, 0.04, 0.04, 0.04, 0.04), DEFAULT_UNIT);

        assertThat(ration.unitUsd()).isCloseTo(0.04, offset(1e-12));
    }

    @Test
    void anAgentRunMayStartOnlyWhileTheShareHoldsOne() {
        assertThat(new AgentRation(() -> 0.05, count -> List.of(), DEFAULT_UNIT).hasTicket()).isTrue();
        assertThat(new AgentRation(() -> 0.02, count -> List.of(), DEFAULT_UNIT).hasTicket()).isFalse();
    }
}
