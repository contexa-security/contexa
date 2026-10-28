package io.contexa.showcase.portal.menu;

import org.junit.jupiter.api.Test;

import java.time.Duration;
import java.time.Instant;
import java.time.LocalTime;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * docs/agent Agent중심-화면 AC-4a: the agent menu's daily refresh runs once a day at a set UTC time (04:30 unless
 * configured), after the retention pass, and the first run waits for the next such time, never for the one just gone.
 */
class AgentMenuConfigurationTest {

    private static final LocalTime AT = LocalTime.of(4, 30);

    @Test
    void theFirstRunWaitsForTheNextTimeOfDay() {
        assertThat(AgentMenuConfiguration.untilNext(Instant.parse("2026-10-27T04:00:00Z"), AT))
                .isEqualTo(Duration.ofMinutes(30));
        assertThat(AgentMenuConfiguration.untilNext(Instant.parse("2026-10-27T05:00:00Z"), AT))
                .isEqualTo(Duration.ofHours(23).plusMinutes(30));
    }

    @Test
    void atTheTimeItselfTheNextRunIsTomorrow() {
        assertThat(AgentMenuConfiguration.untilNext(Instant.parse("2026-10-27T04:30:00Z"), AT))
                .isEqualTo(Duration.ofDays(1));
    }

    @Test
    void aTimeOfDayAcrossMidnightIsTheNextDaysOne() {
        assertThat(AgentMenuConfiguration.untilNext(Instant.parse("2026-10-27T23:00:00Z"), LocalTime.of(0, 15)))
                .isEqualTo(Duration.ofMinutes(75));
    }
}
