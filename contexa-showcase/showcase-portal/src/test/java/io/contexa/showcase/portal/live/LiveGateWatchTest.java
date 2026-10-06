package io.contexa.showcase.portal.live;

import ch.qos.logback.classic.Level;
import ch.qos.logback.classic.Logger;
import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.core.read.ListAppender;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.slf4j.LoggerFactory;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneId;
import java.time.ZoneOffset;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

/** P5-SEC-07: the gate's refusals by reason, and one error log in an hour whose refusals reach the alert level. */
class LiveGateWatchTest {

    private final ListAppender<ILoggingEvent> logs = new ListAppender<>();
    private final Logger logger = (Logger) LoggerFactory.getLogger(LiveGateWatch.class);

    @BeforeEach
    void listen() {
        logs.start();
        logger.addAppender(logs);
    }

    @AfterEach
    void stopListening() {
        logger.detachAppender(logs);
    }

    @Test
    void aBurstOfRefusalsLogsOneErrorInTheHourAndTheNextHourStartsAgain() {
        MovingClock clock = new MovingClock(Instant.parse("2026-10-05T09:10:00Z"));
        LiveGateWatch watch = new LiveGateWatch(3, clock);

        watch.passed(LiveGateWatch.RESUMED);
        watch.passed(LiveGateWatch.STARTED);
        watch.refused("TURNSTILE_FAILED");
        watch.refused("VISITOR_LIMIT");
        assertThat(errors()).isZero();
        watch.refused("TURNSTILE_FAILED");
        watch.refused("ADDRESS_LIMIT");

        LiveGateWatch.Status hour = watch.status();
        assertThat(errors()).isEqualTo(1);
        assertThat(logs.list.get(0).getFormattedMessage())
                .contains("refused 3 new runs", "TURNSTILE_FAILED=2", "VISITOR_LIMIT=1");
        assertThat(hour.alertedThisHour()).isTrue();
        assertThat(hour.refusalsInHour()).isEqualTo(4);
        assertThat(hour.refusalsThisHour()).isEqualTo(Map.of("TURNSTILE_FAILED", 2L, "VISITOR_LIMIT", 1L,
                "ADDRESS_LIMIT", 1L));
        assertThat(hour.hourStart()).isEqualTo(Instant.parse("2026-10-05T09:00:00Z"));

        clock.advance(Duration.ofMinutes(55));
        LiveGateWatch.Status next = watch.status();
        assertThat(next.refusalsInHour()).isZero();
        assertThat(next.alertedThisHour()).isFalse();
        assertThat(next.outcomes()).isEqualTo(Map.of("RESUMED", 1L, "STARTED", 1L, "TURNSTILE_FAILED", 2L,
                "VISITOR_LIMIT", 1L, "ADDRESS_LIMIT", 1L));
        watch.refused("BUSY");
        watch.refused("BUSY");
        watch.refused("BUSY");
        assertThat(errors()).isEqualTo(2);
    }

    private long errors() {
        return logs.list.stream().filter(event -> event.getLevel() == Level.ERROR).count();
    }

    private static final class MovingClock extends Clock {
        private Instant now;

        MovingClock(Instant now) {
            this.now = now;
        }

        void advance(Duration duration) {
            now = now.plus(duration);
        }

        @Override
        public ZoneId getZone() {
            return ZoneOffset.UTC;
        }

        @Override
        public Clock withZone(ZoneId zone) {
            return this;
        }

        @Override
        public Instant instant() {
            return now;
        }
    }
}
