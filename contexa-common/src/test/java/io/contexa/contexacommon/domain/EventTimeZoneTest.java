package io.contexa.contexacommon.domain;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;

import java.time.Instant;
import java.time.LocalDateTime;
import java.time.ZoneId;

import static org.assertj.core.api.Assertions.assertThat;

class EventTimeZoneTest {

    @AfterEach
    void clear() {
        EventTimeZone.set(null);
    }

    @Test
    void readsAnInstantInTheConfiguredTimeZone() {
        EventTimeZone.set(ZoneId.of("Asia/Seoul"));

        assertThat(EventTimeZone.toLocal(Instant.parse("2026-09-30T03:17:00Z")))
                .isEqualTo(LocalDateTime.of(2026, 9, 30, 12, 17));
        assertThat(SecurityEvent.builder().timestamp(Instant.parse("2026-09-30T03:17:00Z")).build().getLocalTimestamp())
                .isEqualTo(LocalDateTime.of(2026, 9, 30, 12, 17));
    }

    @Test
    void readsInTheSystemTimeZoneWithoutConfiguration() {
        Instant instant = Instant.parse("2026-09-30T03:17:00Z");

        assertThat(EventTimeZone.get()).isEqualTo(ZoneId.systemDefault());
        assertThat(EventTimeZone.toLocal(instant)).isEqualTo(LocalDateTime.ofInstant(instant, ZoneId.systemDefault()));
        assertThat(EventTimeZone.toLocal(null)).isNull();
    }
}
