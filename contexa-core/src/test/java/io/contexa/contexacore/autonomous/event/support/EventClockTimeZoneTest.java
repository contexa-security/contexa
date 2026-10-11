package io.contexa.contexacore.autonomous.event.support;

import io.contexa.contexacommon.domain.EventTimeZone;
import io.contexa.contexacommon.domain.SecurityEvent;
import io.contexa.contexacore.autonomous.context.collector.DefaultSessionNarrativeCollector;
import io.contexa.contexacore.autonomous.context.collector.SessionNarrativeSnapshot;
import io.contexa.contexacore.autonomous.event.domain.ZeroTrustEventCategory;
import io.contexa.contexacore.autonomous.event.domain.ZeroTrustSpringEvent;
import io.contexa.contexacore.autonomous.store.InMemorySecurityContextDataStore;
import io.contexa.contexacore.properties.SecurityPlaneProperties;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import java.time.DateTimeException;
import java.time.DayOfWeek;
import java.time.Instant;
import java.time.LocalDateTime;
import java.time.ZoneId;
import java.util.TimeZone;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/** W1-7: the same request reads the same in a JVM running in Seoul time and in one running in UTC. */
class EventClockTimeZoneTest {

    private static final Instant OBSERVED = Instant.parse("2026-09-30T03:17:00Z");

    private TimeZone jvmZone;

    @BeforeEach
    void remember() {
        jvmZone = TimeZone.getDefault();
    }

    @AfterEach
    void restore() {
        TimeZone.setDefault(jvmZone);
        EventTimeZone.set(null);
    }

    @ParameterizedTest
    @ValueSource(strings = {"Asia/Seoul", "UTC"})
    @DisplayName("the request is read at the company time whatever the JVM time zone is")
    void readsTheCompanyTimeInAnyJvmZone(String jvm) {
        TimeZone.setDefault(TimeZone.getTimeZone(jvm));
        EventTimeZone.set(ZoneId.of("UTC"));

        SecurityEvent event = ZeroTrustSecurityEventConverter.convert(ZeroTrustSpringEvent.builder(this)
                .category(ZeroTrustEventCategory.AUTHORIZATION)
                .eventType(ZeroTrustSpringEvent.TYPE_AUTHORIZATION_METHOD)
                .userId("adm-a")
                .eventTimestamp(OBSERVED)
                .build());

        assertThat(event.getTimestamp()).isEqualTo(OBSERVED);
        assertThat(event.getLocalTimestamp()).isEqualTo(LocalDateTime.of(2026, 9, 30, 3, 17));
        assertThat(event.getLocalTimestamp().getDayOfWeek()).isEqualTo(DayOfWeek.WEDNESDAY);
    }

    @ParameterizedTest
    @ValueSource(strings = {"Asia/Seoul", "UTC"})
    @DisplayName("session age and request interval are measured on the event clock")
    void measuresTheSessionOnTheEventClock(String jvm) {
        TimeZone.setDefault(TimeZone.getTimeZone(jvm));
        DefaultSessionNarrativeCollector collector = new DefaultSessionNarrativeCollector(new InMemorySecurityContextDataStore());

        collector.collect(read("session-7", OBSERVED));
        SessionNarrativeSnapshot snapshot = collector.collect(read("session-7", OBSERVED.plusSeconds(240))).orElseThrow();

        assertThat(snapshot.getSessionAgeMinutes()).isEqualTo(4);
        assertThat(snapshot.getLastRequestIntervalMs()).isEqualTo(240_000L);
    }

    @Test
    @DisplayName("the registrar sets the configured company time zone and clears it when the context closes")
    void registrarSetsAndClearsTheCompanyTimeZone() {
        SecurityPlaneProperties properties = new SecurityPlaneProperties();
        properties.getContext().setTimeZone("Asia/Seoul");
        EventTimeZoneRegistrar registrar = new EventTimeZoneRegistrar(properties);

        registrar.afterPropertiesSet();
        assertThat(EventTimeZone.get()).isEqualTo(ZoneId.of("Asia/Seoul"));

        registrar.destroy();
        assertThat(EventTimeZone.get()).isEqualTo(ZoneId.systemDefault());
    }

    @Test
    @DisplayName("an unknown time zone id fails the start")
    void unknownTimeZoneFailsTheStart() {
        SecurityPlaneProperties properties = new SecurityPlaneProperties();
        properties.getContext().setTimeZone("Mars/Olympus");

        assertThatThrownBy(() -> new EventTimeZoneRegistrar(properties).afterPropertiesSet())
                .isInstanceOf(DateTimeException.class);
    }

    private static SecurityEvent read(String sessionId, Instant at) {
        SecurityEvent event = SecurityEvent.builder()
                .sessionId(sessionId)
                .timestamp(at)
                .description("GET /api/customer/list")
                .build();
        event.addMetadata("requestPath", "/api/customer/list");
        event.addMetadata("httpMethod", "GET");
        event.addMetadata("actionFamily", "READ");
        event.addMetadata("isProtectable", false);
        return event;
    }
}
