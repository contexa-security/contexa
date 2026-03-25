package io.contexa.contexacore.autonomous.context;

import io.contexa.contexacore.autonomous.domain.SecurityEvent;
import io.contexa.contexacore.autonomous.store.InMemorySecurityContextDataStore;
import io.contexa.contexacore.autonomous.store.SecurityContextDataStore;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.time.LocalDateTime;

import static org.assertj.core.api.Assertions.assertThat;

class DefaultSessionNarrativeCollectorTest {

    private SecurityContextDataStore dataStore;
    private DefaultSessionNarrativeCollector collector;

    @BeforeEach
    void setUp() {
        dataStore = new InMemorySecurityContextDataStore();
        collector = new DefaultSessionNarrativeCollector(dataStore);
    }

    @Test
    @DisplayName("collect returns empty when sessionId is missing")
    void collect_withoutSessionId_returnsEmpty() {
        SecurityEvent event = SecurityEvent.builder()
                .timestamp(LocalDateTime.of(2026, 3, 25, 9, 0))
                .build();

        assertThat(collector.collect(event)).isEmpty();
    }

    @Test
    @DisplayName("collect builds previous path, interval, and narrative sequence across repeated session requests")
    void collect_repeatedSessionRequests_buildsNarrativeSnapshot() {
        collector.collect(event(
                "session-1",
                LocalDateTime.of(2026, 3, 25, 9, 0, 0),
                "/api/customer/list",
                "GET",
                true,
                "READ"));

        SessionNarrativeSnapshot snapshot = collector.collect(event(
                        "session-1",
                        LocalDateTime.of(2026, 3, 25, 9, 0, 0, 800_000_000),
                        "/api/customer/export",
                        "POST",
                        true,
                        "EXPORT"))
                .orElseThrow();

        assertThat(snapshot.getPreviousPath()).isEqualTo("/api/customer/list");
        assertThat(snapshot.getPreviousActionFamily()).isEqualTo("READ");
        assertThat(snapshot.getLastRequestIntervalMs()).isEqualTo(800L);
        assertThat(snapshot.getSessionActionSequence()).containsExactly("READ", "EXPORT");
        assertThat(snapshot.getSessionProtectableSequence())
                .containsExactly("/api/customer/list", "/api/customer/export");
        assertThat(snapshot.getBurstPattern()).isFalse();
        assertThat(snapshot.getSummary()).contains("Previous path /api/customer/list");
    }

    @Test
    @DisplayName("collect flags burst pattern after three rapid protectable requests")
    void collect_threeRapidProtectableRequests_flagsBurstPattern() {
        collector.collect(event(
                "session-rapid",
                LocalDateTime.of(2026, 3, 25, 9, 10, 0),
                "/api/customer/export",
                "POST",
                true,
                "EXPORT"));
        collector.collect(event(
                "session-rapid",
                LocalDateTime.of(2026, 3, 25, 9, 10, 1),
                "/api/customer/export",
                "POST",
                true,
                "EXPORT"));

        SessionNarrativeSnapshot snapshot = collector.collect(event(
                        "session-rapid",
                        LocalDateTime.of(2026, 3, 25, 9, 10, 2, 200_000_000),
                        "/api/customer/export",
                        "POST",
                        true,
                        "EXPORT"))
                .orElseThrow();

        assertThat(snapshot.getSessionProtectableSequence()).hasSize(3);
        assertThat(snapshot.getBurstPattern()).isTrue();
    }

    @Test
    @DisplayName("collect keeps non-protectable requests out of protectable sequence")
    void collect_nonProtectableRequest_excludesProtectableSequence() {
        SessionNarrativeSnapshot snapshot = collector.collect(event(
                        "session-plain",
                        LocalDateTime.of(2026, 3, 25, 9, 20, 0),
                        "/actuator/health",
                        "GET",
                        false,
                        "READ"))
                .orElseThrow();

        assertThat(snapshot.getSessionActionSequence()).containsExactly("READ");
        assertThat(snapshot.getSessionProtectableSequence()).isEmpty();
        assertThat(snapshot.getBurstPattern()).isFalse();
    }

    private SecurityEvent event(String sessionId,
                                LocalDateTime timestamp,
                                String requestPath,
                                String httpMethod,
                                boolean protectable,
                                String actionFamily) {
        SecurityEvent event = SecurityEvent.builder()
                .sessionId(sessionId)
                .timestamp(timestamp)
                .description(httpMethod + " " + requestPath)
                .build();
        event.addMetadata("requestPath", requestPath);
        event.addMetadata("httpMethod", httpMethod);
        event.addMetadata("actionFamily", actionFamily);
        event.addMetadata("isProtectable", protectable);
        if (protectable) {
            event.addMetadata("className", "io.contexa.CustomerExportController");
            event.addMetadata("methodName", "handle");
            event.addMetadata("granted", true);
        }
        return event;
    }
}
