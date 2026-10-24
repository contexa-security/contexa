package io.contexa.showcase.portal.orchestrator;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.contexa.showcase.business.client.WorkloadClient.RunIdentity;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneId;
import java.time.ZoneOffset;
import java.util.Map;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyMap;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * docs/agent RW-2 (A1-6): an operator's browser session on control D's admin console opens with an administrator made
 * as a run's approver is, reads its one-time code from the demo inbox and removes the administrator when closed or
 * when its lifetime ends.
 */
class ConsoleSessionsTest {

    private static final Instant NOW = Instant.parse("2026-10-24T11:00:00Z");

    private final WorkloadAdmin admin = mock(WorkloadAdmin.class);
    private final MovableClock clock = new MovableClock(NOW);
    private final ConsoleSessions sessions = new ConsoleSessions(admin, clock);

    @Test
    @SuppressWarnings("unchecked")
    void aSessionOpensWithAnApproverAdministratorWhoseCodeComesFromTheInbox() throws Exception {
        when(admin.employee(RunApprover.EMPLOYEE)).thenReturn(new ObjectMapper().readTree(
                "{\"officeNetwork\":\"10.40.12.0/24\",\"roleKey\":\"IT_ADMIN\",\"displayName\":\"Administrator B\","
                        + "\"department\":\"IT\"}"));

        ConsoleSessions.Session session = sessions.open();

        ArgumentCaptor<RunIdentity> identity = ArgumentCaptor.forClass(RunIdentity.class);
        ArgumentCaptor<Map<String, Object>> principal = ArgumentCaptor.forClass(Map.class);
        verify(admin).createEnginePrincipal(identity.capture(), principal.capture());
        assertThat(identity.getValue().runId()).isEqualTo(session.runId()).startsWith("console-");
        assertThat(principal.getValue()).containsEntry("username", session.username())
                .containsEntry("password", session.password()).containsEntry("approver", true)
                .containsEntry("employeeKey", RunApprover.EMPLOYEE).containsEntry("roleKey", "IT_ADMIN");
        assertThat(session.username()).matches("v[0-9a-f]{12}-adm-b");
        assertThat(session.email()).isEqualTo(session.username() + "@showcase.invalid");
        assertThat(session.expiresAt()).isEqualTo(NOW.plus(ConsoleSessions.LIFETIME));

        when(admin.inboxCode(session.email())).thenReturn(Optional.of("482913"));
        assertThat(sessions.code(session.key())).contains("482913");

        assertThat(sessions.close(session.key())).isTrue();
        verify(admin).deleteEnginePrincipal(session.runId(), session.username());
        assertThat(sessions.close(session.key())).isFalse();
        assertThat(sessions.code(session.key())).isEmpty();
    }

    @Test
    void anAdministratorIsRemovedOnceItsLifetimeEnds() throws Exception {
        when(admin.employee(RunApprover.EMPLOYEE)).thenReturn(new ObjectMapper().readTree(
                "{\"officeNetwork\":\"10.40.12.0/24\",\"roleKey\":\"IT_ADMIN\"}"));
        ConsoleSessions.Session session = sessions.open();

        clock.move(ConsoleSessions.LIFETIME.minusSeconds(1));
        sessions.closeExpired();
        verify(admin, never()).deleteEnginePrincipal(any(), any());

        clock.move(Duration.ofSeconds(1));
        assertThat(sessions.code(session.key())).isEmpty();
        verify(admin).deleteEnginePrincipal(session.runId(), session.username());
        verify(admin).createEnginePrincipal(any(RunIdentity.class), anyMap());
    }

    private static final class MovableClock extends Clock {

        private Instant now;

        MovableClock(Instant now) {
            this.now = now;
        }

        void move(Duration duration) {
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
