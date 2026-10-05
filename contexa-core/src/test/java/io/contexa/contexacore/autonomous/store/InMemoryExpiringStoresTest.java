package io.contexa.contexacore.autonomous.store;

import io.contexa.contexacore.autonomous.repository.InMemoryZeroTrustActionRepository;
import io.contexa.contexacore.testsupport.AdjustableClock;
import org.junit.jupiter.api.Test;

import java.time.Duration;
import java.util.List;
import java.util.concurrent.atomic.AtomicInteger;

import static org.assertj.core.api.Assertions.assertThat;

class InMemoryExpiringStoresTest {

    private final AdjustableClock clock = new AdjustableClock();

    @Test
    void blockMfaVerificationIsReleasedAfterItsTtl() {
        InMemoryBlockMfaStateStore store =
                new InMemoryBlockMfaStateStore(new InMemoryZeroTrustActionRepository(), Duration.ofHours(1), clock);
        store.setVerified("alice");

        store.removeExpiredEntries();
        assertThat(store.isVerified("alice")).isTrue();

        clock.advance(Duration.ofMinutes(61));
        store.removeExpiredEntries();
        assertThat(store.holdsVerificationFor("alice")).isFalse();
        assertThat(store.isVerified("alice")).isFalse();
    }

    @Test
    void userRecordsAreReleasedOnlyAfterTheirTtls() {
        InMemorySecurityContextDataStore store = new InMemorySecurityContextDataStore(
                Duration.ofHours(24), Duration.ofDays(7), Duration.ofDays(7), clock);
        store.markMfaVerified("bob");
        store.trackUserSession("bob", "session-1");

        clock.advance(Duration.ofMinutes(61));
        store.removeExpiredEntries();
        assertThat(store.isMfaVerified("bob")).isFalse();
        assertThat(store.peekUserSessions("bob")).containsExactly("session-1");

        clock.advance(Duration.ofDays(7));
        store.removeExpiredEntries();
        assertThat(store.peekUserSessions("bob")).isEmpty();
        assertThat(store.holdsUserRecordsFor("bob")).isFalse();
    }

    @Test
    void loginFailuresAreReleasedOnlyAfterTheLongestQueriedWindow() {
        InMemorySecurityContextDataStore store = new InMemorySecurityContextDataStore(
                Duration.ofHours(24), Duration.ofDays(7), Duration.ofDays(7), clock);
        store.setLoginFailureRetention(Duration.ofMinutes(30));
        store.recordLoginFailure("dave", "203.0.113.7", clock.millis());

        clock.advance(Duration.ofMinutes(20));
        store.removeExpiredEntries();
        assertThat(store.holdsUserRecordsFor("dave")).isTrue();

        clock.advance(Duration.ofMinutes(11));
        store.removeExpiredEntries();
        assertThat(store.holdsUserRecordsFor("dave")).isFalse();
    }

    @Test
    void aFailingStoreDoesNotStopTheSweep() {
        AtomicInteger swept = new AtomicInteger();
        ExpiringStateStore failing = () -> {
            throw new IllegalStateException("store unavailable");
        };
        ExpiringStateStore counting = swept::incrementAndGet;
        InMemoryStateSweeper sweeper = new InMemoryStateSweeper(() -> List.of(failing, counting), Duration.ofHours(1));
        try {
            sweeper.sweep();
        } finally {
            sweeper.close();
        }
        assertThat(swept).hasValue(1);
    }
}
