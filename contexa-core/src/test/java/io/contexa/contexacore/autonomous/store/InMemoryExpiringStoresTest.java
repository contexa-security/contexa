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
    void stoppedRequestsLastAsLongAsTheChallengeAndTheirVerificationAsLongAsTheAllow() {
        // N-LRN-3: a stopped request waits for the step-up while the challenge is in force (30 min); once verified it
        // is sent again under the ALLOW the step-up writes (15 s).
        InMemorySecurityContextDataStore store = new InMemorySecurityContextDataStore(
                Duration.ofHours(24), Duration.ofDays(7), Duration.ofDays(7), clock);
        store.holdStoppedRequest("erin", "POST /api/exports");
        store.holdStoppedRequest("frank", "POST /api/exports");
        store.holdStoppedRequest("gina", "POST /api/exports");

        clock.advance(Duration.ofMinutes(29));
        store.verifyStoppedRequests("erin", null);
        store.verifyStoppedRequests("frank", null);
        assertThat(store.takeVerifiedStoppedRequest("erin", "POST /api/exports")).isTrue();

        clock.advance(Duration.ofSeconds(16));
        assertThat(store.takeVerifiedStoppedRequest("frank", "POST /api/exports")).isFalse();
        clock.advance(Duration.ofMinutes(2));
        store.verifyStoppedRequests("gina", null);
        assertThat(store.takeVerifiedStoppedRequest("gina", "POST /api/exports")).isFalse();
        store.removeExpiredEntries();
        assertThat(store.holdsUserRecordsFor("frank")).isFalse();
        assertThat(store.holdsUserRecordsFor("gina")).isFalse();
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
