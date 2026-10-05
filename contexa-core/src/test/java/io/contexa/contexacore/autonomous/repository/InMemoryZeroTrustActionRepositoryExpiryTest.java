package io.contexa.contexacore.autonomous.repository;

import io.contexa.contexacommon.enums.ZeroTrustAction;
import io.contexa.contexacore.testsupport.AdjustableClock;
import org.junit.jupiter.api.Test;

import java.time.Duration;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Removing expired entries releases memory without changing any read: a decision is kept while its 24 h
 * last-verified record can still answer a read, and decisions without a TTL are never removed.
 */
class InMemoryZeroTrustActionRepositoryExpiryTest {

    private final AdjustableClock clock = new AdjustableClock();
    private final InMemoryZeroTrustActionRepository repository =
            new InMemoryZeroTrustActionRepository(Duration.ofHours(24), clock);

    @Test
    void anExpiredChallengeKeepsReadingPendingAndIsReleasedOnceItsRecordExpires() {
        repository.saveAction("alice", ZeroTrustAction.CHALLENGE, Map.of());

        clock.advance(Duration.ofMinutes(31));
        repository.removeExpiredEntries();
        assertThat(repository.getCurrentAction("alice", "ctx")).isEqualTo(ZeroTrustAction.PENDING_ANALYSIS);
        assertThat(repository.holdsStateFor("alice")).isTrue();

        clock.advance(Duration.ofHours(24));
        repository.removeExpiredEntries();
        assertThat(repository.getCurrentAction("alice", "ctx")).isEqualTo(ZeroTrustAction.PENDING_ANALYSIS);
        assertThat(repository.holdsStateFor("alice")).isFalse();
    }

    @Test
    void anUnresolvedEscalateStillReadsAsEscalateAfterASweep() {
        repository.saveAction("bob", ZeroTrustAction.ESCALATE, Map.of());

        clock.advance(Duration.ofMinutes(6));
        repository.removeExpiredEntries();

        assertThat(repository.getCurrentAction("bob", "ctx")).isEqualTo(ZeroTrustAction.ESCALATE);
    }

    @Test
    void aBlockWithoutTtlIsNeverRemoved() {
        repository.saveAction("carol", ZeroTrustAction.BLOCK, Map.of());
        repository.setBlockedFlag("carol");

        clock.advance(Duration.ofDays(3));
        repository.removeExpiredEntries();

        assertThat(repository.getCurrentAction("carol", "ctx")).isEqualTo(ZeroTrustAction.BLOCK);
        assertThat(repository.getActionFromHash("carol")).isEqualTo(ZeroTrustAction.BLOCK);
    }

    @Test
    void expiredRetryAndMfaMarkersAreReleased() {
        repository.setEscalateRetry("dave", Duration.ofMinutes(5));
        repository.setBlockMfaPending("dave");
        repository.incrementBlockMfaFailCount("dave");
        assertThat(repository.holdsStateFor("dave")).isTrue();

        clock.advance(Duration.ofHours(25));
        repository.removeExpiredEntries();

        assertThat(repository.hasEscalateRetry("dave")).isFalse();
        assertThat(repository.isBlockMfaPending("dave")).isFalse();
        assertThat(repository.holdsStateFor("dave")).isFalse();
    }
}
