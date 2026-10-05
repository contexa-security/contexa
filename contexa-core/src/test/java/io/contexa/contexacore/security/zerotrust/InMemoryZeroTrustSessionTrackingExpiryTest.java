package io.contexa.contexacore.security.zerotrust;

import io.contexa.contexacore.autonomous.blocking.InMemoryBlockingSignalBroadcaster;
import io.contexa.contexacore.autonomous.repository.InMemoryZeroTrustActionRepository;
import io.contexa.contexacore.autonomous.utils.ThreatScoreUtil;
import io.contexa.contexacore.properties.SecurityZeroTrustProperties;
import io.contexa.contexacore.testsupport.AdjustableClock;
import org.junit.jupiter.api.Test;

import java.time.Duration;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;

class InMemoryZeroTrustSessionTrackingExpiryTest {

    private final AdjustableClock clock = new AdjustableClock();
    private final InMemoryZeroTrustSecurityService service = new InMemoryZeroTrustSecurityService(
            mock(ThreatScoreUtil.class), new SecurityZeroTrustProperties(), new InMemoryZeroTrustActionRepository(),
            new InMemoryBlockingSignalBroadcaster(), Duration.ofHours(24), clock);

    @Test
    void aTokenIdentifierIsReleasedAfterItsExpiryAndAnHttpSessionWhenItIsDestroyed() {
        service.doRegisterSession("alice", "jti-1", clock.instant().plus(Duration.ofHours(1)));
        service.doRegisterSession("alice", "http-session-1", null);

        clock.advance(Duration.ofHours(2));
        service.removeExpiredEntries();
        assertThat(service.tracksSession("jti-1")).isFalse();
        assertThat(service.tracksSession("http-session-1")).isTrue();

        service.forgetSession("http-session-1");
        assertThat(service.tracksSession("http-session-1")).isFalse();
    }

    @Test
    void forcedLogoutStillReachesEveryLiveSessionAfterASweep() {
        service.doRegisterSession("bob", "jti-live", clock.instant().plus(Duration.ofHours(1)));
        service.doRegisterSession("bob", "http-session-live", null);

        service.removeExpiredEntries();
        service.invalidateAllUserSessions("bob", "test");

        assertThat(service.isSessionInvalidated("jti-live")).isTrue();
        assertThat(service.isSessionInvalidated("http-session-live")).isTrue();
    }

    @Test
    void invalidationMarksAreReleasedOnlyAfterTheirTtl() {
        service.invalidateSession("http-session-2", "carol", "test");

        clock.advance(Duration.ofHours(23));
        service.removeExpiredEntries();
        assertThat(service.isSessionInvalidated("http-session-2")).isTrue();

        clock.advance(Duration.ofHours(2));
        service.removeExpiredEntries();
        assertThat(service.isSessionInvalidated("http-session-2")).isFalse();
    }
}
