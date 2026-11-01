/*
 * Copyright 2026 The Contexa Project
 *
 * The Contexa Project licenses this file to you under the Apache License,
 * version 2.0 (the "License"); you may not use this file except in compliance
 * with the License. You may obtain a copy of the License at:
 *
 *   https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
 * License for the specific language governing permissions and limitations
 * under the License.
 */
package io.contexa.contexacore.security.zerotrust;

import io.contexa.contexacore.autonomous.store.SecurityContextDataStore;
import io.contexa.contexacore.properties.SecurityZeroTrustProperties;
import io.contexa.contexacore.testsupport.AdjustableClock;
import org.junit.jupiter.api.Test;

import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Z-16 (4.2, 2-a to 2-f): the in-memory and the Redis Zero Trust services treat the user's sessions alike. An
 * invalidation lasts the configured TTL and only it ends one; a forced logout reaches every id the service tracks and
 * every id of the context store's session list; neither a logout nor a forced logout removes what the context store
 * keeps (the session list, whose recent requests the analysis counts, and each session's records, which only that
 * session reads), it lapses with its TTL; a destroyed container session stays tracked until its deadline; an id keeps
 * the latest deadline it was given.
 */
abstract class AbstractZeroTrustSessionServiceContractTest {

    protected final AdjustableClock clock = new AdjustableClock();
    protected final List<String> ids = new ArrayList<>();

    /** The service of the mode, its time from {@link #clock}, its session list from {@link #contextStore()}. */
    protected abstract AbstractZeroTrustSecurityService createService(SecurityZeroTrustProperties properties);

    /** The context store of the same mode. */
    protected abstract SecurityContextDataStore contextStore();

    /** Time passes for the service and its stores alike. */
    protected abstract void elapse(Duration elapsed);

    @Test
    void anInvalidationLastsTheConfiguredCacheTtl() {
        SecurityZeroTrustProperties properties = new SecurityZeroTrustProperties();
        properties.getCache().setTtlHours(1);
        AbstractZeroTrustSecurityService service = createService(properties);
        String user = id("user");
        String session = id("session");

        service.invalidateSession(session, user, "test");
        elapse(Duration.ofMinutes(59));
        service.removeExpiredEntries();
        assertThat(service.isSessionInvalidated(session)).isTrue();

        elapse(Duration.ofMinutes(2));
        service.removeExpiredEntries();
        assertThat(service.isSessionInvalidated(session)).isFalse();
    }

    @Test
    void aLogoutLeavesAnInvalidatedSessionInvalidated() {
        AbstractZeroTrustSecurityService service = createService(new SecurityZeroTrustProperties());
        String user = id("user");
        String session = id("session");
        service.invalidateSession(session, user, "forced logout");

        service.cleanupOnLogout(user, session);

        assertThat(service.isSessionInvalidated(session)).isTrue();
    }

    @Test
    void forcedLogoutReachesEveryIdOfTheContextStoresSessionList() {
        AbstractZeroTrustSecurityService service = createService(new SecurityZeroTrustProperties());
        String user = id("user");
        String listed = id("listed");
        String tracked = id("tracked");
        contextStore().trackUserSession(user, listed);
        service.doRegisterSession(user, tracked, clock.instant().plus(Duration.ofHours(1)));

        service.invalidateAllUserSessions(user, "forced logout");

        assertThat(service.isSessionInvalidated(listed)).isTrue();
        assertThat(service.isSessionInvalidated(tracked)).isTrue();
    }

    @Test
    void neitherALogoutNorAForcedLogoutRemovesWhatTheContextStoreKeeps() {
        AbstractZeroTrustSecurityService service = createService(new SecurityZeroTrustProperties());
        String user = id("user");
        String first = id("first");
        String second = id("second");
        contextStore().trackUserSession(user, first);
        contextStore().trackUserSession(user, second);
        contextStore().addSessionDecision(first, "decision-of-the-first-session");
        contextStore().addSessionAction(first, "action-of-the-first-session");
        service.doRegisterSession(user, first, null);

        service.cleanupOnLogout(user, first);
        assertThat(contextStore().getUserSessions(user)).containsExactlyInAnyOrder(first, second);
        assertThat(contextStore().getRecentSessionDecisions(first, 10))
                .containsExactly("decision-of-the-first-session");
        assertThat(contextStore().getRecentSessionActions(first, 10)).containsExactly("action-of-the-first-session");

        service.invalidateAllUserSessions(user, "forced logout");
        assertThat(contextStore().getUserSessions(user)).containsExactlyInAnyOrder(first, second);
        assertThat(contextStore().getRecentSessionDecisions(first, 10))
                .containsExactly("decision-of-the-first-session");
        assertThat(contextStore().getRecentSessionActions(first, 10)).containsExactly("action-of-the-first-session");
    }

    @Test
    void aDestroyedContainerSessionStaysTrackedUntilItsDeadline() {
        AbstractZeroTrustSecurityService service = createService(new SecurityZeroTrustProperties());
        String user = id("user");
        String timed = id("timed");
        String untimed = id("untimed");
        service.doRegisterSession(user, timed, clock.instant().plus(Duration.ofMinutes(30)));
        service.doRegisterSession(user, untimed, null);

        service.forgetSession(timed);
        service.forgetSession(untimed);
        service.invalidateAllUserSessions(user, "forced logout");

        assertThat(service.isSessionInvalidated(timed)).isTrue();
        assertThat(service.isSessionInvalidated(untimed)).isTrue();

        String later = id("user");
        String lapsing = id("lapsing");
        service.doRegisterSession(later, lapsing, clock.instant().plus(Duration.ofMinutes(30)));
        service.forgetSession(lapsing);
        elapse(Duration.ofMinutes(31));
        service.removeExpiredEntries();
        service.invalidateAllUserSessions(later, "forced logout");

        assertThat(service.isSessionInvalidated(lapsing)).isFalse();
    }

    @Test
    void anIdRegisteredAgainWithoutADeadlineKeepsTheDeadlineItHad() throws InterruptedException {
        SecurityZeroTrustProperties properties = new SecurityZeroTrustProperties();
        properties.getSessionTracking().setMaxUntimedSessionsPerUser(1);
        AbstractZeroTrustSecurityService service = createService(properties);
        String user = id("user");
        String renewed = id("renewed");
        String newest = id("newest");
        service.doRegisterSession(user, renewed, clock.instant().plus(Duration.ofHours(1)));
        service.doRegisterSession(user, renewed, null);
        // The Redis service orders ids registered within the same millisecond by name, so the next one comes later.
        Thread.sleep(3);
        // The limit of one id without a deadline takes the renewed id off them; its deadline still holds it.
        service.doRegisterSession(user, newest, null);

        service.invalidateAllUserSessions(user, "forced logout");

        assertThat(service.isSessionInvalidated(renewed)).isTrue();
        assertThat(service.isSessionInvalidated(newest)).isTrue();
    }

    /** An id of this test, which the Redis contract removes afterwards. */
    protected String id(String kind) {
        String id = "z16-" + kind + "-" + UUID.randomUUID();
        ids.add(id);
        return id;
    }
}
