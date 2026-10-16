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
package io.contexa.contexacore.autonomous.store;

import java.time.Instant;
import org.awaitility.Awaitility;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.time.Duration;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

abstract class AbstractSecurityContextDataStoreContractTest {

    protected SecurityContextDataStore store;

    protected abstract SecurityContextDataStore createStore();

    protected abstract SecurityContextDataStore createStoreWithEventProcessedTtl(Duration ttl);

    protected abstract SecurityContextDataStore createStoreWithLoginFailureRetention(Duration retention);

    @BeforeEach
    void setUpStore() {
        store = createStore();
    }

    @Test
    @DisplayName("claimEventProcessing returns ACQUIRED for a fresh event")
    void claim_freshEvent_acquired() {
        assertThat(store.claimEventProcessing("event-fresh"))
                .isEqualTo(SecurityContextDataStore.EventProcessingClaim.ACQUIRED);
    }

    @Test
    @DisplayName("claimEventProcessing returns IN_FLIGHT when already claimed but not yet marked processed")
    void claim_inFlight_afterAcquire() {
        store.claimEventProcessing("event-inflight");

        assertThat(store.claimEventProcessing("event-inflight"))
                .isEqualTo(SecurityContextDataStore.EventProcessingClaim.IN_FLIGHT);
    }

    @Test
    @DisplayName("claimEventProcessing returns PROCESSED after markEventProcessed")
    void claim_processed_afterMark() {
        store.claimEventProcessing("event-done");
        store.markEventProcessed("event-done");

        assertThat(store.claimEventProcessing("event-done"))
                .isEqualTo(SecurityContextDataStore.EventProcessingClaim.PROCESSED);
    }

    @Test
    @DisplayName("Processed event re-opens for claim after event-processed TTL expires")
    void markEventProcessed_expiresAfterTtl() {
        SecurityContextDataStore ttlStore = createStoreWithEventProcessedTtl(Duration.ofMillis(300));
        ttlStore.claimEventProcessing("event-ttl");
        ttlStore.markEventProcessed("event-ttl");

        assertThat(ttlStore.claimEventProcessing("event-ttl"))
                .isEqualTo(SecurityContextDataStore.EventProcessingClaim.PROCESSED);

        Awaitility.await()
                .atMost(Duration.ofSeconds(5))
                .pollInterval(Duration.ofMillis(100))
                .untilAsserted(() -> assertThat(ttlStore.claimEventProcessing("event-ttl"))
                        .as("processed event must become claimable again after TTL")
                        .isEqualTo(SecurityContextDataStore.EventProcessingClaim.ACQUIRED));
    }

    @Test
    @DisplayName("releaseEventProcessing frees an in-flight claim")
    void release_freesInFlight() {
        store.claimEventProcessing("event-rel");
        store.releaseEventProcessing("event-rel");

        assertThat(store.claimEventProcessing("event-rel"))
                .isEqualTo(SecurityContextDataStore.EventProcessingClaim.ACQUIRED);
    }

    @Test
    @DisplayName("login failure context is counted by user and client IP without double-counting")
    void loginFailureContext_isAvailableForPromptProjection() {
        long now = System.currentTimeMillis();
        store.recordLoginFailure("alice", "203.0.113.10", now - 2_000);
        store.recordLoginFailure("alice", null, now - 1_000);

        assertThat(store.getRecentLoginFailureCount(
                "alice", "203.0.113.10", now - 5_000, now)).isEqualTo(2);
    }

    @Test
    @DisplayName("a user's failures are counted by the user, not by an address shared with other users (W1-9)")
    void loginFailures_areCountedByUser() {
        long now = System.currentTimeMillis();
        store.recordLoginFailure("alice", "203.0.113.10", now - 3_000);
        store.recordLoginFailure("bob", "203.0.113.10", now - 2_000);
        store.recordLoginFailure("bob", "203.0.113.10", now - 1_000);

        assertThat(store.findRecentLoginFailures("alice", now - 60_000, now)).isEqualTo(1);
        assertThat(store.findRecentLoginFailures(null, now - 60_000, now)).isNull();
    }

    @Test
    @DisplayName("failures stay countable for the configured window, not only five minutes (W1-9)")
    void loginFailures_stayForTheConfiguredWindow() {
        SecurityContextDataStore longWindow = createStoreWithLoginFailureRetention(Duration.ofMinutes(15));
        long first = System.currentTimeMillis() - Duration.ofMinutes(7).toMillis();
        longWindow.recordLoginFailure("erin", null, first);
        longWindow.recordLoginFailure("erin", null, first + 1_000);
        long later = first + Duration.ofMinutes(6).toMillis() + 15_000;
        longWindow.recordLoginFailure("erin", null, later);

        assertThat(longWindow.findRecentLoginFailures("erin", later - Duration.ofMinutes(15).toMillis(), later))
                .isEqualTo(3);
    }

    @Test
    @DisplayName("MFA completion context is available after verification")
    void mfaCompletionContext_isAvailableForPromptProjection() {
        assertThat(store.isMfaVerified("alice")).isFalse();
        assertThat(store.getLastMfaVerifiedAt("alice")).isNull();
        Instant before = Instant.now().minusSeconds(1);
        store.markMfaVerified("alice");
        assertThat(store.isMfaVerified("alice")).isTrue();
        // The mark keeps when the MFA happened, so a request can say how long ago the user completed it (W1-5).
        assertThat(store.getLastMfaVerifiedAt("alice")).isAfterOrEqualTo(before);
    }

    @Test
    @DisplayName("MFA completion keeps the time of the request that completed it (W1-7)")
    void mfaCompletion_keepsTheRequestTime() {
        Instant requestTime = Instant.parse("2026-09-30T03:15:00Z");

        store.markMfaVerified("carol", requestTime);

        assertThat(store.isMfaVerified("carol")).isTrue();
        assertThat(store.getLastMfaVerifiedAt("carol")).isEqualTo(requestTime);
    }

    @Test
    @DisplayName("a session's decisions are kept oldest first, repeats included, and the most recent are read (W1-11)")
    void sessionDecisions_keepTheirOrder() {
        for (int number = 1; number <= 4; number++) {
            store.addSessionDecision("session-decisions", "decision-" + number);
        }
        store.addSessionDecision("session-decisions", "decision-4");

        assertThat(store.getRecentSessionDecisions("session-decisions", 3))
                .containsExactly("decision-3", "decision-4", "decision-4");
        assertThat(store.getRecentSessionDecisions("session-other", 3)).isEmpty();
    }

    @Test
    @DisplayName("a session's narrative is read in the order its requests were made, though decided out of it (N-SES-1)")
    void sessionNarrative_isReadInTheOrderTheRequestsWereMade() {
        store.addSessionNarrativeActionFamily("session-order", "READ", 1_000L);
        store.addSessionProtectableAccess("session-order", "/api/a", 1_000L);
        // The request made at 2_005 was decided before the one made at 2_000.
        store.addSessionNarrativeActionFamily("session-order", "DELETE", 2_005L);
        store.addSessionProtectableAccess("session-order", "/api/c", 2_005L);
        store.addSessionRequestInterval("session-order", 1_005L, 2_005L);
        store.addSessionNarrativeActionFamily("session-order", "EXPORT", 2_000L);
        store.addSessionProtectableAccess("session-order", "/api/b", 2_000L);
        store.addSessionRequestInterval("session-order", 1_000L, 2_000L);

        assertThat(store.getRecentSessionNarrativeActionFamilies("session-order", 10))
                .containsExactly("READ", "EXPORT", "DELETE");
        assertThat(store.getRecentSessionProtectableAccesses("session-order", 10))
                .containsExactly("/api/a", "/api/b", "/api/c");
        assertThat(store.getRecentSessionProtectableAccesses("session-order", 2)).containsExactly("/api/b", "/api/c");
        assertThat(store.getRecentSessionRequestIntervals("session-order", 10)).containsExactly(1_000L, 1_005L);
    }

    @Test
    @DisplayName("an entry kept without its request time keeps its place after the entry before it (N-SES-1)")
    void sessionNarrative_entriesWithoutTheirRequestTimeKeepTheirPlace() {
        store.addSessionProtectableAccess("session-mixed", "/api/kept-before");
        store.addSessionProtectableAccess("session-mixed", "/api/late", 3_000L);
        store.addSessionProtectableAccess("session-mixed", "/api/early", 2_000L);
        store.addSessionProtectableAccess("session-mixed", "/api/kept-after");

        assertThat(store.getRecentSessionProtectableAccesses("session-mixed", 10))
                .containsExactly("/api/kept-before", "/api/early", "/api/kept-after", "/api/late");
    }

    @Test
    @DisplayName("a session's last request is the latest one made, whichever was decided last (N-SES-1)")
    void sessionLastRequest_isTheLatestRequestMade() {
        store.recordSessionLastRequest("session-last", 2_005L, "/api/c");
        store.recordSessionLastRequest("session-last", 2_000L, "/api/b");

        assertThat(store.getSessionLastRequestTime("session-last")).isEqualTo(2_005L);
        assertThat(store.getSessionPreviousPath("session-last")).isEqualTo("/api/c");

        store.recordSessionLastRequest("session-last", 3_000L, null);
        assertThat(store.getSessionLastRequestTime("session-last")).isEqualTo(3_000L);
        assertThat(store.getSessionPreviousPath("session-last")).isEqualTo("/api/c");

        store.recordSessionLastRequest("session-last", 4_000L, "/api/d");
        assertThat(store.getSessionLastRequestTime("session-last")).isEqualTo(4_000L);
        assertThat(store.getSessionPreviousPath("session-last")).isEqualTo("/api/d");
    }

    @Test
    @DisplayName("how the verification of a stopped request ended is kept by its event, for a record stored after it (W5-4)")
    void verificationOutcome_isKeptByTheEvent() {
        store.recordVerificationOutcome("event-held", "verified by step-up");

        assertThat(store.verificationOutcome("event-held")).isEqualTo("verified by step-up");
        assertThat(store.verificationOutcome("event-other")).isNull();
    }

    @Test
    @DisplayName("the facts of a request a restriction stopped are kept until they are taken, once (W5-2)")
    void verificationLearning_isTakenOnce() {
        store.holdVerificationLearning("user-held", "request-1", "{\"requestPath\":\"/api/a\"}");
        store.holdVerificationLearning("user-held", "request-2", "{\"requestPath\":\"/api/b\"}");

        assertThat(store.takeVerificationLearning("user-held", "request-1")).isEqualTo("{\"requestPath\":\"/api/a\"}");
        assertThat(store.takeVerificationLearning("user-held", "request-1")).isNull();
        assertThat(store.takeVerificationLearning("user-other", "request-2")).isNull();
        assertThat(store.takeVerificationLearning("user-held", "request-2")).isEqualTo("{\"requestPath\":\"/api/b\"}");
        // The kept facts are the user's data and go with it.
        store.holdVerificationLearning("user-held", "request-3", "{}");
        store.deleteUserData("user-held");
        assertThat(store.takeVerificationLearning("user-held", "request-3")).isNull();
    }

    @Test
    @DisplayName("a held request waits, listed with the user's other held requests, until it is removed (W5-1)")
    void promotionLearning_isListedUntilRemoved() {
        store.holdPromotionLearning("user-held", "request-1", "{\"day\":\"2026-09-29\"}");
        store.holdPromotionLearning("user-held", "request-2", "{\"day\":\"2026-09-30\"}");
        store.holdPromotionLearning("user-other", "request-3", "{}");

        assertThat(store.promotionLearning("user-held")).isEqualTo(Map.of(
                "request-1", "{\"day\":\"2026-09-29\"}", "request-2", "{\"day\":\"2026-09-30\"}"));
        store.removePromotionLearning("user-held", List.of("request-1", "request-9"));
        assertThat(store.promotionLearning("user-held")).containsOnlyKeys("request-2");
        // The held requests are the user's data and go with it.
        store.deleteUserData("user-held");
        assertThat(store.promotionLearning("user-held")).isEmpty();
        assertThat(store.promotionLearning("user-other")).containsOnlyKeys("request-3");
    }

    @Test
    @DisplayName("a session's records follow it to the id the container gives it; the old id keeps none (W1-11)")
    void moveSessionRecords_carriesTheSessionToItsNewId() {
        store.addSessionAction("session-old", "03:15 | MFA_LOGIN (multi-factor sign-in) | 10.0.0.1");
        store.addSessionDecision("session-old", "decision-1");
        store.addSessionNarrativeActionFamily("session-old", "EXPORT");
        store.addSessionProtectableAccess("session-old", "/api/projects/GB-500/exports");
        store.addSessionRequestInterval("session-old", 800L);
        store.setSessionStartedAt("session-old", 1_000L);
        store.setSessionLastRequestTime("session-old", 2_000L);
        store.setSessionPreviousPath("session-old", "/api/projects/GB-500/exports");
        // A record written under the new id before the move stays after the old id's records.
        store.addSessionAction("session-new", "03:18 | ZERO_TRUST_CHALLENGE_VERIFIED (step-up MFA in this session)");

        store.moveSessionRecords("session-old", "session-new");

        assertThat(store.getRecentSessionActions("session-new", 10)).containsExactly(
                "03:15 | MFA_LOGIN (multi-factor sign-in) | 10.0.0.1",
                "03:18 | ZERO_TRUST_CHALLENGE_VERIFIED (step-up MFA in this session)");
        assertThat(store.getRecentSessionDecisions("session-new", 10)).containsExactly("decision-1");
        assertThat(store.getRecentSessionNarrativeActionFamilies("session-new", 10)).containsExactly("EXPORT");
        assertThat(store.getRecentSessionProtectableAccesses("session-new", 10))
                .containsExactly("/api/projects/GB-500/exports");
        assertThat(store.getRecentSessionRequestIntervals("session-new", 10)).containsExactly(800L);
        assertThat(store.getSessionStartedAt("session-new")).isEqualTo(1_000L);
        assertThat(store.getSessionLastRequestTime("session-new")).isEqualTo(2_000L);
        assertThat(store.getSessionPreviousPath("session-new")).isEqualTo("/api/projects/GB-500/exports");
        assertThat(store.getRecentSessionActions("session-old", 10)).isEmpty();
        assertThat(store.getRecentSessionDecisions("session-old", 10)).isEmpty();
        assertThat(store.getRecentSessionProtectableAccesses("session-old", 10)).isEmpty();
        assertThat(store.getSessionStartedAt("session-old")).isNull();
        assertThat(store.getSessionPreviousPath("session-old")).isNull();
        // The new id remembers the ids the session had, newest first (P2 correction 5).
        assertThat(store.getSessionPreviousIds("session-new")).containsExactly("session-old");
        store.moveSessionRecords("session-new", "session-newer");
        assertThat(store.getSessionPreviousIds("session-newer")).containsExactly("session-new", "session-old");
        assertThat(store.getSessionPreviousIds("session-new")).isEmpty();
        assertThat(store.getSessionPreviousIds("session-unknown")).isEmpty();
    }

    @Test
    @DisplayName("the client a session first came from is kept once and follows the session to its new id (W2-14)")
    void sessionFirstClient_isKeptOnceAndFollowsTheSession() {
        store.setSessionFirstClientIfAbsent("session-first", "UA|WINDOWS|Chrome/140|10.40.12.0/24|CORPORATE");
        store.setSessionFirstClientIfAbsent("session-first", "UA|MAC|Safari/17|203.0.113.0/24|");

        assertThat(store.getSessionFirstClient("session-first"))
                .isEqualTo("UA|WINDOWS|Chrome/140|10.40.12.0/24|CORPORATE");
        store.moveSessionRecords("session-first", "session-second");
        assertThat(store.getSessionFirstClient("session-second"))
                .isEqualTo("UA|WINDOWS|Chrome/140|10.40.12.0/24|CORPORATE");
        assertThat(store.getSessionFirstClient("session-first")).isNull();
        assertThat(store.getSessionFirstClient("session-unknown")).isNull();
    }

    @Test
    @DisplayName("deleting a user removes its records in every tenant and keeps other users and shared scopes")
    void deleteUserData_removesOnlyThatUser() {
        long now = System.currentTimeMillis();
        for (String user : new String[]{"carol", "dave"}) {
            store.addWorkProfileObservation(null, user, "{\"path\":\"/documents\"}");
            store.addWorkProfileObservation("tenant-a", user, "{\"path\":\"/exports\"}");
            store.addPermissionChangeObservation("tenant-a", user, "{\"role\":\"ENGINEER\"}");
            store.setAuthorizationScopeState("tenant-a", user, "{\"scope\":\"engineering\"}");
            store.markMfaVerified(user);
            store.recordLoginFailure(user, null, now);
        }
        store.addRoleScopeObservation("tenant-a", "engineering", "{\"user\":\"carol\"}");

        store.deleteUserData("carol");

        assertThat(store.getRecentWorkProfileObservations(null, "carol", 10)).isEmpty();
        assertThat(store.getRecentWorkProfileObservations("tenant-a", "carol", 10)).isEmpty();
        assertThat(store.getRecentPermissionChangeObservations("tenant-a", "carol", 10)).isEmpty();
        assertThat(store.getAuthorizationScopeState("tenant-a", "carol")).isNull();
        assertThat(store.isMfaVerified("carol")).isFalse();
        assertThat(store.getRecentLoginFailureCount("carol", null, now - 5_000, now + 5_000)).isZero();
        assertThat(store.getRecentWorkProfileObservations("tenant-a", "dave", 10)).isNotEmpty();
        assertThat(store.isMfaVerified("dave")).isTrue();
        assertThat(store.getRecentRoleScopeObservations("tenant-a", "engineering", 10)).isNotEmpty();
    }
}
