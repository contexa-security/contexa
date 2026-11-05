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
package io.contexa.contexacore.autonomous.repository;

import io.contexa.contexacommon.enums.ZeroTrustAction;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.time.Instant;
import java.util.Locale;
import java.util.Map;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Q-12 (PR-62): the code the victim passes does not free the attacker's session. Each test uses a user of its own, so
 * the Redis store runs beside other tests.
 */
abstract class AbstractZeroTrustActionRepositoryChallengeHoldContractTest {

    private static final String VICTIM = "context-victim";
    private static final String ATTACKER = "context-attacker";
    private static final String SECOND_DEVICE = "context-second-device";

    protected ZeroTrustActionRepository repository;
    protected String user;

    protected abstract ZeroTrustActionRepository createRepository();

    @BeforeEach
    void setUpRepository() {
        repository = createRepository();
        user = "hold-" + UUID.randomUUID();
    }

    private static Map<String, Object> decision(String context) {
        return Map.of("observationId", "observation-1", "processingGeneration", "1", "contextBindingHash", context);
    }

    protected void challenge() {
        assertThat(repository.saveFinalAction(user, ZeroTrustAction.CHALLENGE, decision(ATTACKER))).isTrue();
    }

    private void answeredIn(String context) {
        repository.holdChallengeForOtherSessions(user, context);
        repository.saveActionWithPrevious(user, ZeroTrustAction.ALLOW, context);
    }

    @Test
    @DisplayName("the session that answered goes on and every other session stays stopped, a new one and one without a context too")
    void onlyTheSessionThatAnsweredGoesOn() {
        challenge();

        answeredIn(VICTIM);

        assertThat(repository.getCurrentAction(user, VICTIM)).isEqualTo(ZeroTrustAction.ALLOW);
        assertThat(repository.getCurrentAction(user, ATTACKER)).isEqualTo(ZeroTrustAction.CHALLENGE);
        assertThat(repository.getCurrentAction(user, "context-new-sign-in")).isEqualTo(ZeroTrustAction.CHALLENGE);
        assertThat(repository.getCurrentAction(user, null)).isEqualTo(ZeroTrustAction.CHALLENGE);
    }

    @Test
    @DisplayName("each device answers for itself, and the one that answered first needs no second answer")
    void eachDeviceAnswersForItself() {
        challenge();
        answeredIn(VICTIM);

        answeredIn(SECOND_DEVICE);

        assertThat(repository.getCurrentAction(user, SECOND_DEVICE)).isEqualTo(ZeroTrustAction.ALLOW);
        assertThat(repository.getCurrentAction(user, VICTIM)).as("a fresh analysis, no new challenge")
                .isEqualTo(ZeroTrustAction.PENDING_ANALYSIS);
        assertThat(repository.getCurrentAction(user, ATTACKER)).isEqualTo(ZeroTrustAction.CHALLENGE);
    }

    @Test
    @DisplayName("a logout of the session that answered frees nobody")
    void aLogoutFreesNobody() {
        challenge();
        answeredIn(VICTIM);

        repository.removeLogoutData(user);

        assertThat(repository.getCurrentAction(user, ATTACKER)).isEqualTo(ZeroTrustAction.CHALLENGE);
        assertThat(repository.getCurrentAction(user, VICTIM)).isEqualTo(ZeroTrustAction.PENDING_ANALYSIS);
    }

    @Test
    @DisplayName("an ALLOW analysed for a session still stopped stays out, and one for the session that answered is written")
    void aLessStrictResultOfAStoppedSessionStaysOut() {
        challenge();
        answeredIn(VICTIM);

        assertThat(repository.writeFinalAction(user, ZeroTrustAction.ALLOW, decision(ATTACKER)))
                .isEqualTo(ZeroTrustActionRepository.FinalActionWrite.KEPT_STRICTER);
        assertThat(repository.getCurrentAction(user, VICTIM)).isEqualTo(ZeroTrustAction.ALLOW);

        assertThat(repository.writeFinalAction(user, ZeroTrustAction.ALLOW, decision(VICTIM)))
                .isEqualTo(ZeroTrustActionRepository.FinalActionWrite.APPLIED);
    }

    @Test
    @DisplayName("a new CHALLENGE stops the session that answered the last one, and its answer counts for itself alone")
    void aNewChallengeStartsOver() {
        challenge();
        answeredIn(VICTIM);

        assertThat(repository.writeFinalAction(user, ZeroTrustAction.CHALLENGE, decision(VICTIM)))
                .isEqualTo(ZeroTrustActionRepository.FinalActionWrite.APPLIED);
        assertThat(repository.getCurrentAction(user, VICTIM)).isEqualTo(ZeroTrustAction.CHALLENGE);

        answeredIn(SECOND_DEVICE);

        assertThat(repository.getCurrentAction(user, SECOND_DEVICE)).isEqualTo(ZeroTrustAction.ALLOW);
        assertThat(repository.getCurrentAction(user, VICTIM)).isEqualTo(ZeroTrustAction.CHALLENGE);
    }

    @Test
    @DisplayName("a BLOCK and an ESCALATE stay stricter than what is held")
    void aStricterDecisionStays() {
        challenge();
        answeredIn(VICTIM);

        repository.saveAction(user, ZeroTrustAction.ESCALATE, Map.of());
        assertThat(repository.getCurrentAction(user, ATTACKER)).isEqualTo(ZeroTrustAction.ESCALATE);

        repository.setBlockedFlag(user);
        assertThat(repository.getCurrentAction(user, VICTIM)).isEqualTo(ZeroTrustAction.BLOCK);
    }

    @Test
    @DisplayName("an administrator's override ends it for every session")
    void anOverrideEndsIt() {
        challenge();
        answeredIn(VICTIM);

        repository.approveOverrideAtomically(user, ZeroTrustAction.ALLOW);

        assertThat(repository.getCurrentAction(user, ATTACKER)).isNotEqualTo(ZeroTrustAction.CHALLENGE);
    }

    @Test
    @DisplayName("removing the user's data ends it")
    void removalEndsIt() {
        challenge();
        answeredIn(VICTIM);

        repository.removeAllUserData(user);

        assertThat(repository.getCurrentAction(user, ATTACKER)).isEqualTo(ZeroTrustAction.PENDING_ANALYSIS);
    }

    @Test
    @DisplayName("without a CHALLENGE nothing is held")
    void withoutAChallengeNothingIsHeld() {
        repository.holdChallengeForOtherSessions(user, VICTIM);
        repository.saveActionWithPrevious(user, ZeroTrustAction.ALLOW, VICTIM);

        assertThat(repository.getCurrentAction(user, ATTACKER)).isEqualTo(ZeroTrustAction.PENDING_ANALYSIS);
        assertThat(repository.challengeHeldSince(user)).isNull();
    }

    @Test
    @DisplayName("what is held says when the CHALLENGE was decided, whatever the analysis holds by now")
    void itKeepsTheTimeOfTheChallenge() {
        Instant before = Instant.now().minusSeconds(1);
        challenge();
        answeredIn(VICTIM);

        repository.removeLogoutData(user);

        assertThat(repository.challengeHeldSince(user)).isAfter(before).isBeforeOrEqualTo(Instant.now());
    }

    @Test
    @DisplayName("the spellings of a name share what is held")
    void theSpellingsOfANameShareIt() {
        challenge();
        repository.holdChallengeForOtherSessions(user.toUpperCase(Locale.ROOT), VICTIM);
        repository.saveActionWithPrevious(user, ZeroTrustAction.ALLOW, VICTIM);

        assertThat(repository.getCurrentAction(user.toUpperCase(Locale.ROOT), ATTACKER))
                .isEqualTo(ZeroTrustAction.CHALLENGE);
    }
}
