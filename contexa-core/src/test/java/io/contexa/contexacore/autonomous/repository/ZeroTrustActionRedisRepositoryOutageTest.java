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
import io.contexa.contexacore.autonomous.utils.ZeroTrustRedisKeys;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.dao.QueryTimeoutException;
import org.springframework.data.redis.core.HashOperations;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.data.redis.core.ValueOperations;

import java.time.Duration;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.HashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.anyCollection;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.reset;
import static org.mockito.Mockito.when;

/**
 * D-1 (PR-84): a decision that cannot be read is no decision to pass on. What this server read last stays in force while
 * Redis does not answer: a restriction is never lowered by an outage, while a user without one goes on.
 */
class ZeroTrustActionRedisRepositoryOutageTest {

    private static final String USER = "plain-bad";
    private static final String CONTEXT = "context-a";

    private StringRedisTemplate strings;
    private RedisTemplate<String, Object> objects;
    private ValueOperations<String, String> values;
    private HashOperations<String, Object, Object> analysis;
    private HashOperations<String, Object, Object> holds;
    private ZeroTrustActionRedisRepository repository;

    @BeforeEach
    @SuppressWarnings("unchecked")
    void setUp() {
        strings = mock(StringRedisTemplate.class);
        objects = mock(RedisTemplate.class);
        values = mock(ValueOperations.class);
        analysis = mock(HashOperations.class);
        holds = mock(HashOperations.class);
        when(strings.opsForValue()).thenReturn(values);
        when(strings.opsForHash()).thenReturn(holds);
        when(objects.opsForHash()).thenReturn(analysis);
        when(analysis.entries(anyString())).thenReturn(Map.of());
        when(holds.multiGet(anyString(), anyCollection())).thenReturn(Arrays.asList(null, null));
        repository = new ZeroTrustActionRedisRepository(objects, strings);
    }

    private void stored(ZeroTrustAction action, String context) {
        Map<Object, Object> entries = new HashMap<>();
        entries.put("action", action.name());
        if (context != null) {
            entries.put("contextBindingHash", context);
        }
        when(analysis.entries(ZeroTrustRedisKeys.autonomousActionAnalysis(USER))).thenReturn(entries);
    }

    private void redisStopsAnswering() {
        when(values.get(anyString())).thenThrow(new QueryTimeoutException("Redis command timed out"));
        when(analysis.entries(anyString())).thenThrow(new QueryTimeoutException("Redis command timed out"));
        when(holds.multiGet(anyString(), anyCollection())).thenThrow(new QueryTimeoutException("Redis command timed out"));
    }

    /** Q-12: the CHALLENGE is answered by one session and held for the others. */
    private void heldForTheOtherSessions(String answeredContext) {
        stored(ZeroTrustAction.ALLOW, answeredContext);
        when(holds.multiGet(eq(ZeroTrustRedisKeys.autonomousChallengeHold(USER)), anyCollection())).thenAnswer(call -> {
            List<String> fields = new ArrayList<>(call.<Collection<String>>getArgument(1));
            return Arrays.asList("2026-11-05T10:00:00Z", answeredContext.equals(fields.get(1)) ? "1" : null);
        });
    }

    @Test
    @DisplayName("a BLOCK read before the outage stays in force")
    void aBlockStaysInForce() {
        when(values.get(ZeroTrustRedisKeys.userBlocked(USER))).thenReturn("true");
        assertThat(repository.getCurrentAction(USER, CONTEXT)).isEqualTo(ZeroTrustAction.BLOCK);

        redisStopsAnswering();

        assertThat(repository.getCurrentAction(USER, CONTEXT)).isEqualTo(ZeroTrustAction.BLOCK);
        assertThat(repository.getCurrentAction(USER, "another-context")).isEqualTo(ZeroTrustAction.BLOCK);
    }

    @Test
    @DisplayName("a CHALLENGE read before the outage stays in force")
    void aChallengeStaysInForce() {
        stored(ZeroTrustAction.CHALLENGE, CONTEXT);
        assertThat(repository.getCurrentAction(USER, CONTEXT)).isEqualTo(ZeroTrustAction.CHALLENGE);

        redisStopsAnswering();

        assertThat(repository.getCurrentAction(USER, CONTEXT)).isEqualTo(ZeroTrustAction.CHALLENGE);
    }

    @Test
    @DisplayName("an ESCALATE read before the outage stays in force")
    void anEscalateStaysInForce() {
        stored(ZeroTrustAction.ESCALATE, CONTEXT);
        assertThat(repository.getCurrentAction(USER, CONTEXT)).isEqualTo(ZeroTrustAction.ESCALATE);

        redisStopsAnswering();

        assertThat(repository.getCurrentAction(USER, CONTEXT)).isEqualTo(ZeroTrustAction.ESCALATE);
    }

    @Test
    @DisplayName("the read without a context keeps a restriction too")
    void theReadWithoutAContextKeepsARestriction() {
        when(values.get(ZeroTrustRedisKeys.userBlocked(USER))).thenReturn("true");
        assertThat(repository.getCurrentAction(USER)).isEqualTo(ZeroTrustAction.BLOCK);

        redisStopsAnswering();

        assertThat(repository.getCurrentAction(USER)).isEqualTo(ZeroTrustAction.BLOCK);
    }

    @Test
    @DisplayName("an ALLOW read before the outage is no restriction: the request goes on as undecided")
    void anAllowIsNoRestriction() {
        stored(ZeroTrustAction.ALLOW, CONTEXT);
        assertThat(repository.getCurrentAction(USER, CONTEXT)).isEqualTo(ZeroTrustAction.ALLOW);

        redisStopsAnswering();

        assertThat(repository.getCurrentAction(USER, CONTEXT)).isEqualTo(ZeroTrustAction.PENDING_ANALYSIS);
    }

    @Test
    @DisplayName("a user this server never read goes on as undecided")
    void anUnknownUserGoesOn() {
        redisStopsAnswering();

        assertThat(repository.getCurrentAction(USER, CONTEXT)).isEqualTo(ZeroTrustAction.PENDING_ANALYSIS);
    }

    @Test
    @DisplayName("a restriction lifted before the outage does not come back with it")
    void aLiftedRestrictionDoesNotComeBack() {
        when(values.get(ZeroTrustRedisKeys.userBlocked(USER))).thenReturn("true");
        assertThat(repository.getCurrentAction(USER, CONTEXT)).isEqualTo(ZeroTrustAction.BLOCK);
        when(values.get(ZeroTrustRedisKeys.userBlocked(USER))).thenReturn(null);
        stored(ZeroTrustAction.ALLOW, CONTEXT);
        assertThat(repository.getCurrentAction(USER, CONTEXT)).isEqualTo(ZeroTrustAction.ALLOW);

        redisStopsAnswering();

        assertThat(repository.getCurrentAction(USER, CONTEXT)).isEqualTo(ZeroTrustAction.PENDING_ANALYSIS);
    }

    @Test
    @DisplayName("Q-18: every spelling of a name meets what was read under another")
    void everySpellingMeetsTheRestriction() {
        when(values.get(ZeroTrustRedisKeys.userBlocked(USER))).thenReturn("true");
        assertThat(repository.getCurrentAction(USER, CONTEXT)).isEqualTo(ZeroTrustAction.BLOCK);

        redisStopsAnswering();

        assertThat(repository.getCurrentAction(USER.toUpperCase(Locale.ROOT), CONTEXT)).isEqualTo(ZeroTrustAction.BLOCK);
    }

    @Test
    @DisplayName("Q-12: a CHALLENGE held for other sessions stays held when the one that answered read last")
    void aHoldStaysForTheOtherSessions() {
        heldForTheOtherSessions(CONTEXT);
        assertThat(repository.getCurrentAction(USER, CONTEXT)).isEqualTo(ZeroTrustAction.ALLOW);

        redisStopsAnswering();

        assertThat(repository.getCurrentAction(USER, "attackers-session")).isEqualTo(ZeroTrustAction.CHALLENGE);
        assertThat(repository.getCurrentAction(USER, CONTEXT)).as("the session that answered is not stopped by the outage")
                .isEqualTo(ZeroTrustAction.PENDING_ANALYSIS);
    }

    @Test
    @DisplayName("Q-12: a session that did not answer stays stopped when it read last")
    void aSessionThatDidNotAnswerStaysStopped() {
        heldForTheOtherSessions(CONTEXT);
        assertThat(repository.getCurrentAction(USER, "attackers-session")).isEqualTo(ZeroTrustAction.CHALLENGE);

        redisStopsAnswering();

        assertThat(repository.getCurrentAction(USER, "attackers-session")).isEqualTo(ZeroTrustAction.CHALLENGE);
    }

    @Test
    @DisplayName("a block this server never read is found in the database's record")
    void aBlockThisServerNeverReadIsFoundInTheRecord() {
        repository.setBlockRecord(USER::equals);
        redisStopsAnswering();

        assertThat(repository.getCurrentAction(USER, CONTEXT)).isEqualTo(ZeroTrustAction.BLOCK);
        assertThat(repository.getCurrentAction("someone-else", CONTEXT)).isEqualTo(ZeroTrustAction.PENDING_ANALYSIS);
    }

    @Test
    @DisplayName("the record is asked once for a user, not at every request of the outage")
    void theRecordIsAskedOnce() {
        AtomicInteger asked = new AtomicInteger();
        repository.setBlockRecord(user -> {
            asked.incrementAndGet();
            return false;
        });
        redisStopsAnswering();

        repository.getCurrentAction(USER, CONTEXT);
        repository.getCurrentAction(USER, CONTEXT);
        repository.getCurrentAction(USER);

        assertThat(asked).hasValue(1);
    }

    @Test
    @DisplayName("a record that cannot be read either leaves the user undecided: both stores are away")
    void aRecordThatCannotBeRead() {
        repository.setBlockRecord(user -> {
            throw new QueryTimeoutException("the database does not answer");
        });
        redisStopsAnswering();

        assertThat(repository.getCurrentAction(USER, CONTEXT)).isEqualTo(ZeroTrustAction.PENDING_ANALYSIS);
    }

    @Test
    @DisplayName("a read while Redis answers does not ask the record: the database is no part of a normal request")
    void aNormalReadDoesNotAskTheRecord() {
        AtomicInteger asked = new AtomicInteger();
        repository.setBlockRecord(user -> {
            asked.incrementAndGet();
            return true;
        });

        assertThat(repository.getCurrentAction(USER, CONTEXT)).isEqualTo(ZeroTrustAction.PENDING_ANALYSIS);

        assertThat(asked).hasValue(0);
    }

    @Test
    @DisplayName("a decision bound to another session stays what it is: the reader was not its subject")
    void aDecisionOfAnotherSessionStaysThatSessions() {
        stored(ZeroTrustAction.ALLOW, CONTEXT);
        assertThat(repository.getCurrentAction(USER, "another-context")).isEqualTo(ZeroTrustAction.PENDING_ANALYSIS);
    }

    private void storedAChallengeNoModelDecided(Object mark) {
        Map<Object, Object> entries = new HashMap<>();
        entries.put("action", ZeroTrustAction.CHALLENGE.name());
        entries.put("contextBindingHash", CONTEXT);
        entries.put(ZeroTrustActionRepository.TECHNICAL_CHALLENGE, mark);
        when(analysis.entries(ZeroTrustRedisKeys.autonomousActionAnalysis(USER))).thenReturn(entries);
    }

    @Test
    @DisplayName("A CHALLENGE no model decided stands no longer than its own short time through an outage")
    void aChallengeNoModelDecidedStaysShort() {
        storedAChallengeNoModelDecided(true);
        assertThat(repository.getCurrentAction(USER, CONTEXT)).isEqualTo(ZeroTrustAction.CHALLENGE);

        redisStopsAnswering();

        assertThat(repository.getCurrentAction(USER, CONTEXT)).as("it still stands").isEqualTo(ZeroTrustAction.CHALLENGE);
        assertThat(repository.restrictionHeldMillis(USER))
                .isBetween(1L, ZeroTrustActionRepository.TECHNICAL_CHALLENGE_TTL.toMillis());
    }

    @Test
    @DisplayName("The read without a context knows the mark too")
    void theReadWithoutAContextKnowsTheMark() {
        storedAChallengeNoModelDecided(true);

        assertThat(repository.getCurrentAction(USER)).isEqualTo(ZeroTrustAction.CHALLENGE);

        assertThat(repository.restrictionHeldMillis(USER))
                .isBetween(1L, ZeroTrustActionRepository.TECHNICAL_CHALLENGE_TTL.toMillis());
    }

    @Test
    @DisplayName("The mark is a field that is there, whatever it holds, as the script asks with HEXISTS")
    void theMarkIsAFieldThatIsThere() {
        storedAChallengeNoModelDecided("1");

        assertThat(repository.getCurrentAction(USER, CONTEXT)).isEqualTo(ZeroTrustAction.CHALLENGE);

        assertThat(repository.restrictionHeldMillis(USER))
                .isBetween(1L, ZeroTrustActionRepository.TECHNICAL_CHALLENGE_TTL.toMillis());
    }

    @Test
    @DisplayName("A CHALLENGE the model decided keeps its own time")
    void aChallengeTheModelDecidedKeepsItsOwnTime() {
        stored(ZeroTrustAction.CHALLENGE, CONTEXT);

        assertThat(repository.getCurrentAction(USER, CONTEXT)).isEqualTo(ZeroTrustAction.CHALLENGE);

        assertThat(repository.restrictionHeldMillis(USER))
                .isGreaterThan(ZeroTrustActionRepository.TECHNICAL_CHALLENGE_TTL.toMillis())
                .isLessThanOrEqualTo(ZeroTrustAction.CHALLENGE.getDefaultTtl().toMillis());
    }

    @Test
    @DisplayName("The mark on any other action changes nothing")
    void theMarkOnAnotherActionChangesNothing() {
        Map<Object, Object> entries = new HashMap<>();
        entries.put("action", ZeroTrustAction.ESCALATE.name());
        entries.put(ZeroTrustActionRepository.TECHNICAL_CHALLENGE, true);
        when(analysis.entries(ZeroTrustRedisKeys.autonomousActionAnalysis(USER))).thenReturn(entries);

        assertThat(repository.getCurrentAction(USER, CONTEXT)).isEqualTo(ZeroTrustAction.ESCALATE);

        assertThat(repository.restrictionHeldMillis(USER))
                .isGreaterThan(ZeroTrustActionRepository.TECHNICAL_CHALLENGE_TTL.toMillis());
    }

    @Test
    @DisplayName("A CHALLENGE held for other sessions stands as long as what is held in Redis")
    void aHoldStandsAsLongAsItsKey() {
        heldForTheOtherSessions("answered-session");
        when(strings.getExpire(ZeroTrustRedisKeys.autonomousChallengeHold(USER), TimeUnit.MILLISECONDS)).thenReturn(40_000L);

        assertThat(repository.getCurrentAction(USER, "another-session")).isEqualTo(ZeroTrustAction.CHALLENGE);

        assertThat(repository.restrictionHeldMillis(USER)).isBetween(1L, 40_000L);
    }

    @Test
    @DisplayName("A hold whose time cannot be told stands as a CHALLENGE does")
    void aHoldWithoutATimeStandsAsAChallengeDoes() {
        heldForTheOtherSessions("answered-session");
        when(strings.getExpire(ZeroTrustRedisKeys.autonomousChallengeHold(USER), TimeUnit.MILLISECONDS)).thenReturn(-1L);

        assertThat(repository.getCurrentAction(USER, "another-session")).isEqualTo(ZeroTrustAction.CHALLENGE);

        assertThat(repository.restrictionHeldMillis(USER))
                .isGreaterThan(ZeroTrustActionRepository.TECHNICAL_CHALLENGE_TTL.toMillis());
    }

    @Test
    @DisplayName("A BLOCK stands until a read says otherwise, and nothing is held for an ALLOW")
    void aBlockStandsAndAnAllowHoldsNothing() {
        when(values.get(ZeroTrustRedisKeys.userBlocked(USER))).thenReturn("true");
        assertThat(repository.getCurrentAction(USER, CONTEXT)).isEqualTo(ZeroTrustAction.BLOCK);
        assertThat(repository.restrictionHeldMillis(USER)).isGreaterThan(Duration.ofDays(1000).toMillis());

        when(values.get(ZeroTrustRedisKeys.userBlocked(USER))).thenReturn(null);
        stored(ZeroTrustAction.ALLOW, CONTEXT);
        assertThat(repository.getCurrentAction(USER, CONTEXT)).isEqualTo(ZeroTrustAction.ALLOW);
        assertThat(repository.restrictionHeldMillis(USER)).isZero();
    }

    @Test
    @DisplayName("the store reads again once Redis answers: what it says then counts")
    void theStoreCountsAgainOnceRedisAnswers() {
        when(values.get(ZeroTrustRedisKeys.userBlocked(USER))).thenReturn("true");
        assertThat(repository.getCurrentAction(USER, CONTEXT)).isEqualTo(ZeroTrustAction.BLOCK);
        redisStopsAnswering();
        assertThat(repository.getCurrentAction(USER, CONTEXT)).isEqualTo(ZeroTrustAction.BLOCK);

        reset(values, analysis);
        when(analysis.entries(anyString())).thenReturn(Map.of());

        assertThat(repository.getCurrentAction(USER, CONTEXT)).isEqualTo(ZeroTrustAction.PENDING_ANALYSIS);
    }

    @Test
    @DisplayName("the context on record is no read that answers for an outage: nothing on record would pass the request")
    void theContextOnRecordStaysAFailureInAnOutage() {
        stored(ZeroTrustAction.ALLOW, CONTEXT);
        assertThat(repository.decidedContext(USER)).isEqualTo(CONTEXT);

        redisStopsAnswering();

        assertThatThrownBy(() -> repository.decidedContext(USER)).isInstanceOf(QueryTimeoutException.class);
    }

    @Test
    @DisplayName("past the decision's TTL an unread last verified context stays a failure as well")
    void theLastVerifiedContextStaysAFailureInAnOutage() {
        when(values.get(ZeroTrustRedisKeys.autonomousLastVerifiedActionContext(USER)))
                .thenThrow(new QueryTimeoutException("Redis command timed out"));

        assertThatThrownBy(() -> repository.decidedContext(USER)).isInstanceOf(QueryTimeoutException.class);
    }
}
