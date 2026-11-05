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

import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.atomic.AtomicInteger;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.anyString;
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
    private ZeroTrustActionRedisRepository repository;

    @BeforeEach
    @SuppressWarnings("unchecked")
    void setUp() {
        strings = mock(StringRedisTemplate.class);
        objects = mock(RedisTemplate.class);
        values = mock(ValueOperations.class);
        analysis = mock(HashOperations.class);
        when(strings.opsForValue()).thenReturn(values);
        when(objects.opsForHash()).thenReturn(analysis);
        when(analysis.entries(anyString())).thenReturn(Map.of());
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
}
