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
import io.contexa.contexacore.testsupport.RedisTestTemplates;
import io.contexa.contexacore.testsupport.TestStores;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.data.redis.connection.RedisStandaloneConfiguration;
import org.springframework.data.redis.connection.lettuce.LettuceConnectionFactory;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.data.redis.core.StringRedisTemplate;

import java.util.ArrayList;
import java.util.List;
import java.util.UUID;
import java.util.function.Consumer;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * A call of {@code getCurrentAction(user, context)} reads three things, the BLOCK flag, the analysis and the CHALLENGE held for
 * other sessions, and asks for them in one round trip. It must answer what the three reads one after the other answer: the
 * same user in the same state is read both ways and the answers are compared, for every state a user can be in, a flag
 * stored under the name as typed and an analysis in the form an earlier version wrote. Keys of their own in a shared Redis:
 * nothing here flushes it.
 */
class ZeroTrustActionRedisRepositoryOneTripReadTest {

    private static LettuceConnectionFactory connectionFactory;
    private static RedisTemplate<String, Object> redisTemplate;
    private static StringRedisTemplate stringRedisTemplate;

    private ZeroTrustActionRedisRepository repository;
    private String user;

    @BeforeAll
    static void connect() {
        TestStores.Redis server = TestStores.redis();
        connectionFactory = new LettuceConnectionFactory(new RedisStandaloneConfiguration(server.host(), server.port()));
        connectionFactory.afterPropertiesSet();
        redisTemplate = RedisTestTemplates.newProductionAlignedRedisTemplate(connectionFactory);
        stringRedisTemplate = RedisTestTemplates.newStringRedisTemplate(connectionFactory);
    }

    @AfterAll
    static void disconnect() {
        if (connectionFactory != null) {
            connectionFactory.destroy();
        }
    }

    @BeforeEach
    void newUser() {
        repository = new ZeroTrustActionRedisRepository(redisTemplate, stringRedisTemplate);
        user = "One-Trip-" + UUID.randomUUID();
    }

    @AfterEach
    void removeTheUser() {
        repository.useOneTripReads(true);
        repository.removeAllUserData(user);
        stringRedisTemplate.delete(ZeroTrustRedisKeys.userBlockedAsTyped(user));
    }

    private ZeroTrustAction read(boolean oneTrip, String context) {
        repository.useOneTripReads(oneTrip);
        return repository.getCurrentAction(user, context);
    }

    /** The user is read for every context both ways; the answers are the same and the one-trip read was used where it can be. */
    private List<ZeroTrustAction> sameBothWays(String state) {
        List<ZeroTrustAction> answers = new ArrayList<>();
        for (String context : new String[]{null, "context-a", "context-b"}) {
            ZeroTrustAction oneByOne = read(false, context);
            long before = repository.oneTripReads();
            ZeroTrustAction inOneTrip = read(true, context);
            assertThat(inOneTrip).as("%s, context %s", state, context).isEqualTo(oneByOne);
            answers.add(inOneTrip);
            assertThat(repository.oneTripReads()).as("%s, context %s: read in one trip", state, context).isEqualTo(before + 1);
        }
        return answers;
    }

    private void in(Consumer<ZeroTrustActionRedisRepository> state, String name) {
        state.accept(repository);
        sameBothWays(name);
    }

    @Test
    @DisplayName("a user nothing is stored for reads pending, both ways")
    void nothingStored() {
        assertThat(sameBothWays("nothing stored")).containsOnly(ZeroTrustAction.PENDING_ANALYSIS);
    }

    @Test
    @DisplayName("an ALLOW, a CHALLENGE, a BLOCK and an ESCALATE read the same both ways, for the context that decided and for others")
    void everyAction() {
        in(r -> r.saveActionWithPrevious(user, ZeroTrustAction.ALLOW, "context-a"), "ALLOW");
        in(r -> r.saveActionWithPrevious(user, ZeroTrustAction.CHALLENGE, "context-a"), "CHALLENGE");
        in(r -> r.saveActionWithPrevious(user, ZeroTrustAction.ESCALATE, "context-a"), "ESCALATE");
        in(r -> r.saveActionWithPrevious(user, ZeroTrustAction.BLOCK, "context-a"), "BLOCK");
    }

    @Test
    @DisplayName("a CHALLENGE held for the other sessions reads the same both ways, for the session that answered and for the others")
    void aHeldChallenge() {
        repository.saveActionWithPrevious(user, ZeroTrustAction.CHALLENGE, "context-a");
        repository.holdChallengeForOtherSessions(user, "context-a");
        repository.saveActionWithPrevious(user, ZeroTrustAction.ALLOW, "context-a");

        List<ZeroTrustAction> answers = sameBothWays("held CHALLENGE");

        assertThat(answers).contains(ZeroTrustAction.CHALLENGE);
    }

    @Test
    @DisplayName("a BLOCK flag alone, and a flag stored under the name as typed, read BLOCK both ways")
    void blockFlags() {
        repository.setBlockedFlag(user);
        assertThat(sameBothWays("flag")).containsOnly(ZeroTrustAction.BLOCK);

        repository.removeBlockedFlag(user);
        stringRedisTemplate.opsForValue().set(ZeroTrustRedisKeys.userBlockedAsTyped(user), "true");
        assertThat(sameBothWays("flag as typed")).containsOnly(ZeroTrustAction.BLOCK);
    }

    @Test
    @DisplayName("an analysis in the form an earlier version wrote is read the old way and answers the same")
    void anAnalysisInTheEarlierForm() {
        stringRedisTemplate.opsForHash().put(ZeroTrustRedisKeys.autonomousActionAnalysis(user), "action", "BLOCK");
        repository.useOneTripReads(false);
        ZeroTrustAction oneByOne = repository.getCurrentAction(user, "context-a");
        long before = repository.oneTripReads();

        repository.useOneTripReads(true);
        ZeroTrustAction inOneTrip = repository.getCurrentAction(user, "context-a");

        assertThat(inOneTrip).isEqualTo(oneByOne);
        assertThat(repository.oneTripReads()).as("the form no longer read in one trip falls back to the reads one by one").isEqualTo(before);
    }

    @Test
    @DisplayName("a restriction read in one trip stays in force while Redis does not answer, as one read the old way does")
    void aRestrictionStaysInForceThroughAnOutage() {
        TestStores.Redis server = TestStores.redis();
        LettuceConnectionFactory own = new LettuceConnectionFactory(new RedisStandaloneConfiguration(server.host(), server.port()));
        own.afterPropertiesSet();
        ZeroTrustActionRedisRepository onItsOwn = new ZeroTrustActionRedisRepository(
                RedisTestTemplates.newProductionAlignedRedisTemplate(own), RedisTestTemplates.newStringRedisTemplate(own));
        repository.setBlockedFlag(user);
        onItsOwn.useOneTripReads(true);
        assertThat(onItsOwn.getCurrentAction(user, "context-a")).isEqualTo(ZeroTrustAction.BLOCK);
        assertThat(onItsOwn.oneTripReads()).isEqualTo(1L);

        own.destroy();

        assertThat(onItsOwn.getCurrentAction(user, "context-a")).as("in one trip").isEqualTo(ZeroTrustAction.BLOCK);
        onItsOwn.useOneTripReads(false);
        assertThat(onItsOwn.getCurrentAction(user, "context-a")).as("one by one").isEqualTo(ZeroTrustAction.BLOCK);
        assertThat(onItsOwn.getCurrentAction("a-user-nothing-was-read-for", "context-a")).as("no restriction read: goes on undecided")
                .isEqualTo(ZeroTrustAction.PENDING_ANALYSIS);
    }

    @Test
    @DisplayName("an ESCALATE that is replaced when it is read is replaced the same way")
    void aReplacedEscalate() {
        repository.setEscalateTerminalAction(ZeroTrustAction.BLOCK);
        repository.saveActionWithPrevious(user, ZeroTrustAction.ESCALATE, "context-a");

        ZeroTrustAction oneByOne = read(false, "context-a");
        repository.saveActionWithPrevious(user, ZeroTrustAction.ESCALATE, "context-a");
        ZeroTrustAction inOneTrip = read(true, "context-a");

        assertThat(inOneTrip).isEqualTo(oneByOne);
    }
}
