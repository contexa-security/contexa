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
package io.contexa.contexaidentity.security.core.mfa.policy.evaluator;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.contexa.contexacommon.config.redis.ContexaJsonRedisSerializer;
import io.contexa.contexacore.autonomous.repository.ZeroTrustActionRedisRepository;
import io.contexa.contexacore.autonomous.repository.ZeroTrustActionRepository;
import io.contexa.contexacore.autonomous.utils.ZeroTrustRedisKeys;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.EnabledIfEnvironmentVariable;
import org.springframework.data.redis.connection.RedisConnectionFactory;
import org.springframework.data.redis.connection.lettuce.LettuceConnectionFactory;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.data.redis.serializer.GenericJackson2JsonRedisSerializer;
import org.springframework.data.redis.serializer.StringRedisSerializer;

import java.io.IOException;
import java.net.ServerSocket;

/**
 * The stored decision at a password step on a real Redis (set CONTEXA_BACKLOG_REDIS_PORT), under keys of its own: nothing
 * here flushes the database. An outage is a Redis that does not answer.
 */
@EnabledIfEnvironmentVariable(named = "CONTEXA_BACKLOG_REDIS_PORT", matches = "[0-9]+")
class RedisStoredDecisionSignInTest extends AbstractStoredDecisionSignInContractTest {

    private static final String LOOPBACK = "127.0.0.1";

    private static LettuceConnectionFactory factory;
    private static StringRedisTemplate strings;
    private static ZeroTrustActionRepository store;

    @BeforeAll
    static void connect() {
        factory = connected(Integer.parseInt(System.getenv("CONTEXA_BACKLOG_REDIS_PORT")));
        strings = new StringRedisTemplate(factory);
        store = new ZeroTrustActionRedisRepository(template(factory), strings);
    }

    @AfterAll
    static void close() {
        if (factory != null) {
            factory.destroy();
        }
    }

    @Override
    protected ZeroTrustActionRepository store() {
        return store;
    }

    @Override
    protected void analysisRunsOut(String user) {
        strings.delete(ZeroTrustRedisKeys.autonomousActionAnalysis(user));
    }

    @Test
    @DisplayName("a sign-in while Redis does not answer meets the second step")
    void aSignInDuringAnOutageMeetsTheSecondStep() throws IOException {
        LettuceConnectionFactory gone = connected(portNobodyListensOn());
        try {
            SignInPolicyFixture policy = new SignInPolicyFixture(
                    new ZeroTrustActionRedisRepository(template(gone), new StringRedisTemplate(gone)));

            assertAsksForTheSecondStep(policy.provider.evaluateInitialMfaRequirement(
                    SignInPolicyFixture.signIn("sign-in-outage", "198.51.100.77", "curl/8.5.0 (thief)")));
            assertAsksForTheSecondStep(policy.fallback.evaluatePolicy(
                    SignInPolicyFixture.signIn("sign-in-outage", "198.51.100.77", "curl/8.5.0 (thief)")));
        } finally {
            gone.destroy();
        }
    }

    private static LettuceConnectionFactory connected(int port) {
        LettuceConnectionFactory connection = new LettuceConnectionFactory(LOOPBACK, port);
        connection.afterPropertiesSet();
        connection.start();
        return connection;
    }

    private static int portNobodyListensOn() throws IOException {
        try (ServerSocket socket = new ServerSocket(0)) {
            return socket.getLocalPort();
        }
    }

    private static RedisTemplate<String, Object> template(RedisConnectionFactory connection) {
        GenericJackson2JsonRedisSerializer json = new ContexaJsonRedisSerializer(
                ContexaJsonRedisSerializer.activateDefaultTyping(new ObjectMapper()));
        StringRedisSerializer plain = new StringRedisSerializer();
        RedisTemplate<String, Object> template = new RedisTemplate<>();
        template.setConnectionFactory(connection);
        template.setKeySerializer(plain);
        template.setHashKeySerializer(plain);
        template.setValueSerializer(json);
        template.setHashValueSerializer(json);
        template.setDefaultSerializer(json);
        template.afterPropertiesSet();
        return template;
    }
}
