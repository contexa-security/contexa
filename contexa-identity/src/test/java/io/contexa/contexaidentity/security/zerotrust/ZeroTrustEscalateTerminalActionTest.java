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
package io.contexa.contexaidentity.security.zerotrust;

import com.fasterxml.jackson.annotation.JsonAutoDetect;
import com.fasterxml.jackson.annotation.PropertyAccessor;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;
import io.contexa.contexacommon.config.redis.ContexaJsonRedisSerializer;
import io.contexa.contexacommon.enums.ZeroTrustAction;
import io.contexa.contexacore.autonomous.blocking.BlockingSignalBroadcaster;
import io.contexa.contexacore.autonomous.repository.InMemoryZeroTrustActionRepository;
import io.contexa.contexacore.autonomous.repository.ZeroTrustActionRedisRepository;
import io.contexa.contexacore.autonomous.repository.ZeroTrustActionRepository;
import io.contexa.contexacore.autonomous.service.IBlockedUserRecorder;
import io.contexa.contexacore.autonomous.service.SecurityLearningService;
import io.contexa.contexacore.autonomous.utils.ZeroTrustRedisKeys;
import io.contexa.contexacore.autonomous.store.BlockMfaStateStore;
import io.contexa.contexacore.infra.lock.DistributedLockService;
import io.contexa.contexacore.infra.session.MfaSessionRepository;
import io.contexa.contexaidentity.security.filter.handler.MfaStateMachineIntegrator;
import io.contexa.contexaidentity.security.service.AuthUrlProvider;
import io.contexa.contexaidentity.security.service.MfaFlowUrlRegistry;
import io.contexa.contexaidentity.security.utils.AuthResponseWriter;
import jakarta.servlet.FilterChain;
import jakarta.servlet.http.HttpServletResponse;
import org.awaitility.Awaitility;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.EnabledIfEnvironmentVariable;
import org.springframework.data.redis.connection.lettuce.LettuceConnectionFactory;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.data.redis.serializer.GenericJackson2JsonRedisSerializer;
import org.springframework.data.redis.serializer.StringRedisSerializer;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneId;
import java.time.ZoneOffset;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

/**
 * PR-83, on the real filters and both real repositories: with allow-escalate-final-action off a stored ESCALATE meets
 * the fallback's own answer. The user is not held with a 423, is not promoted to BLOCK and passes the step-up that
 * answers the CHALLENGE. With the setting on, the hold and the promotion stay as they were.
 */
class ZeroTrustEscalateTerminalActionTest {

    private static final String REDIS_PORT = "CONTEXA_BACKLOG_REDIS_PORT";

    private static LettuceConnectionFactory factory;
    private static StringRedisTemplate strings;
    private static RedisTemplate<String, Object> objects;

    private final AuthResponseWriter responseWriter = mock(AuthResponseWriter.class);
    private final IBlockedUserRecorder blockedUserRecorder = mock(IBlockedUserRecorder.class);
    private final FilterChain application = mock(FilterChain.class);

    private String user;

    @BeforeAll
    static void connect() {
        String port = System.getenv(REDIS_PORT);
        if (port == null || !port.matches("[0-9]+")) {
            return;
        }
        factory = new LettuceConnectionFactory("127.0.0.1", Integer.parseInt(port));
        factory.afterPropertiesSet();
        strings = new StringRedisTemplate();
        strings.setConnectionFactory(factory);
        strings.afterPropertiesSet();
        objects = objectTemplate(factory);
    }

    @AfterAll
    static void close() {
        if (factory != null) {
            factory.destroy();
        }
    }

    @BeforeEach
    void signIn() {
        user = "pr83-filter-" + UUID.randomUUID();
        SecurityContextHolder.getContext().setAuthentication(
                new UsernamePasswordAuthenticationToken(user, "n/a", List.of()));
    }

    @AfterEach
    void signOut() {
        SecurityContextHolder.clearContext();
    }

    // ----- allow-escalate-final-action off: what a held user meets after the upgrade -----

    @Test
    void inMemoryAnEscalatePastItsTtlMeetsTheChallengeNotABlock() throws Exception {
        MovingClock clock = new MovingClock();
        InMemoryZeroTrustActionRepository repository = new InMemoryZeroTrustActionRepository(Duration.ofHours(24), clock);
        repository.saveFinalAction(user, ZeroTrustAction.ESCALATE, fields());
        clock.advance(ZeroTrustAction.ESCALATE.getDefaultTtl().plusSeconds(1));

        assertMeetsTheChallenge(repository);
    }

    @Test
    @EnabledIfEnvironmentVariable(named = REDIS_PORT, matches = "[0-9]+")
    void redisAnEscalatePastItsTtlMeetsTheChallengeNotABlock() throws Exception {
        ZeroTrustActionRepository repository = redis();
        repository.saveFinalAction(user, ZeroTrustAction.ESCALATE, fields());
        expireAnalysis();

        assertMeetsTheChallenge(repository);
    }

    @Test
    void inMemoryALiveEscalateMeetsTheChallengeNotAHold() throws Exception {
        InMemoryZeroTrustActionRepository repository = new InMemoryZeroTrustActionRepository();
        repository.saveFinalAction(user, ZeroTrustAction.ESCALATE, fields());

        assertMeetsTheChallenge(repository);
    }

    @Test
    @EnabledIfEnvironmentVariable(named = REDIS_PORT, matches = "[0-9]+")
    void redisALiveEscalateMeetsTheChallengeNotAHold() throws Exception {
        ZeroTrustActionRepository repository = redis();
        repository.saveFinalAction(user, ZeroTrustAction.ESCALATE, fields());

        assertMeetsTheChallenge(repository);
    }

    private void assertMeetsTheChallenge(ZeroTrustActionRepository repository) throws Exception {
        repository.setEscalateTerminalAction(ZeroTrustAction.CHALLENGE);
        ZeroTrustChallengeFilter challenge = challengeFilter(repository);
        ZeroTrustAccessControlFilter accessControl = accessControlFilter(repository, ZeroTrustAction.CHALLENGE);

        // Twice: a BLOCK was reached by the request after the one that found the ESCALATE lapsed.
        for (int request = 0; request < 2; request++) {
            MockHttpServletResponse response = new MockHttpServletResponse();
            challenge.doFilter(apiRequest(), response, (req, res) -> accessControl.doFilter(req, res, application));
            assertThat(response.getHeader("Retry-After")).isNull();
            assertThat(response.getRedirectedUrl()).isNull();
        }

        verify(responseWriter, times(2)).writeErrorResponse(any(),
                eq(HttpServletResponse.SC_UNAUTHORIZED), eq("ZERO_TRUST_CHALLENGE"), anyString(), anyString(), any());
        verify(responseWriter, never()).writeErrorResponse(any(), eq(423), anyString(), anyString(), anyString(), any());
        verify(responseWriter, never()).writeErrorResponse(any(), eq(HttpServletResponse.SC_FORBIDDEN), anyString(),
                anyString(), anyString(), any());
        verifyNoInteractions(application);
        verifyNoInteractions(blockedUserRecorder);
        assertThat(repository.getCurrentAction(user, "context-1")).isEqualTo(ZeroTrustAction.CHALLENGE);
        repository.removeAllUserData(user);
    }

    /** The access filter alone, on a path the challenge filter leaves to the sign-in: nothing promotes the user. */
    @Test
    void inMemoryTheAccessFilterAloneLeavesTheEndedActionToTheChallenge() throws Exception {
        MovingClock clock = new MovingClock();
        InMemoryZeroTrustActionRepository repository = new InMemoryZeroTrustActionRepository(Duration.ofHours(24), clock);
        repository.saveFinalAction(user, ZeroTrustAction.ESCALATE, fields());
        clock.advance(ZeroTrustAction.ESCALATE.getDefaultTtl().plusSeconds(1));
        repository.setEscalateTerminalAction(ZeroTrustAction.CHALLENGE);

        accessControlFilter(repository, ZeroTrustAction.CHALLENGE)
                .doFilter(apiRequest(), new MockHttpServletResponse(), application);

        verify(application).doFilter(any(), any());
        verifyNoInteractions(blockedUserRecorder);
        assertThat(repository.getCurrentAction(user, "context-1")).isEqualTo(ZeroTrustAction.CHALLENGE);
    }

    /** The step-up answers the ended CHALLENGE, which an ESCALATE never let it do. */
    @Test
    void inMemoryTheStepUpReleasesTheUser() {
        MovingClock clock = new MovingClock();
        InMemoryZeroTrustActionRepository repository = new InMemoryZeroTrustActionRepository(Duration.ofHours(24), clock);
        repository.saveFinalAction(user, ZeroTrustAction.ESCALATE, fields());
        clock.advance(ZeroTrustAction.ESCALATE.getDefaultTtl().plusSeconds(1));
        repository.setEscalateTerminalAction(ZeroTrustAction.CHALLENGE);

        assertStepUpReleases(repository);
    }

    @Test
    @EnabledIfEnvironmentVariable(named = REDIS_PORT, matches = "[0-9]+")
    void redisTheStepUpReleasesTheUser() {
        ZeroTrustActionRepository repository = redis();
        repository.saveFinalAction(user, ZeroTrustAction.ESCALATE, fields());
        expireAnalysis();
        repository.setEscalateTerminalAction(ZeroTrustAction.CHALLENGE);

        assertStepUpReleases(repository);
        repository.removeAllUserData(user);
    }

    private void assertStepUpReleases(ZeroTrustActionRepository repository) {
        assertThat(repository.getCurrentAction(user, "context-1")).isEqualTo(ZeroTrustAction.CHALLENGE);
        ChallengeResolution resolution = new ChallengeResolution(repository, mock(SecurityLearningService.class),
                () -> null, () -> null, mock(BlockingSignalBroadcaster.class), blockedUserRecorder,
                mock(BlockMfaStateStore.class));

        assertThat(resolution.releaseChallenge(user, "context-1", new MockHttpServletRequest(), null)).isTrue();

        assertThat(repository.getCurrentAction(user, "context-1")).isEqualTo(ZeroTrustAction.ALLOW);
    }

    /**
     * A repository of the application's own ends nothing by itself and may answer ESCALATE for as long as it keeps one:
     * the filter ends it there, once, never as a BLOCK; the retry meets the fallback.
     */
    @Test
    void aRepositoryThatKeepsItsEscalateIsEndedByTheFilterNotPromoted() throws Exception {
        ZeroTrustActionRepository own = mock(ZeroTrustActionRepository.class);
        when(own.getCurrentAction(eq(user), anyString())).thenReturn(ZeroTrustAction.ESCALATE);

        accessControlFilter(own, ZeroTrustAction.CHALLENGE)
                .doFilter(apiRequest(), new MockHttpServletResponse(), application);

        verify(own).saveAction(eq(user), eq(ZeroTrustAction.CHALLENGE), any());
        verify(own, never()).saveAction(eq(user), eq(ZeroTrustAction.BLOCK), any());
        verify(own, never()).setBlockedFlag(anyString());
        verifyNoInteractions(blockedUserRecorder);
        verifyNoInteractions(application);
    }

    // ----- what stays as it was -----

    /** allow-escalate-final-action on: 423 while the analysis is in its TTL, a BLOCK with its record after it. */
    @Test
    void inMemoryAnAllowedFinalEscalateIsHeldAndThenPromoted() throws Exception {
        MovingClock clock = new MovingClock();
        InMemoryZeroTrustActionRepository repository = new InMemoryZeroTrustActionRepository(Duration.ofHours(24), clock);
        repository.saveFinalAction(user, ZeroTrustAction.ESCALATE, fields());

        accessControlFilter(repository, null).doFilter(apiRequest(), new MockHttpServletResponse(), application);

        verify(responseWriter).writeErrorResponse(any(), eq(423), eq("SECURITY_REVIEW_IN_PROGRESS"), anyString(),
                anyString(), any());

        clock.advance(Duration.ofMinutes(6));
        accessControlFilter(repository, null).doFilter(apiRequest(), new MockHttpServletResponse(), application);

        assertPromoted(repository);
    }

    @Test
    @EnabledIfEnvironmentVariable(named = REDIS_PORT, matches = "[0-9]+")
    void redisAnAllowedFinalEscalateIsPromotedPastItsTtl() throws Exception {
        ZeroTrustActionRepository repository = redis();
        repository.saveFinalAction(user, ZeroTrustAction.ESCALATE, fields());
        expireAnalysis();

        accessControlFilter(repository, null).doFilter(apiRequest(), new MockHttpServletResponse(), application);

        assertPromoted(repository);
        repository.removeAllUserData(user);
    }

    /** escalate-fallback-action BLOCK: the setting asks for a BLOCK; the filter writes it with its flag and record. */
    @Test
    void inMemoryATerminalBlockIsWrittenByTheFilterWithItsRecord() throws Exception {
        MovingClock clock = new MovingClock();
        InMemoryZeroTrustActionRepository repository = new InMemoryZeroTrustActionRepository(Duration.ofHours(24), clock);
        repository.saveFinalAction(user, ZeroTrustAction.ESCALATE, fields());
        clock.advance(ZeroTrustAction.ESCALATE.getDefaultTtl().plusSeconds(1));
        repository.setEscalateTerminalAction(ZeroTrustAction.BLOCK);

        accessControlFilter(repository, ZeroTrustAction.BLOCK)
                .doFilter(apiRequest(), new MockHttpServletResponse(), application);

        assertPromoted(repository);
    }

    private void assertPromoted(ZeroTrustActionRepository repository) throws Exception {
        assertThat(repository.getCurrentAction(user, "context-1")).isEqualTo(ZeroTrustAction.BLOCK);
        verify(blockedUserRecorder).recordBlock(anyString(), eq(user), any(), eq("BLOCK"),
                eq("Auto-promoted from ESCALATE: TTL expired without resolution"), any(), any());
        verify(responseWriter).writeErrorResponse(any(), eq(HttpServletResponse.SC_FORBIDDEN), eq("ACCOUNT_BLOCKED"),
                anyString(), anyString(), any());
    }

    private ZeroTrustChallengeFilter challengeFilter(ZeroTrustActionRepository repository) {
        ZeroTrustChallengeFilter filter = new ZeroTrustChallengeFilter(mock(ChallengeMfaInitializer.class), responseWriter,
                mock(AuthUrlProvider.class), mock(MfaSessionRepository.class),
                mock(MfaStateMachineIntegrator.class), mock(DistributedLockService.class),
                mock(MfaFlowUrlRegistry.class), repository);
        // The application offers no MFA flow: the filter answers with its 401 itself.
        filter.setChallengeProcedureAvailable(false);
        return filter;
    }

    private ZeroTrustAccessControlFilter accessControlFilter(ZeroTrustActionRepository repository,
                                                             ZeroTrustAction terminalAction) {
        ZeroTrustAccessControlFilter filter = new ZeroTrustAccessControlFilter(repository, responseWriter,
                blockedUserRecorder, mock(ChallengeMfaInitializer.class), mock(AuthUrlProvider.class),
                mock(BlockingSignalBroadcaster.class), 2);
        filter.setEscalateTerminalAction(terminalAction);
        return filter;
    }

    private static MockHttpServletRequest apiRequest() {
        MockHttpServletRequest request = new MockHttpServletRequest("GET", "/api/owners");
        request.addHeader("Accept", "application/json");
        request.addHeader("User-Agent", "TestAgent");
        return request;
    }

    private static Map<String, Object> fields() {
        Map<String, Object> fields = new HashMap<>();
        fields.put("observationId", "observation-" + UUID.randomUUID());
        fields.put("processingGeneration", "generation-" + UUID.randomUUID());
        fields.put("contextBindingHash", "context-1");
        fields.put("requestId", "request-1");
        return fields;
    }

    private static ZeroTrustActionRepository redis() {
        return new ZeroTrustActionRedisRepository(objects, strings);
    }

    private void expireAnalysis() {
        String key = ZeroTrustRedisKeys.autonomousActionAnalysis(user);
        strings.expire(key, Duration.ofMillis(200));
        Awaitility.await().atMost(Duration.ofSeconds(5)).until(() -> !Boolean.TRUE.equals(strings.hasKey(key)));
    }

    /** The production Redis template: string keys, Contexa's typed JSON values. */
    private static RedisTemplate<String, Object> objectTemplate(LettuceConnectionFactory connections) {
        ObjectMapper mapper = new ObjectMapper();
        mapper.registerModule(new JavaTimeModule());
        mapper.disable(SerializationFeature.WRITE_DATES_AS_TIMESTAMPS);
        mapper.setVisibility(PropertyAccessor.ALL, JsonAutoDetect.Visibility.ANY);
        GenericJackson2JsonRedisSerializer json = new ContexaJsonRedisSerializer(
                ContexaJsonRedisSerializer.activateDefaultTyping(mapper));
        StringRedisSerializer keys = new StringRedisSerializer();
        RedisTemplate<String, Object> template = new RedisTemplate<>();
        template.setConnectionFactory(connections);
        template.setKeySerializer(keys);
        template.setHashKeySerializer(keys);
        template.setValueSerializer(json);
        template.setHashValueSerializer(json);
        template.setDefaultSerializer(json);
        template.setEnableTransactionSupport(false);
        template.afterPropertiesSet();
        return template;
    }

    /** A clock a test moves forward, so that stored keys expire without waiting. */
    private static final class MovingClock extends Clock {

        private volatile Duration offset = Duration.ZERO;

        void advance(Duration amount) {
            offset = offset.plus(amount);
        }

        @Override
        public ZoneId getZone() {
            return ZoneOffset.UTC;
        }

        @Override
        public Clock withZone(ZoneId zone) {
            return this;
        }

        @Override
        public Instant instant() {
            return Instant.now().plus(offset);
        }
    }
}
