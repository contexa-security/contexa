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
package io.contexa.contexaidentity.security.statemachine.core.service;

import io.contexa.contexacommon.enums.AuthType;
import io.contexa.contexacommon.properties.AuthContextProperties;
import io.contexa.contexacommon.properties.MfaSettings;
import io.contexa.contexacore.infra.session.MfaSessionRepository;
import io.contexa.contexaidentity.security.core.bootstrap.ConfiguredFactorFilterProvider;
import io.contexa.contexaidentity.security.core.config.PlatformConfig;
import io.contexa.contexaidentity.security.core.mfa.context.FactorContext;
import io.contexa.contexaidentity.security.core.mfa.model.MfaDecision;
import io.contexa.contexaidentity.security.core.mfa.policy.MfaPolicyProvider;
import io.contexa.contexaidentity.security.core.mfa.policy.NextFactorDecision;
import io.contexa.contexaidentity.security.filter.MfaContinuationFilter;
import io.contexa.contexaidentity.security.filter.MfaStepFilterWrapper;
import io.contexa.contexaidentity.security.filter.handler.MfaStateMachineIntegrator;
import io.contexa.contexaidentity.security.filter.matcher.MfaRequestType;
import io.contexa.contexaidentity.security.filter.matcher.MfaUrlMatcher;
import io.contexa.contexaidentity.security.service.AuthUrlProvider;
import io.contexa.contexaidentity.security.service.MfaFlowUrlRegistry;
import io.contexa.contexaidentity.security.statemachine.action.CompleteMfaAction;
import io.contexa.contexaidentity.security.statemachine.action.DetermineNextFactorAction;
import io.contexa.contexaidentity.security.statemachine.action.HandleFailureAction;
import io.contexa.contexaidentity.security.statemachine.action.InitializeMfaAction;
import io.contexa.contexaidentity.security.statemachine.action.InitiateChallengeAction;
import io.contexa.contexaidentity.security.statemachine.action.SelectFactorAction;
import io.contexa.contexaidentity.security.statemachine.action.VerifyFactorAction;
import io.contexa.contexaidentity.security.statemachine.config.MfaStateMachineConfiguration;
import io.contexa.contexaidentity.security.statemachine.config.StateMachineProperties;
import io.contexa.contexaidentity.security.statemachine.config.kyro.MfaKryoStateMachineSerialisationService;
import io.contexa.contexaidentity.security.statemachine.core.persist.ExpiringRedisRepositoryStateMachinePersist;
import io.contexa.contexaidentity.security.statemachine.core.persist.InMemoryStateMachinePersist;
import io.contexa.contexaidentity.security.statemachine.enums.MfaEvent;
import io.contexa.contexaidentity.security.statemachine.enums.MfaState;
import io.contexa.contexaidentity.security.statemachine.guard.AllFactorsCompletedGuard;
import io.contexa.contexaidentity.security.statemachine.guard.RetryLimitGuard;
import io.contexa.contexaidentity.security.utils.AuthResponseWriter;
import jakarta.servlet.Filter;
import jakarta.servlet.FilterChain;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;
import org.redisson.Redisson;
import org.redisson.api.RedissonClient;
import org.redisson.config.Config;
import org.springframework.context.ApplicationContext;
import org.springframework.data.redis.connection.RedisStandaloneConfiguration;
import org.springframework.data.redis.connection.lettuce.LettuceConnectionFactory;
import org.springframework.data.redis.core.RedisKeyValueAdapter;
import org.springframework.data.redis.core.RedisKeyValueTemplate;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.data.redis.core.mapping.RedisMappingContext;
import org.springframework.data.redis.repository.support.RedisRepositoryFactory;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.authentication.ott.OneTimeTokenAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.statemachine.StateMachine;
import org.springframework.statemachine.config.StateMachineBuilder;
import org.springframework.statemachine.config.StateMachineFactory;
import org.springframework.statemachine.data.redis.RedisPersistingStateMachineInterceptor;
import org.springframework.statemachine.data.redis.RedisStateMachineRepository;
import org.springframework.statemachine.persist.DefaultStateMachinePersister;
import org.springframework.statemachine.persist.StateMachinePersister;
import org.springframework.test.util.ReflectionTestUtils;

import java.io.IOException;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeMap;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.ThreadLocalRandom;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.locks.LockSupport;
import java.util.stream.Stream;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;
import static org.mockito.Mockito.withSettings;

/**
 * PR-102: codes sent at once, through the filters, the state machine and the store of the application. The factor's own
 * filter is the one thing stood in for: it spends the code and finishes the flow in the order of Spring's one-time token
 * filter and the success and failure handlers.
 */
class MfaDoubleClickTest {

    private static final int ROUNDS = 100;
    private static final long CLICK_SPREAD_NANOS = 20_000_000;
    private static final long VERIFICATION_NANOS = 5_000_000;
    private static final String FLOW = "mfa";
    private static final String OTT_STEP = "mfa:mfa_ott:1";
    private static final String FLOW_ATTRIBUTE = "test.flow";
    private static final String RIGHT = "right-code";
    private static final String WRONG = "wrong-code";
    private static final List<GrantedAuthority> ROLES = List.of(new SimpleGrantedAuthority("ROLE_USER"));
    private static final List<MfaEvent> FINISHING = List.of(MfaEvent.FACTOR_VERIFIED_SUCCESS, MfaEvent.DETERMINE_NEXT_FACTOR,
            MfaEvent.ALL_REQUIRED_FACTORS_COMPLETED);

    private static LettuceConnectionFactory connectionFactory;
    private static RedisStateMachineRepository repository;
    private static RedissonClient redisson;

    enum Store { MEMORY, REDIS }

    private final Set<String> liveFlows = ConcurrentHashMap.newKeySet();
    private final List<String> startedFlows = new ArrayList<>();
    private final ExecutorService clicks = Executors.newFixedThreadPool(16);
    private final MfaSettings settings = new MfaSettings();

    private MfaStateMachineConfiguration machineConfiguration;
    private AbstractMfaStateMachineService service;
    private MfaStateMachineIntegrator integrator;
    private MfaContinuationFilter continuation;
    private MfaStepFilterWrapper step;
    private volatile CountDownLatch verifying;
    private volatile CountDownLatch mayFinish;

    static Stream<Store> stores() {
        return MfaFlowOnRedisTest.isRedisAvailable() ? Stream.of(Store.MEMORY, Store.REDIS) : Stream.of(Store.MEMORY);
    }

    @BeforeAll
    static void connect() {
        if (!MfaFlowOnRedisTest.isRedisAvailable()) {
            return;
        }
        connectionFactory = new LettuceConnectionFactory(new RedisStandaloneConfiguration(MfaFlowOnRedisTest.REDIS_HOST, MfaFlowOnRedisTest.REDIS_PORT));
        connectionFactory.afterPropertiesSet();
        RedisTemplate<byte[], byte[]> bytes = new RedisTemplate<>();
        bytes.setConnectionFactory(connectionFactory);
        bytes.afterPropertiesSet();
        RedisMappingContext mappingContext = new RedisMappingContext();
        repository = new RedisRepositoryFactory(new RedisKeyValueTemplate(new RedisKeyValueAdapter(bytes, mappingContext), mappingContext))
                .getRepository(RedisStateMachineRepository.class);
        Config config = new Config();
        config.useSingleServer().setAddress("redis://" + MfaFlowOnRedisTest.REDIS_HOST + ":" + MfaFlowOnRedisTest.REDIS_PORT);
        redisson = Redisson.create(config);
    }

    @AfterAll
    static void disconnect() {
        if (redisson != null) {
            redisson.shutdown();
        }
        if (connectionFactory != null) {
            connectionFactory.destroy();
        }
    }

    @AfterEach
    void removeTheFlows() {
        clicks.shutdownNow();
        startedFlows.forEach(service::releaseStateMachine);
    }

    @ParameterizedTest
    @MethodSource("stores")
    void aSecondClickDuringTheVerificationLeavesTheFirstToFinish(Store store) throws Exception {
        build(store);
        String flow = challengedFlow();
        verifying = new CountDownLatch(1);
        mayFinish = new CountDownLatch(1);

        Future<Integer> first = clicks.submit(() -> click(flow, RIGHT));
        assertThat(verifying.await(10, TimeUnit.SECONDS)).as("the first click reached the verification").isTrue();
        mayFinishOnlyForTheFirst();
        int second = click(flow, RIGHT);
        mayFinish.countDown();

        assertThat(second).as("the second click, with the first being verified").isEqualTo(429);
        assertThat(first.get(10, TimeUnit.SECONDS)).as("the first click").isEqualTo(200);
    }

    @ParameterizedTest
    @MethodSource("stores")
    void aDoubleClickNeverLeavesTheUserOutside(Store store) throws Exception {
        build(store);
        Map<String, Integer> answers = new TreeMap<>();
        int outside = 0;
        for (int round = 0; round < ROUNDS; round++) {
            List<Integer> statuses = atOnce(challengedFlow(), RIGHT, RIGHT);
            Collections.sort(statuses);
            answers.merge(statuses.toString(), 1, Integer::sum);
            outside += statuses.contains(200) ? 0 : 1;
        }

        assertThat(outside).as("rounds that left the user outside, of %d: %s", ROUNDS, answers).isZero();
        assertThat(answers.keySet()).as("every round passed once, the other click told to retry or finding the flow done")
                .allMatch(shape -> shape.equals("[200, 429]") || shape.equals("[200, 400]"));
    }

    @ParameterizedTest
    @MethodSource("stores")
    void aWrongCodeClickedTwiceLeavesTheNextTry(Store store) throws Exception {
        build(store);
        String flow = challengedFlow();
        verifying = new CountDownLatch(1);
        mayFinish = new CountDownLatch(1);

        Future<Integer> first = clicks.submit(() -> click(flow, WRONG));
        assertThat(verifying.await(10, TimeUnit.SECONDS)).as("the first click reached the verification").isTrue();
        mayFinishOnlyForTheFirst();
        int second = click(flow, WRONG);
        mayFinish.countDown();

        assertThat(second).as("the second click, with the first being verified").isEqualTo(429);
        assertThat(first.get(10, TimeUnit.SECONDS)).as("the first click").isEqualTo(401);
        assertThat(integrator.loadFactorContext(flow).getAttemptCount(AuthType.MFA_OTT)).as("attempts counted").isEqualTo(1);
        assertThat(click(flow, RIGHT)).as("the right code on the next try").isEqualTo(200);
    }

    /** The limit counts the codes that were compared: one refused unread tells its sender nothing, and spends nothing. */
    @ParameterizedTest
    @MethodSource("stores")
    void wrongCodesAtOnceNeverGetMoreComparisonsThanTheLimit(Store store) throws Exception {
        build(store);
        String flow = challengedFlow();
        int limit = settings.getMaxRetryAttempts();
        int compared = 0;
        for (int burst = 0; burst < limit * 4 && liveFlows.contains(flow); burst++) {
            String[] codes = new String[12];
            Arrays.fill(codes, WRONG);
            for (int status : atOnce(flow, codes)) {
                compared += status == 401 ? 1 : 0;
                assertThat(status).as("no server error").isLessThan(500);
            }
            if (integrator.loadFactorContext(flow) != null
                    && integrator.loadFactorContext(flow).getCurrentState().isTerminal()) {
                click(flow, WRONG);
            }
        }

        assertThat(compared).as("wrong codes compared").isLessThanOrEqualTo(limit);
        assertThat(liveFlows).as("the flow ended at the limit").doesNotContain(flow);
        assertThat(click(flow, RIGHT)).as("the right code after the limit").isNotEqualTo(200);
    }

    /** A verification whose request died never ends: the state stays, and the user must be let back to the sign-in. */
    @ParameterizedTest
    @MethodSource("stores")
    void aVerificationNobodyFinishedGivesWayToTheNextRequest(Store store) throws Exception {
        build(store);
        settings.setStateMachineTimeoutMs(1);
        String flow = challengedFlow();
        FactorContext context = integrator.loadFactorContext(flow);
        assertThat(integrator.sendEvent(MfaEvent.SUBMIT_FACTOR_CREDENTIAL, context, request(flow, RIGHT))).isTrue();
        Thread.sleep(20);

        int answer = click(flow, RIGHT);

        assertThat(answer).as("the request after the time of a verification").isEqualTo(400);
        assertThat(liveFlows).as("the flow that nobody finishes").doesNotContain(flow);
    }

    private void mayFinishOnlyForTheFirst() {
        verifying = null;
    }

    private List<Integer> atOnce(String flow, String... codes) throws Exception {
        CountDownLatch go = new CountDownLatch(1);
        List<Future<Integer>> sent = new ArrayList<>();
        for (String code : codes) {
            sent.add(clicks.submit(() -> {
                go.await();
                // A browser's second click is not the same instant: it lands anywhere around the first.
                LockSupport.parkNanos(ThreadLocalRandom.current().nextLong(CLICK_SPREAD_NANOS));
                return click(flow, code);
            }));
        }
        go.countDown();
        List<Integer> statuses = new ArrayList<>();
        for (Future<Integer> one : sent) {
            statuses.add(one.get(30, TimeUnit.SECONDS));
        }
        return statuses;
    }

    private MockHttpServletRequest request(String flow, String code) {
        MockHttpServletRequest request = new MockHttpServletRequest("POST", "/login/mfa-ott");
        request.setParameter("token", code);
        request.setAttribute(FLOW_ATTRIBUTE, flow);
        return request;
    }

    private int click(String flow, String code) throws Exception {
        MockHttpServletRequest request = request(flow, code);
        MockHttpServletResponse response = new MockHttpServletResponse();
        continuation.doFilter(request, response, (passed, answered) -> step.doFilter(passed, answered, (unused, none) -> {
            throw new IllegalStateException("the factor's filter answers the request");
        }));
        return response.getStatus();
    }

    /** What the factor's filter and the handlers do with a code, in their order. */
    private void verified(HttpServletRequest request, HttpServletResponse response) throws IOException {
        String flow = (String) request.getAttribute(FLOW_ATTRIBUTE);
        CountDownLatch reached = verifying;
        if (reached != null) {
            reached.countDown();
            try {
                assertThat(mayFinish.await(10, TimeUnit.SECONDS)).isTrue();
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                throw new IllegalStateException(e);
            }
        } else {
            // Reading the stored code: the time the other click has to arrive in.
            LockSupport.parkNanos(VERIFICATION_NANOS);
        }
        if (!RIGHT.equals(request.getParameter("token"))) {
            FactorContext failed = integrator.loadFactorContextFromRequest(request);
            failed.incrementAttemptCount(AuthType.MFA_OTT);
            failed.setAttribute("retryCount_MFA_OTT", failed.getAttemptCount(AuthType.MFA_OTT));
            integrator.sendEvent(MfaEvent.FACTOR_VERIFICATION_FAILED, failed, request);
            response.setStatus(401);
            return;
        }
        FactorContext context = (FactorContext) request.getAttribute(MfaContinuationFilter.FACTOR_CONTEXT_ATTR);
        if (!liveFlows.contains(flow)) {
            response.setStatus(400);
            return;
        }
        for (MfaEvent event : FINISHING) {
            if (!integrator.sendEvent(event, context, request)) {
                response.setStatus(500);
                return;
            }
        }
        integrator.releaseStateMachine(flow);
        liveFlows.remove(flow);
        response.setStatus(200);
    }

    /** As ChallengeMfaInitializer starts it, up to the code that was sent. */
    private String challengedFlow() {
        String flow = "rc-fix-double-click-" + UUID.randomUUID();
        startedFlows.add(flow);
        MockHttpServletRequest request = request(flow, RIGHT);
        FactorContext context = new FactorContext(flow, OneTimeTokenAuthenticationToken.authenticated(MfaFlowOnRedisTest.contexaUser(), ROLES), MfaState.NONE, FLOW);
        context.setAttribute("challengeInitiated", true);
        context.setAttribute("challengeReason", "ZERO_TRUST_ADAPTIVE");
        integrator.initializeStateMachine(context, request, null);
        liveFlows.add(flow);

        Map<String, Object> headers = new LinkedHashMap<>();
        headers.put("mfaDecision", MfaDecision.builder().required(true).type(MfaDecision.DecisionType.CHALLENGED)
                .reason("Zero Trust CHALLENGE action requires additional verification")
                .metadata(Map.of("challengeFlow", true, "zeroTrustTriggered", true)).build());
        headers.put("request", request);
        headers.put("challengeFlow", true);
        assertThat(integrator.sendEvent(MfaEvent.ADAPTIVE_MFA_REQUIRED, context, request, headers)).isTrue();
        assertThat(integrator.sendEvent(MfaEvent.MFA_REQUIRED_SELECT_FACTOR, integrator.loadFactorContext(flow), request)).isTrue();
        FactorContext selecting = integrator.loadFactorContext(flow);
        selecting.setCurrentStepId(OTT_STEP);
        assertThat(integrator.sendEvent(MfaEvent.FACTOR_SELECTED, selecting, request, Map.of("selectedFactor", AuthType.MFA_OTT.name()))).isTrue();
        assertThat(integrator.sendEvent(MfaEvent.INITIATE_CHALLENGE, integrator.loadFactorContext(flow), request)).isTrue();
        assertThat(integrator.loadFactorContext(flow).getCurrentState()).isEqualTo(MfaState.FACTOR_CHALLENGE_PRESENTED_AWAITING_VERIFICATION);
        return flow;
    }

    private void build(Store store) throws Exception {
        settings.setMinimumDelayMs(0);
        PlatformConfig platform = PlatformConfig.builder().addFlow(MfaFlowOnRedisTest.mfaFlow()).build();
        MfaPolicyProvider policy = mock(MfaPolicyProvider.class);
        when(policy.evaluateNextFactor(any())).thenReturn(NextFactorDecision.noMoreFactors());
        when(policy.getRequiredFactorCount(anyString(), anyString())).thenReturn(1L);
        machineConfiguration = new MfaStateMachineConfiguration(new InitializeMfaAction(platform), new SelectFactorAction(),
                new InitiateChallengeAction(), new VerifyFactorAction(platform), new CompleteMfaAction(),
                new HandleFailureAction(settings), new DetermineNextFactorAction(policy),
                new AllFactorsCompletedGuard(policy), new RetryLimitGuard(settings));
        service = store == Store.REDIS ? onRedis() : inMemory();

        AuthContextProperties properties = mock(AuthContextProperties.class, withSettings().stubOnly());
        when(properties.getMfa()).thenReturn(settings);
        MfaSessionRepository sessions = sessions();
        integrator = new MfaStateMachineIntegrator(service, sessions, properties);

        ApplicationContext context = mock(ApplicationContext.class, withSettings().stubOnly());
        when(context.getBean(AuthUrlProvider.class)).thenReturn(mock(AuthUrlProvider.class, withSettings().stubOnly()));
        when(context.getBean(MfaStateMachineIntegrator.class)).thenReturn(integrator);
        when(context.getBean(MfaSessionRepository.class)).thenReturn(sessions);
        when(context.getBean(MfaFlowUrlRegistry.class)).thenReturn(mock(MfaFlowUrlRegistry.class, withSettings().stubOnly()));

        AuthResponseWriter writer = new StatusOnly();
        continuation = new MfaContinuationFilter(properties, writer, context);
        MfaUrlMatcher matcher = mock(MfaUrlMatcher.class, withSettings().stubOnly());
        when(matcher.isMfaRequest(any())).thenReturn(true);
        when(matcher.getRequestType(any())).thenReturn(MfaRequestType.OTT_CODE_VERIFY);
        ReflectionTestUtils.setField(continuation, "urlMatcher", matcher);
        ReflectionTestUtils.setField(continuation, "initialized", true);

        Filter factorFilter = (request, response, chain) -> verified((HttpServletRequest) request, (HttpServletResponse) response);
        ConfiguredFactorFilterProvider factorFilters = mock(ConfiguredFactorFilterProvider.class, withSettings().stubOnly());
        when(factorFilters.getFilter(any())).thenReturn(factorFilter);
        step = new MfaStepFilterWrapper(factorFilters, request -> true, context, properties, writer);
    }

    private MfaSessionRepository sessions() {
        MfaSessionRepository sessions = mock(MfaSessionRepository.class, withSettings().stubOnly());
        when(sessions.getSessionId(any())).thenAnswer(call -> ((HttpServletRequest) call.getArgument(0)).getAttribute(FLOW_ATTRIBUTE));
        when(sessions.existsSession(anyString())).thenAnswer(call -> liveFlows.contains(call.<String>getArgument(0)));
        doAnswer(call -> liveFlows.remove(call.<String>getArgument(0))).when(sessions).removeSession(anyString(), any(), any());
        when(sessions.getRepositoryType()).thenReturn("TEST");
        return sessions;
    }

    private AbstractMfaStateMachineService inMemory() {
        InMemoryStateMachinePersist persist = new InMemoryStateMachinePersist();
        StateMachinePersister<MfaState, MfaEvent, String> persister = new DefaultStateMachinePersister<>(persist);
        return new StandaloneMfaStateMachineServiceImpl(new Machines(), persister, new StateMachineProperties(), persist);
    }

    private AbstractMfaStateMachineService onRedis() {
        ExpiringRedisRepositoryStateMachinePersist persist = new ExpiringRedisRepositoryStateMachinePersist(repository,
                new MfaKryoStateMachineSerialisationService(), Duration.ofMinutes(5));
        return new MfaStateMachineServiceImpl(new Machines(),
                new DefaultStateMachinePersister<>(new RedisPersistingStateMachineInterceptor<MfaState, MfaEvent, String>(persist)),
                redisson, new StateMachineProperties());
    }

    private static final class StatusOnly implements AuthResponseWriter {

        @Override
        public void writeSuccessResponse(HttpServletResponse response, Object data, int status) {
            response.setStatus(status);
        }

        @Override
        public void writeErrorResponse(HttpServletResponse response, int status, String errorCode, String errorMessage, String path) {
            response.setStatus(status);
        }

        @Override
        public void writeErrorResponse(HttpServletResponse response, int status, String errorCode, String errorMessage, String requestURI,
                                       Map<String, Object> errorDetails) {
            response.setStatus(status);
        }
    }

    /** The machines of the real configuration, new for every request as the factory of the application gives them. */
    private final class Machines implements StateMachineFactory<MfaState, MfaEvent> {

        @Override
        public StateMachine<MfaState, MfaEvent> getStateMachine() {
            try {
                StateMachineBuilder.Builder<MfaState, MfaEvent> builder = StateMachineBuilder.builder();
                machineConfiguration.configure(builder.configureConfiguration());
                machineConfiguration.configure(builder.configureStates());
                machineConfiguration.configure(builder.configureTransitions());
                return builder.build();
            } catch (Exception ex) {
                throw new IllegalStateException(ex);
            }
        }

        @Override
        public StateMachine<MfaState, MfaEvent> getStateMachine(String machineId) {
            return getStateMachine();
        }

        @Override
        public StateMachine<MfaState, MfaEvent> getStateMachine(UUID uuid) {
            return getStateMachine();
        }
    }
}
