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

import io.contexa.contexacommon.domain.UserDto;
import io.contexa.contexacommon.enums.AuthType;
import io.contexa.contexacommon.enums.StateType;
import io.contexa.contexacommon.properties.AuthContextProperties;
import io.contexa.contexacommon.properties.MfaSettings;
import io.contexa.contexacommon.security.UnifiedCustomUserDetails;
import io.contexa.contexacore.infra.session.MfaSessionRepository;
import io.contexa.contexacore.testsupport.TestStores;
import io.contexa.contexaidentity.security.core.config.AuthenticationFlowConfig;
import io.contexa.contexaidentity.security.core.config.AuthenticationStepConfig;
import io.contexa.contexaidentity.security.core.config.PlatformConfig;
import io.contexa.contexaidentity.security.core.config.StateConfig;
import io.contexa.contexaidentity.security.core.dsl.option.AuthenticationProcessingOptions;
import io.contexa.contexaidentity.security.core.dsl.option.RestOptions;
import io.contexa.contexaidentity.security.core.mfa.context.FactorContext;
import io.contexa.contexaidentity.security.core.mfa.model.MfaDecision;
import io.contexa.contexaidentity.security.core.mfa.options.PrimaryAuthenticationOptions;
import io.contexa.contexaidentity.security.core.mfa.policy.MfaPolicyProvider;
import io.contexa.contexaidentity.security.core.mfa.policy.NextFactorDecision;
import io.contexa.contexaidentity.security.filter.handler.MfaStateMachineIntegrator;
import io.contexa.contexaidentity.security.handler.login.LoginFactsDetails;
import io.contexa.contexaidentity.security.handler.login.LoginFactsRecorder;
import io.contexa.contexaidentity.security.statemachine.action.CompleteMfaAction;
import io.contexa.contexaidentity.security.statemachine.action.DetermineNextFactorAction;
import io.contexa.contexaidentity.security.statemachine.action.HandleFailureAction;
import io.contexa.contexaidentity.security.statemachine.action.InitializeMfaAction;
import io.contexa.contexaidentity.security.statemachine.action.InitiateChallengeAction;
import io.contexa.contexaidentity.security.statemachine.action.SelectFactorAction;
import io.contexa.contexaidentity.security.statemachine.action.VerifyFactorAction;
import io.contexa.contexaidentity.security.statemachine.config.MfaStateMachineConfiguration;
import io.contexa.contexaidentity.security.statemachine.config.StateMachineProperties;
import io.contexa.contexaidentity.security.statemachine.config.kyro.MfaKryoFactorContextRoundTripTest;
import io.contexa.contexaidentity.security.statemachine.config.kyro.MfaKryoStateMachineSerialisationService;
import io.contexa.contexaidentity.security.statemachine.core.persist.ExpiringRedisRepositoryStateMachinePersist;
import io.contexa.contexaidentity.security.statemachine.enums.MfaEvent;
import io.contexa.contexaidentity.security.statemachine.enums.MfaState;
import io.contexa.contexaidentity.security.statemachine.guard.AllFactorsCompletedGuard;
import io.contexa.contexaidentity.security.statemachine.guard.RetryLimitGuard;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Named;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;
import org.redisson.Redisson;
import org.redisson.api.RedissonClient;
import org.redisson.config.Config;
import org.springframework.data.redis.connection.RedisStandaloneConfiguration;
import org.springframework.data.redis.connection.lettuce.LettuceConnectionFactory;
import org.springframework.data.redis.core.RedisKeyValueAdapter;
import org.springframework.data.redis.core.RedisKeyValueTemplate;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.data.redis.core.mapping.RedisMappingContext;
import org.springframework.data.redis.repository.support.RedisRepositoryFactory;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.authentication.ott.OneTimeTokenAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.security.web.webauthn.api.Bytes;
import org.springframework.security.web.webauthn.api.ImmutablePublicKeyCredentialUserEntity;
import org.springframework.security.web.webauthn.authentication.WebAuthnAuthentication;
import org.springframework.statemachine.StateMachine;
import org.springframework.statemachine.config.StateMachineBuilder;
import org.springframework.statemachine.config.StateMachineFactory;
import org.springframework.statemachine.data.redis.RedisPersistingStateMachineInterceptor;
import org.springframework.statemachine.data.redis.RedisRepositoryStateMachine;
import org.springframework.statemachine.data.redis.RedisStateMachineRepository;
import org.springframework.statemachine.persist.DefaultStateMachinePersister;

import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.stream.Stream;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.junit.jupiter.api.Named.named;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/**
 * PR-80: an MFA flow on real Redis, with the distributed service, its Kryo persist, its Redisson lock and the real
 * actions and guards, one read of Redis per request as the filters read it. Nothing here keeps a flow between requests
 * except Redis.
 */
class MfaFlowOnRedisTest {

    private static final String FLOW = "mfa";
    private static final String USERNAME = "alice";
    private static final String OTT_STEP = "mfa:mfa_ott:1";
    private static final List<GrantedAuthority> ROLES = List.of(new SimpleGrantedAuthority("ROLE_USER"));
    private static final byte[] UNREADABLE = "not an MFA flow".getBytes(StandardCharsets.UTF_8);

    private static LettuceConnectionFactory connectionFactory;
    private static RedisStateMachineRepository repository;
    private static RedissonClient redisson;

    private final List<String> flows = new ArrayList<>();
    private final MockHttpServletRequest request = new MockHttpServletRequest("POST", "/mfa/select-factor");

    private MfaStateMachineConfiguration machineConfiguration;
    private MfaStateMachineServiceImpl service;
    private MfaStateMachineIntegrator integrator;

    @BeforeAll
    static void connect() {
        TestStores.Redis server = TestStores.redis();
        connectionFactory = new LettuceConnectionFactory(new RedisStandaloneConfiguration(server.host(), server.port()));
        connectionFactory.afterPropertiesSet();
        RedisTemplate<byte[], byte[]> bytes = new RedisTemplate<>();
        bytes.setConnectionFactory(connectionFactory);
        bytes.afterPropertiesSet();
        RedisMappingContext mappingContext = new RedisMappingContext();
        RedisKeyValueAdapter adapter = new RedisKeyValueAdapter(bytes, mappingContext);
        repository = new RedisRepositoryFactory(new RedisKeyValueTemplate(adapter, mappingContext))
                .getRepository(RedisStateMachineRepository.class);
        Config config = new Config();
        config.useSingleServer().setAddress(server.uri());
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

    @BeforeEach
    void buildTheDistributedService() {
        PlatformConfig platform = PlatformConfig.builder().addFlow(mfaFlow()).build();
        MfaPolicyProvider policy = mock(MfaPolicyProvider.class);
        when(policy.evaluateNextFactor(any())).thenReturn(NextFactorDecision.noMoreFactors());
        when(policy.getRequiredFactorCount(anyString(), anyString())).thenReturn(1L);
        MfaSettings settings = new MfaSettings();
        machineConfiguration = new MfaStateMachineConfiguration(new InitializeMfaAction(platform), new SelectFactorAction(),
                new InitiateChallengeAction(), new VerifyFactorAction(platform), new CompleteMfaAction(),
                new HandleFailureAction(settings), new DetermineNextFactorAction(policy),
                new AllFactorsCompletedGuard(policy), new RetryLimitGuard(settings));

        ExpiringRedisRepositoryStateMachinePersist persist = new ExpiringRedisRepositoryStateMachinePersist(repository,
                new MfaKryoStateMachineSerialisationService(), Duration.ofMinutes(5));
        service = new MfaStateMachineServiceImpl(new Machines(),
                new DefaultStateMachinePersister<>(new RedisPersistingStateMachineInterceptor<MfaState, MfaEvent, String>(persist)),
                redisson, new StateMachineProperties());
        integrator = new MfaStateMachineIntegrator(service, mock(MfaSessionRepository.class), mock(AuthContextProperties.class));
    }

    @AfterEach
    void removeTheFlows() {
        flows.forEach(repository::deleteById);
    }

    static Stream<Named<Authentication>> signIns() {
        return Stream.of(
                named("one-time token (the sign-in of the measurement)", OneTimeTokenAuthenticationToken.authenticated(contexaUser(), ROLES)),
                named("one-time token of Spring's User", OneTimeTokenAuthenticationToken.authenticated(
                        User.withUsername(USERNAME).password("hash").authorities(ROLES).build(), ROLES)),
                named("passkey", new WebAuthnAuthentication(ImmutablePublicKeyCredentialUserEntity.builder()
                        .name(USERNAME).id(new Bytes(new byte[] {1, 2, 3})).displayName("Alice").build(), ROLES)),
                named("JWT", new JwtAuthenticationToken(Jwt.withTokenValue("token").header("alg", "RS256")
                        .subject(USERNAME).claim("amr", List.of("pwd")).claim("auth_time", 1_760_000_000L).build(), ROLES)),
                named("the application's user", OneTimeTokenAuthenticationToken.authenticated(
                        new MfaKryoFactorContextRoundTripTest.AppUser(), ROLES)),
                named("password", UsernamePasswordAuthenticationToken.authenticated(contexaUser(), null, ROLES)));
    }

    @ParameterizedTest
    @MethodSource("signIns")
    void aChallengedUserAnswersTheChallengeThroughRedis(Authentication signIn) {
        String flow = startedChallenge(signIn);

        assertThat(storedBytes(flow)).as("the flow is in Redis").isNotEmpty();
        FactorContext selecting = loaded(flow);
        assertThat(selecting.getCurrentState()).isEqualTo(MfaState.AWAITING_FACTOR_SELECTION);
        assertThat(selecting.getUsername()).isEqualTo(USERNAME);
        assertThat(selecting.getPrimaryAuthentication().getName()).isEqualTo(USERNAME);
        assertThat(selecting.getPrimaryAuthentication().isAuthenticated()).isTrue();
        assertThat(selecting.getAvailableFactors()).containsExactlyInAnyOrder(AuthType.MFA_OTT, AuthType.MFA_PASSKEY);

        selecting.setCurrentStepId(OTT_STEP);
        assertThat(integrator.sendEvent(MfaEvent.FACTOR_SELECTED, selecting, request,
                Map.of("selectedFactor", AuthType.MFA_OTT.name()))).isTrue();

        assertThat(integrator.sendEvent(MfaEvent.INITIATE_CHALLENGE, loaded(flow), request)).isTrue();
        FactorContext challenged = loaded(flow);
        assertThat(challenged.getCurrentState()).isEqualTo(MfaState.FACTOR_CHALLENGE_PRESENTED_AWAITING_VERIFICATION);
        assertThat(challenged.getCurrentProcessingFactor()).isEqualTo(AuthType.MFA_OTT);

        assertThat(integrator.sendEvent(MfaEvent.SUBMIT_FACTOR_CREDENTIAL, challenged, request)).isTrue();
        assertThat(integrator.sendEvent(MfaEvent.FACTOR_VERIFIED_SUCCESS, loaded(flow), request)).isTrue();
        FactorContext verified = loaded(flow);
        assertThat(verified.getCompletedFactors()).extracting(AuthenticationStepConfig::getStepId).containsExactly(OTT_STEP);
        assertThat(verified.getCompletedFactors().get(0).getOptions()).isEmpty();

        assertThat(integrator.sendEvent(MfaEvent.DETERMINE_NEXT_FACTOR, verified, request)).isTrue();
        assertThat(integrator.sendEvent(MfaEvent.ALL_REQUIRED_FACTORS_COMPLETED, loaded(flow), request)).isTrue();
        assertThat(integrator.sendEvent(MfaEvent.ALL_FACTORS_VERIFIED_PROCEED_TO_TOKEN, loaded(flow), request)).isTrue();

        FactorContext finished = loaded(flow);
        assertThat(finished.getCurrentState()).isEqualTo(MfaState.MFA_SUCCESSFUL);
        assertThat(finished.isCompleted()).isTrue();

        OneTimeTokenAuthenticationToken last = OneTimeTokenAuthenticationToken.authenticated(USERNAME, ROLES);
        LoginFactsRecorder.recordFinal(last, request, finished);
        assertThat(((LoginFactsDetails) last.getDetails()).getChallengeVerifiedAt()).isNotNull();
    }

    @Test
    void theAttemptsOfAChallengeAreCountedAcrossRequestsUntilItEnds() {
        String flow = startedChallenge(OneTimeTokenAuthenticationToken.authenticated(contexaUser(), ROLES));
        FactorContext selecting = loaded(flow);
        selecting.setCurrentStepId(OTT_STEP);
        integrator.sendEvent(MfaEvent.FACTOR_SELECTED, selecting, request, Map.of("selectedFactor", AuthType.MFA_OTT.name()));
        integrator.sendEvent(MfaEvent.INITIATE_CHALLENGE, loaded(flow), request);

        int attempts = new MfaSettings().getMaxRetryAttempts() + 1;
        for (int attempt = 1; attempt <= attempts; attempt++) {
            assertThat(integrator.sendEvent(MfaEvent.SUBMIT_FACTOR_CREDENTIAL, loaded(flow), request)).isTrue();
            FactorContext failed = loaded(flow);
            failed.incrementAttemptCount(AuthType.MFA_OTT);
            failed.setAttribute("retryCount_MFA_OTT", failed.getAttemptCount(AuthType.MFA_OTT));
            assertThat(integrator.sendEvent(MfaEvent.FACTOR_VERIFICATION_FAILED, failed, request)).isTrue();
            if (loaded(flow).getCurrentState() == MfaState.MFA_RETRY_LIMIT_EXCEEDED) {
                break;
            }
        }

        FactorContext ended = loaded(flow);
        assertThat(ended.getCurrentState()).isEqualTo(MfaState.MFA_RETRY_LIMIT_EXCEEDED);
        assertThat(ended.getAttemptCount(AuthType.MFA_OTT)).isEqualTo(new MfaSettings().getMaxRetryAttempts());
    }

    /**
     * A request holds its copy of the flow while what Redis stores cannot be read (a failed read, or a record of
     * another version). The stored flow may have ended; the copy must not take its place.
     */
    @Test
    void aFlowThatCannotBeReadIsNotReplacedByTheCopyARequestHolds() {
        String flow = newFlowId();
        store(flow, MfaState.MFA_RETRY_LIMIT_EXCEEDED, UNREADABLE);
        FactorContext copy = copyHeldByARequest(flow);

        assertThatThrownBy(() -> service.sendEvent(MfaEvent.FACTOR_VERIFIED_SUCCESS, copy, request))
                .isInstanceOf(AbstractMfaStateMachineService.MfaStateMachineException.class);

        assertThat(copy.getCurrentState()).isEqualTo(MfaState.FACTOR_VERIFICATION_PENDING);
        assertThat(copy.getCompletedFactors()).isEmpty();
        assertThat(storedBytes(flow)).isEqualTo(UNREADABLE);
    }

    @Test
    void theFiltersSeeAFlowThatCannotBeReadAsNoFlowAndARefusedEvent() {
        String flow = newFlowId();
        store(flow, MfaState.FACTOR_VERIFICATION_PENDING, UNREADABLE);

        assertThat(integrator.loadFactorContext(flow)).isNull();
        assertThat(integrator.sendEvent(MfaEvent.FACTOR_VERIFIED_SUCCESS, copyHeldByARequest(flow), request)).isFalse();

        assertThat(storedBytes(flow)).isEqualTo(UNREADABLE);
    }

    @Test
    void savingOverAFlowThatCannotBeReadIsRefused() {
        String flow = newFlowId();
        store(flow, MfaState.MFA_RETRY_LIMIT_EXCEEDED, UNREADABLE);
        FactorContext copy = copyHeldByARequest(flow);

        assertThatThrownBy(() -> service.saveFactorContext(copy))
                .isInstanceOf(AbstractMfaStateMachineService.MfaStateMachineException.class);

        assertThat(storedBytes(flow)).isEqualTo(UNREADABLE);
    }

    /**
     * Redis replaces a record in two commands and a read takes no lock. A read that finds no flow ends it in the filters
     * (MfaContinuationFilter releases it, ZeroTrustChallengeFilter starts another), so a request running beside a write
     * must still find the flow.
     */
    @Test
    void aReadBesideAWriteFindsTheFlow() throws Exception {
        String flow = startedChallenge(OneTimeTokenAuthenticationToken.authenticated(contexaUser(), ROLES));
        long end = System.currentTimeMillis() + 3_000;
        Thread writes = new Thread(() -> {
            while (System.currentTimeMillis() < end) {
                FactorContext context = service.getFactorContext(flow);
                if (context != null) {
                    service.saveFactorContext(context);
                }
            }
        });
        writes.start();

        int reads = 0;
        int notFound = 0;
        while (System.currentTimeMillis() < end) {
            reads++;
            if (integrator.loadFactorContext(flow) == null) {
                notFound++;
            }
        }
        writes.join();

        assertThat(reads).isGreaterThan(50);
        assertThat(notFound).as("reads that found no flow, of %d", reads).isZero();
    }

    @Test
    void aFlowThatIsGoneGivesARequestNothingToContinue() {
        String flow = newFlowId();
        FactorContext copy = copyHeldByARequest(flow);

        boolean accepted = integrator.sendEvent(MfaEvent.FACTOR_VERIFIED_SUCCESS, copy, request);

        assertThat(accepted).isFalse();
        assertThat(copy.isCompleted()).isFalse();
        assertThat(copy.getCompletedFactors()).isEmpty();
    }

    @Test
    void aFlowThatNeverExistedReadsAsNoFlow() {
        assertThat(integrator.loadFactorContext(newFlowId())).isNull();
    }

    /** As ChallengeMfaInitializer starts it: the context is kept, and each next step reads it back from Redis. */
    private String startedChallenge(Authentication signIn) {
        String flow = newFlowId();
        FactorContext context = new FactorContext(flow, signIn, MfaState.NONE, FLOW);
        context.setAttribute("challengeInitiated", true);
        context.setAttribute("challengeReason", "ZERO_TRUST_ADAPTIVE");
        integrator.initializeStateMachine(context, request, null);

        Map<String, Object> headers = new LinkedHashMap<>();
        headers.put("mfaDecision", MfaDecision.builder().required(true).type(MfaDecision.DecisionType.CHALLENGED)
                .reason("Zero Trust CHALLENGE action requires additional verification")
                .metadata(Map.of("challengeFlow", true, "zeroTrustTriggered", true)).build());
        headers.put("request", request);
        headers.put("challengeFlow", true);
        assertThat(integrator.sendEvent(MfaEvent.ADAPTIVE_MFA_REQUIRED, context, request, headers)).isTrue();

        assertThat(integrator.sendEvent(MfaEvent.MFA_REQUIRED_SELECT_FACTOR, loaded(flow), request)).isTrue();
        return flow;
    }

    private FactorContext loaded(String flow) {
        FactorContext context = integrator.loadFactorContext(flow);
        assertThat(context).as("the flow read back from Redis").isNotNull();
        return context;
    }

    private FactorContext copyHeldByARequest(String flow) {
        FactorContext copy = new FactorContext(flow, OneTimeTokenAuthenticationToken.authenticated(contexaUser(), ROLES),
                MfaState.FACTOR_VERIFICATION_PENDING, FLOW);
        copy.setCurrentProcessingFactor(AuthType.MFA_OTT);
        copy.setCurrentStepId(OTT_STEP);
        return copy;
    }

    private String newFlowId() {
        String flow = "rc-fix-mfa-state-" + UUID.randomUUID();
        flows.add(flow);
        return flow;
    }

    private static void store(String flow, MfaState state, byte[] stored) {
        ExpiringRedisRepositoryStateMachinePersist.ExpiringRedisRepositoryStateMachine machine =
                new ExpiringRedisRepositoryStateMachinePersist.ExpiringRedisRepositoryStateMachine();
        machine.setId(flow);
        machine.setMachineId(flow);
        machine.setState(state.name());
        machine.setStateMachineContext(stored);
        machine.setTimeToLive(300L);
        repository.save(machine);
    }

    private static byte[] storedBytes(String flow) {
        return repository.findById(flow).map(RedisRepositoryStateMachine::getStateMachineContext).orElse(null);
    }

    static UnifiedCustomUserDetails contexaUser() {
        UserDto user = UserDto.builder().id(7L).username(USERNAME).password("hash").email("alice@example.org")
                .enabled(true).build();
        return new UnifiedCustomUserDetails(user, new HashSet<>(ROLES));
    }

    static AuthenticationFlowConfig mfaFlow() {
        AuthenticationStepConfig primary = new AuthenticationStepConfig(FLOW, AuthType.MFA_REST.name(), 0, true);
        AuthenticationStepConfig ott = new AuthenticationStepConfig(FLOW, AuthType.MFA_OTT.name(), 1, false);
        // A configured step holds the options of its DSL: objects a stored flow must not drag along.
        ott.addOption(AuthenticationStepConfig.OPTIONS_KEY, mock(AuthenticationProcessingOptions.class));
        AuthenticationStepConfig passkey = new AuthenticationStepConfig(FLOW, AuthType.MFA_PASSKEY.name(), 2, false);
        return AuthenticationFlowConfig.builder(FLOW)
                .primaryAuthenticationOptions(PrimaryAuthenticationOptions.builder()
                        .restOptions(mock(RestOptions.class)).loginProcessingUrl("/api/mfa/login").build())
                .stateConfig(new StateConfig("session", StateType.SESSION))
                .registeredFactorOptions(Map.of(AuthType.MFA_OTT, mock(AuthenticationProcessingOptions.class),
                        AuthType.MFA_PASSKEY, mock(AuthenticationProcessingOptions.class)))
                .stepConfigs(List.of(primary, ott, passkey))
                .build();
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
