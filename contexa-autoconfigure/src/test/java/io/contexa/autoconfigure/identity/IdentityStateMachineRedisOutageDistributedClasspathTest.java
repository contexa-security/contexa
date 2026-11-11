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
package io.contexa.autoconfigure.identity;

import io.contexa.autoconfigure.core.infra.CoreInfrastructureAutoConfiguration;
import io.contexa.contexacommon.config.redis.CommonRedisAutoConfiguration;
import io.contexa.contexacommon.properties.AuthContextProperties;
import io.contexa.contexacommon.store.ApplicationNamespace;
import io.contexa.contexacore.infra.session.MfaSessionRepository;
import io.contexa.contexacore.properties.SecurityPlaneProperties;
import io.contexa.contexaidentity.security.core.config.PlatformConfig;
import io.contexa.contexaidentity.security.core.mfa.context.FactorContext;
import io.contexa.contexaidentity.security.core.mfa.policy.MfaPolicyProvider;
import io.contexa.contexaidentity.security.statemachine.core.service.AbstractMfaStateMachineService.MfaStateMachineException;
import io.contexa.contexaidentity.security.statemachine.core.service.MfaStateMachineService;
import io.contexa.contexaidentity.security.statemachine.enums.MfaState;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.condition.EnabledIfEnvironmentVariable;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.springframework.boot.autoconfigure.AutoConfigurations;
import org.springframework.boot.autoconfigure.data.redis.RedisAutoConfiguration;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.data.redis.connection.RedisStandaloneConfiguration;
import org.springframework.data.redis.connection.lettuce.LettuceConnectionFactory;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;

import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.awaitility.Awaitility.await;
import static org.mockito.Mockito.mock;

/**
 * The distributed MFA service of an application that starts as Contexa starts it, on a real Redis that stops or freezes
 * (a proxy in front of it behaves as a stopped or a paused container does): the step that takes the lock of the flow
 * first is refused as it always was, the request that meets the outage waits about a second and the ones after it do
 * not wait at all, and with Redis back the same application, not restarted, takes the lock again. Runs in the task
 * distributedClasspathTest. CONTEXA_TEST_REDIS_PORT: a Redis of the test; it removes only the keys it wrote.
 */
@EnabledIfEnvironmentVariable(named = IdentityStateMachineRedisOutageDistributedClasspathTest.PORT, matches = "[0-9]+")
class IdentityStateMachineRedisOutageDistributedClasspathTest {

    static final String PORT = "CONTEXA_TEST_REDIS_PORT";
    private static final String HOST = "CONTEXA_TEST_REDIS_HOST";
    private static final String FLOWS = "RedisRepositoryStateMachine";
    /** The request that meets the outage: the application's own client would wait three seconds and more. */
    private static final Duration FIRST_LIMIT = Duration.ofMillis(2500);
    private static final Duration LATER_LIMIT = Duration.ofMillis(300);

    private static String redisHost;
    private static int redisPort;
    private static LettuceConnectionFactory connections;
    private static StringRedisTemplate redis;

    private final List<String> flows = new ArrayList<>();

    @BeforeAll
    static void connect() {
        String host = System.getenv(HOST);
        redisHost = host == null || host.isBlank() ? "127.0.0.1" : host.trim();
        redisPort = Integer.parseInt(System.getenv(PORT).trim());
        assertThat(redisPort).as("a Redis of the test, not one on 6379").isNotEqualTo(6379);
        connections = new LettuceConnectionFactory(new RedisStandaloneConfiguration(redisHost, redisPort));
        connections.afterPropertiesSet();
        redis = new StringRedisTemplate(connections);
    }

    @AfterAll
    static void disconnect() {
        if (connections != null) {
            connections.destroy();
        }
    }

    @ParameterizedTest(name = "Redis {0}")
    @ValueSource(strings = {"freezes", "stops"})
    @DisplayName("the steps that take the lock first fail at once while Redis is down, the one that meets the outage waits about a second, and the application takes them again when Redis is back")
    void theStepsThatTakeTheLockFirst(String outage) throws Exception {
        try (RedisOutageProxy proxy = new RedisOutageProxy(redisHost, redisPort);
             ApplicationNamespace.Scope ignored = ApplicationNamespace.using("")) {
            runner(proxy).run(context -> {
                assertThat(context).hasNotFailed();
                MfaStateMachineService service = context.getBean("contexaMfaStateMachineService", MfaStateMachineService.class);

                FactorContext kept = flow();
                onRequestThread(() -> {
                    service.initializeStateMachine(kept, new MockHttpServletRequest());
                    return null;
                });
                assertThat(onRequestThread(() -> service.getFactorContext(kept.getMfaSessionId()))).as("while Redis answers").isNotNull();

                if (outage.equals("freezes")) {
                    proxy.freeze();
                } else {
                    proxy.refuse();
                }

                FactorContext meets = flow();
                Duration first = refusedAfter(() -> {
                    service.initializeStateMachine(meets, new MockHttpServletRequest());
                    return null;
                });
                System.out.println("[outage] Redis " + outage + ": the request that meets it waited " + first.toMillis() + " ms");
                assertThat(first).as("the request that meets the outage, taking the lock first").isLessThan(FIRST_LIMIT);

                FactorContext later = flow();
                assertThat(refusedAfter(() -> {
                    service.initializeStateMachine(later, new MockHttpServletRequest());
                    return null;
                })).as("a later initialization").isLessThan(LATER_LIMIT);
                assertThat(refusedAfter(() -> {
                    service.saveFactorContext(kept);
                    return null;
                })).as("saving the flow").isLessThan(LATER_LIMIT);
                assertThat(refusedAfter(() -> service.updateStateOnly(kept.getMfaSessionId(), MfaState.AWAITING_FACTOR_SELECTION)))
                        .as("a state-only update").isLessThan(LATER_LIMIT);
                assertThat(refusedAfter(() -> service.getFactorContext(kept.getMfaSessionId())))
                        .as("reading the flow").isLessThan(LATER_LIMIT);
                long start = System.nanoTime();
                onRequestThread(() -> {
                    service.releaseStateMachine(kept.getMfaSessionId());
                    return null;
                });
                assertThat(Duration.ofNanos(System.nanoTime() - start)).as("releasing the flow").isLessThan(LATER_LIMIT);

                proxy.restore();
                FactorContext after = flow();
                await().atMost(Duration.ofSeconds(60)).pollInterval(Duration.ofMillis(250)).ignoreExceptions().untilAsserted(() -> {
                    onRequestThread(() -> {
                        service.initializeStateMachine(after, new MockHttpServletRequest());
                        return null;
                    });
                    assertThat(onRequestThread(() -> service.getFactorContext(after.getMfaSessionId())))
                            .as("the flow started after Redis is back").isNotNull();
                });
                assertThat(onRequestThread(() -> service.getFactorContext(kept.getMfaSessionId())))
                        .as("the flow kept through the outage, which the failed release left alone").isNotNull();
            });
        } finally {
            flows.forEach(flow -> {
                redis.delete(redis.keys("*" + flow + "*"));
                redis.opsForSet().remove(FLOWS, flow);
            });
        }
    }

    private FactorContext flow() {
        String id = "outage-flow-" + UUID.randomUUID();
        flows.add(id);
        return new FactorContext(id, UsernamePasswordAuthenticationToken.authenticated("alice", null,
                List.of(new SimpleGrantedAuthority("ROLE_USER"))), MfaState.NONE, "mfa");
    }

    private static ApplicationContextRunner runner(RedisOutageProxy proxy) {
        return new ApplicationContextRunner()
                .withPropertyValues("spring.data.redis.host=127.0.0.1", "spring.data.redis.port=" + proxy.port(),
                        "contexa.infrastructure.mode=distributed")
                .withUserConfiguration(ContexaSide.class)
                .withConfiguration(AutoConfigurations.of(RedisAutoConfiguration.class, CommonRedisAutoConfiguration.class,
                        CoreInfrastructureAutoConfiguration.class, IdentityStateMachineAutoConfiguration.class));
    }

    @FunctionalInterface
    private interface Call<T> {
        T run() throws Exception;
    }

    private static <T> T onRequestThread(Call<T> call) throws Exception {
        RequestContextHolder.setRequestAttributes(new ServletRequestAttributes(new MockHttpServletRequest()));
        try {
            return call.run();
        } finally {
            RequestContextHolder.resetRequestAttributes();
        }
    }

    /** How long a call of a request thread takes to be refused: it fails as an MFA step fails, or ends without the work done. */
    private static Duration refusedAfter(Call<?> call) throws Exception {
        long start = System.nanoTime();
        Object result = null;
        try {
            result = onRequestThread(call);
        } catch (MfaStateMachineException refused) {
            return Duration.ofNanos(System.nanoTime() - start);
        }
        if (Boolean.FALSE.equals(result)) {
            return Duration.ofNanos(System.nanoTime() - start);
        }
        throw new AssertionError("the step was expected to be refused, and returned " + result);
    }

    /** What the distributed MFA service stands on in an application of Contexa: the platform and its policies. */
    @Configuration(proxyBeanMethods = false)
    @EnableConfigurationProperties(SecurityPlaneProperties.class)
    static class ContexaSide {

        @Bean
        PlatformConfig platformConfig() {
            return PlatformConfig.builder().build();
        }

        @Bean
        MfaPolicyProvider mfaPolicyProvider() {
            return mock(MfaPolicyProvider.class);
        }

        @Bean
        AuthContextProperties authContextProperties() {
            return new AuthContextProperties();
        }

        @Bean
        MfaSessionRepository contexaMfaSessionRepository() {
            return mock(MfaSessionRepository.class);
        }
    }
}
