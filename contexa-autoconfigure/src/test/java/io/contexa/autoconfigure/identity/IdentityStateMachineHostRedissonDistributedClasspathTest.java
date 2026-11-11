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
import io.contexa.autoconfigure.hostredis.CountedRedissonForDistributedClasspathTests;
import io.contexa.contexacommon.config.redis.CommonRedisAutoConfiguration;
import io.contexa.contexacommon.properties.AuthContextProperties;
import io.contexa.contexacommon.store.ApplicationNamespace;
import io.contexa.contexacore.infra.session.MfaSessionRepository;
import io.contexa.contexacore.properties.SecurityPlaneProperties;
import io.contexa.contexaidentity.security.core.config.PlatformConfig;
import io.contexa.contexaidentity.security.core.mfa.context.FactorContext;
import io.contexa.contexaidentity.security.core.mfa.policy.MfaPolicyProvider;
import io.contexa.contexaidentity.security.filter.handler.MfaStateMachineIntegrator;
import io.contexa.contexaidentity.security.statemachine.core.service.MfaStateMachineService;
import io.contexa.contexaidentity.security.statemachine.core.service.MfaStateMachineServiceImpl;
import io.contexa.contexaidentity.security.statemachine.core.service.StandaloneMfaStateMachineServiceImpl;
import io.contexa.contexaidentity.security.statemachine.enums.MfaState;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.EnabledIfEnvironmentVariable;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.redisson.api.RedissonClient;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.AutoConfigurations;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.data.redis.RedisAutoConfiguration;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;
import org.springframework.context.ApplicationContext;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.data.redis.connection.RedisStandaloneConfiguration;
import org.springframework.data.redis.connection.lettuce.LettuceConnectionFactory;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.test.util.ReflectionTestUtils;

import java.util.ArrayList;
import java.util.List;
import java.util.Set;
import java.util.TreeSet;
import java.util.UUID;
import java.util.stream.Stream;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;

/**
 * An application with a Redisson client of its own, in each infrastructure mode and each security mode, on a real Redis:
 * the application starts, Contexa keeps its MFA flows where its infrastructure mode says (in memory when standalone, in
 * Redis through Contexa's own Redisson client when distributed), Contexa sends nothing through the application's client,
 * and the application's code is still given the application's client. An application without a client of its own starts as
 * before. Runs in the task distributedClasspathTest, whose class path has Redisson and Spring Statemachine's Redis
 * repositories. CONTEXA_TEST_REDIS_PORT: a Redis of the test; it removes only the keys it wrote.
 */
@EnabledIfEnvironmentVariable(named = IdentityStateMachineHostRedissonDistributedClasspathTest.PORT, matches = "[0-9]+")
class IdentityStateMachineHostRedissonDistributedClasspathTest {

    static final String PORT = "CONTEXA_TEST_REDIS_PORT";
    private static final String HOST = "CONTEXA_TEST_REDIS_HOST";
    private static final String FLOWS = "RedisRepositoryStateMachine";
    private static final String USERNAME = "alice";
    /** The database of the application's own client; Contexa's state is in Spring Boot's connection, database 0. */
    private static final int APPLICATION_DATABASE = 5;

    private static String redisHost;
    private static int redisPort;
    private static LettuceConnectionFactory contexaDatabase;
    private static LettuceConnectionFactory applicationDatabase;
    private static StringRedisTemplate contexaRedis;
    private static StringRedisTemplate applicationRedis;

    private final List<String> flows = new ArrayList<>();

    @BeforeAll
    static void connect() {
        String host = System.getenv(HOST);
        redisHost = host == null || host.isBlank() ? "127.0.0.1" : host.trim();
        redisPort = Integer.parseInt(System.getenv(PORT).trim());
        assertThat(redisPort).as("a Redis of the test, not one on 6379").isNotEqualTo(6379);
        contexaDatabase = connections(0);
        applicationDatabase = connections(APPLICATION_DATABASE);
        contexaRedis = new StringRedisTemplate(contexaDatabase);
        applicationRedis = new StringRedisTemplate(applicationDatabase);
    }

    @AfterAll
    static void disconnect() {
        for (LettuceConnectionFactory factory : new LettuceConnectionFactory[] {contexaDatabase, applicationDatabase}) {
            if (factory != null) {
                factory.destroy();
            }
        }
    }

    @AfterEach
    void removeWhatThisTestWrote() {
        for (String flow : flows) {
            for (StringRedisTemplate redis : List.of(contexaRedis, applicationRedis)) {
                redis.delete(redis.keys("*" + flow + "*"));
                redis.opsForSet().remove(FLOWS, flow);
            }
        }
    }

    static Stream<Arguments> configurations() {
        return Stream.of("standalone", "distributed").flatMap(infrastructure -> Stream.of("SANDBOX", "FULL")
                .flatMap(security -> Stream.of(true, false).map(own -> Arguments.of(infrastructure, security, own))));
    }

    @ParameterizedTest(name = "{0}, {1}, a Redisson client of the application''s own: {2}")
    @MethodSource("configurations")
    @DisplayName("the application starts, the flows are kept where the infrastructure mode says, and the application's own client is neither used nor hidden")
    void theFlowsAreKeptWhereTheModeSays(String infrastructure, String security, boolean ownClient) {
        boolean distributed = infrastructure.equals("distributed");
        try (ApplicationNamespace.Scope ignored = ApplicationNamespace.using("")) {
            runner(infrastructure, security, ownClient).run(context -> {
                assertThat(context).hasNotFailed();
                MfaStateMachineService service = context.getBean("contexaMfaStateMachineService", MfaStateMachineService.class);

                String flow = startedFlow(context);
                FactorContext read = context.getBean(MfaStateMachineIntegrator.class).loadFactorContext(flow);
                assertThat(read).as("the flow read back").isNotNull();
                assertThat(read.getUsername()).isEqualTo(USERNAME);

                if (distributed) {
                    assertThat(service).isInstanceOf(MfaStateMachineServiceImpl.class);
                    assertThat(ReflectionTestUtils.getField(service, "redissonClient"))
                            .as("the lock of the flows is Contexa's own client").isSameAs(context.getBean("contexaRedissonClient"));
                    assertThat(keys(contexaRedis, flow)).as("the flow in Contexa's Redis").containsExactly(FLOWS + ":" + flow);
                } else {
                    assertThat(service).isInstanceOf(StandaloneMfaStateMachineServiceImpl.class);
                    assertThat(context).doesNotHaveBean("contexaRedissonClient")
                            .doesNotHaveBean("contexaRedisStateMachineRepository");
                    assertThat(keys(contexaRedis, flow)).as("nothing of the flow in Redis").isEmpty();
                }
                assertThat(keys(applicationRedis, flow)).as("nothing of the flow in the database of the application's client").isEmpty();

                if (ownClient) {
                    CountedRedissonForDistributedClasspathTests own = context.getBean(CountedRedissonForDistributedClasspathTests.class);
                    assertThat(own.calls()).as("what Contexa sent through the application's client").isEmpty();
                    assertThat(context.getBean(ApplicationCode.class).redisson())
                            .as("the client the application's code is given").isSameAs(own.client());
                }
            });
        }
    }

    @Test
    @DisplayName("an application that makes its client the way the Redisson starter does, before Spring Boot's Redis, keeps it, and Contexa keeps its own")
    void anApplicationClientMadeAheadOfSpringBootsRedisIsKept() {
        try (ApplicationNamespace.Scope ignored = ApplicationNamespace.using("")) {
            for (String infrastructure : List.of("standalone", "distributed")) {
                new ApplicationContextRunner()
                        .withPropertyValues(properties(infrastructure, "SANDBOX"))
                        .withUserConfiguration(ContexaSide.class, ApplicationClientHolder.class)
                        .withConfiguration(AutoConfigurations.of(with(autoConfigurations(infrastructure.equals("distributed")),
                                ApplicationRedissonStarter.class)))
                        .run(context -> {
                            assertThat(context).hasNotFailed();
                            CountedRedissonForDistributedClasspathTests own = context.getBean(CountedRedissonForDistributedClasspathTests.class);
                            assertThat(context.getBean("redisson")).as("the application's client is made").isSameAs(own.client());
                            assertThat(context.getBean(ApplicationCode.class).redisson()).isSameAs(own.client());

                            String flow = startedFlow(context);
                            assertThat(context.getBean(MfaStateMachineIntegrator.class).loadFactorContext(flow)).isNotNull();
                            assertThat(own.calls()).as("what Contexa sent through the application's client").isEmpty();
                            if (infrastructure.equals("distributed")) {
                                assertThat(context.getBean("contexaRedissonClient")).isNotSameAs(own.client());
                            }
                        });
            }
        }
    }

    @Test
    @DisplayName("in the distributed mode the code of an application without a client of its own is given Contexa's client, as it was")
    void anApplicationWithoutAClientIsGivenContexasAsBefore() {
        try (ApplicationNamespace.Scope ignored = ApplicationNamespace.using("")) {
            runner("distributed", "SANDBOX", false).withUserConfiguration(ApplicationCodeTakingAClient.class).run(context -> {
                assertThat(context).hasNotFailed();
                assertThat(context.getBean(ApplicationCode.class).redisson()).isSameAs(context.getBean("contexaRedissonClient"));
            });
        }
    }

    private static ApplicationContextRunner runner(String infrastructure, String security, boolean ownClient) {
        ApplicationContextRunner runner = new ApplicationContextRunner()
                .withPropertyValues(properties(infrastructure, security))
                .withUserConfiguration(ContexaSide.class)
                .withConfiguration(AutoConfigurations.of(autoConfigurations(infrastructure.equals("distributed"))));
        return ownClient ? runner.withUserConfiguration(ApplicationClientHolder.class, ApplicationWithItsOwnClient.class) : runner;
    }

    private static String[] properties(String infrastructure, String security) {
        return new String[] {"spring.data.redis.host=" + redisHost, "spring.data.redis.port=" + redisPort,
                "contexa.infrastructure.mode=" + infrastructure, "contexa.ai.security.mode=" + security};
    }

    /**
     * What a start passes in the mode: Spring Boot's Redis (the application configured its Redis), Contexa's infrastructure
     * and state machine, and in the distributed mode Contexa's own Redis configuration, which the standalone mode leaves out
     * (StandaloneAutoConfigurationFilter).
     */
    private static Class<?>[] autoConfigurations(boolean distributed) {
        List<Class<?>> classes = new ArrayList<>(List.of(RedisAutoConfiguration.class, CoreInfrastructureAutoConfiguration.class,
                IdentityStateMachineAutoConfiguration.class));
        if (distributed) {
            classes.add(CommonRedisAutoConfiguration.class);
        }
        return classes.toArray(Class<?>[]::new);
    }

    private static Class<?>[] with(Class<?>[] classes, Class<?> more) {
        List<Class<?>> all = new ArrayList<>(List.of(classes));
        all.add(more);
        return all.toArray(Class<?>[]::new);
    }

    private String startedFlow(ApplicationContext context) {
        String flow = "host-redisson-flow-" + UUID.randomUUID();
        flows.add(flow);
        FactorContext factorContext = new FactorContext(flow, UsernamePasswordAuthenticationToken.authenticated(USERNAME, null,
                List.of(new SimpleGrantedAuthority("ROLE_USER"))), MfaState.NONE, "mfa");
        context.getBean(MfaStateMachineIntegrator.class).initializeStateMachine(factorContext, new MockHttpServletRequest(), null);
        return flow;
    }

    private static Set<String> keys(StringRedisTemplate redis, String flow) {
        Set<String> keys = new TreeSet<>(redis.keys("*" + flow + "*"));
        if (Boolean.TRUE.equals(redis.opsForSet().isMember(FLOWS, flow)) && keys.isEmpty()) {
            keys.add(FLOWS + " holds the flow");
        }
        return keys;
    }

    private static LettuceConnectionFactory connections(int database) {
        RedisStandaloneConfiguration configuration = new RedisStandaloneConfiguration(redisHost, redisPort);
        configuration.setDatabase(database);
        LettuceConnectionFactory factory = new LettuceConnectionFactory(configuration);
        factory.afterPropertiesSet();
        return factory;
    }

    @Configuration(proxyBeanMethods = false)
    static class ApplicationClientHolder {

        @Bean
        CountedRedissonForDistributedClasspathTests countedRedisson() {
            return new CountedRedissonForDistributedClasspathTests(redisHost, redisPort, APPLICATION_DATABASE);
        }

        @Bean
        ApplicationCode applicationCode(RedissonClient client) {
            return new ApplicationCode(client);
        }
    }

    /** An application that declares its Redisson client as a bean of its own. */
    @Configuration(proxyBeanMethods = false)
    static class ApplicationWithItsOwnClient {

        @Bean(destroyMethod = "")
        RedissonClient redisson(CountedRedissonForDistributedClasspathTests counted) {
            return counted.client();
        }
    }

    /** The shape of the Redisson starter's configuration: ahead of Spring Boot's Redis, and only without a client. */
    @AutoConfiguration(before = RedisAutoConfiguration.class)
    static class ApplicationRedissonStarter {

        @Bean(destroyMethod = "")
        @ConditionalOnMissingBean(RedissonClient.class)
        RedissonClient redisson(CountedRedissonForDistributedClasspathTests counted) {
            return counted.client();
        }
    }

    @Configuration(proxyBeanMethods = false)
    static class ApplicationCodeTakingAClient {

        @Bean
        ApplicationCode applicationCode(RedissonClient client) {
            return new ApplicationCode(client);
        }
    }

    /** The application's code that is given a Redisson client by its type. */
    record ApplicationCode(RedissonClient redisson) {
    }

    /**
     * What the MFA store stands on in an application of Contexa: the platform, its policies, the MFA session store, and
     * the properties other configurations of Contexa register.
     */
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
