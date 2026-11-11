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
package io.contexa.autoconfigure.iam.xacml;

import io.contexa.autoconfigure.core.infra.CoreInfrastructureAutoConfiguration;
import io.contexa.autoconfigure.hostredis.CountedRedissonForDistributedClasspathTests;
import io.contexa.contexacommon.config.redis.CommonRedisAutoConfiguration;
import io.contexa.contexacommon.store.ApplicationNamespace;
import io.contexa.contexacore.infra.redis.PolicyReloadBroadcaster;
import io.contexa.contexacore.properties.SecurityPlaneProperties;
import io.contexa.contexaiam.security.xacml.pep.CustomDynamicAuthorizationManager;
import io.contexa.contexaiam.security.xacml.prp.PolicyRetrievalPoint;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.EnabledIfEnvironmentVariable;
import org.redisson.Redisson;
import org.redisson.api.RedissonClient;
import org.redisson.config.Config;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.AutoConfigurations;
import org.springframework.boot.autoconfigure.data.redis.RedisAutoConfiguration;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Import;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.timeout;
import static org.mockito.Mockito.verify;

/**
 * In the distributed mode the policy reload signal between the servers of an application goes through Contexa's own
 * Redisson client, on a real Redis, whether or not the application has a client of its own: the application's client is
 * given to the application's code and carries nothing of Contexa's. Runs in the task distributedClasspathTest, whose class
 * path has Redisson. CONTEXA_TEST_REDIS_PORT: a Redis of the test; nothing is kept in it.
 */
@EnabledIfEnvironmentVariable(named = PolicyReloadHostRedissonDistributedClasspathTest.PORT, matches = "[0-9]+")
class PolicyReloadHostRedissonDistributedClasspathTest {

    static final String PORT = "CONTEXA_TEST_REDIS_PORT";
    private static final String TOPIC = "contexa:policy:reload-signal";
    private static final int APPLICATION_DATABASE = 5;

    private static String redisHost;
    private static int redisPort;

    @BeforeAll
    static void address() {
        String host = System.getenv("CONTEXA_TEST_REDIS_HOST");
        redisHost = host == null || host.isBlank() ? "127.0.0.1" : host.trim();
        redisPort = Integer.parseInt(System.getenv(PORT).trim());
        assertThat(redisPort).as("a Redis of the test, not one on 6379").isNotEqualTo(6379);
    }

    @Test
    @DisplayName("an application's own client carries no policy reload signal of Contexa's, its code is still given it, and another server's signal is heard")
    void theApplicationsClientCarriesNoSignal() {
        try (ApplicationNamespace.Scope ignored = ApplicationNamespace.using("")) {
            runner().withUserConfiguration(ApplicationWithItsOwnClient.class).run(context -> {
                assertThat(context).hasNotFailed();
                assertThat(context).hasSingleBean(PolicyReloadBroadcaster.class);
                CountedRedissonForDistributedClasspathTests own = context.getBean(CountedRedissonForDistributedClasspathTests.class);

                signalFromAnotherServer();
                verify(context.getBean(PolicyRetrievalPoint.class), timeout(5_000)).clearUrlPoliciesCache();
                assertThat(own.calls()).as("what Contexa sent through the application's client").isEmpty();
                assertThat(context.getBean(ApplicationCode.class).redisson()).isSameAs(own.client());
            });
        }
    }

    @Test
    @DisplayName("without a client of the application's own the signal goes through Contexa's client, as before")
    void withoutAClientOfTheApplicationsOwn() {
        try (ApplicationNamespace.Scope ignored = ApplicationNamespace.using("")) {
            runner().run(context -> {
                assertThat(context).hasNotFailed();
                signalFromAnotherServer();
                verify(context.getBean(PolicyRetrievalPoint.class), timeout(5_000)).clearUrlPoliciesCache();
            });
        }
    }

    private static void signalFromAnotherServer() {
        Config config = new Config();
        config.useSingleServer().setAddress("redis://" + redisHost + ":" + redisPort);
        RedissonClient anotherServer = Redisson.create(config);
        try {
            anotherServer.getTopic(ApplicationNamespace.key(TOPIC)).publish("POLICY_RELOAD:another-server");
        } finally {
            anotherServer.shutdown();
        }
    }

    private static ApplicationContextRunner runner() {
        return new ApplicationContextRunner()
                .withPropertyValues("spring.data.redis.host=" + redisHost, "spring.data.redis.port=" + redisPort,
                        "contexa.infrastructure.mode=distributed")
                .withUserConfiguration(ContexaSide.class)
                .withConfiguration(AutoConfigurations.of(RedisAutoConfiguration.class, CommonRedisAutoConfiguration.class,
                        CoreInfrastructureAutoConfiguration.class, PolicyReload.class));
    }

    /** The broadcaster's configuration, in the order IamXacmlPapAutoConfiguration has: after Contexa's infrastructure. */
    @AutoConfiguration(after = CoreInfrastructureAutoConfiguration.class)
    @Import(IamXacmlPapAutoConfiguration.RedissonPapConfiguration.class)
    static class PolicyReload {
    }

    /** What the broadcaster reloads, and the properties other configurations of Contexa register. */
    @Configuration(proxyBeanMethods = false)
    @EnableConfigurationProperties(SecurityPlaneProperties.class)
    static class ContexaSide {

        @Bean
        PolicyRetrievalPoint policyRetrievalPoint() {
            return mock(PolicyRetrievalPoint.class);
        }

        @Bean
        CustomDynamicAuthorizationManager customDynamicAuthorizationManager() {
            return mock(CustomDynamicAuthorizationManager.class);
        }
    }

    /** An application that declares a Redisson client of its own, on another database, and code that is given it. */
    @Configuration(proxyBeanMethods = false)
    static class ApplicationWithItsOwnClient {

        @Bean
        CountedRedissonForDistributedClasspathTests countedRedisson() {
            return new CountedRedissonForDistributedClasspathTests(redisHost, redisPort, APPLICATION_DATABASE);
        }

        @Bean(destroyMethod = "")
        RedissonClient redisson(CountedRedissonForDistributedClasspathTests counted) {
            return counted.client();
        }

        @Bean
        ApplicationCode applicationCode(RedissonClient client) {
            return new ApplicationCode(client);
        }
    }

    record ApplicationCode(RedissonClient redisson) {
    }
}
