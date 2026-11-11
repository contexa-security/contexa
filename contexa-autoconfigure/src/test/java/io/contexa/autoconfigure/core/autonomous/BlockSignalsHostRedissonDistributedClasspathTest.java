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
package io.contexa.autoconfigure.core.autonomous;

import io.contexa.autoconfigure.core.infra.CoreInfrastructureAutoConfiguration;
import io.contexa.autoconfigure.hostredis.CountedRedissonForDistributedClasspathTests;
import io.contexa.contexacommon.config.redis.CommonRedisAutoConfiguration;
import io.contexa.contexacommon.store.ApplicationNamespace;
import io.contexa.contexacore.autonomous.blocking.BlockingDecisionRegistry;
import io.contexa.contexacore.properties.SecurityPlaneProperties;
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

import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * In the distributed mode the block signals between the servers of an application go through Contexa's own Redisson
 * client, on a real Redis, whether or not the application has a client of its own: the application's client is given to
 * the application's code and carries nothing of Contexa's. Runs in the task distributedClasspathTest, whose class path has
 * Redisson. CONTEXA_TEST_REDIS_PORT: a Redis of the test; nothing is kept in it.
 */
@EnabledIfEnvironmentVariable(named = BlockSignalsHostRedissonDistributedClasspathTest.PORT, matches = "[0-9]+")
class BlockSignalsHostRedissonDistributedClasspathTest {

    static final String PORT = "CONTEXA_TEST_REDIS_PORT";
    private static final String TOPIC = "contexa:security:block-signal";
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
    @DisplayName("an application's own client carries none of Contexa's block signals, its code is still given it, and a signal of another server is heard")
    void theApplicationsClientCarriesNoSignal() {
        try (ApplicationNamespace.Scope ignored = ApplicationNamespace.using("")) {
            runner().withUserConfiguration(ApplicationWithItsOwnClient.class).run(context -> {
                assertThat(context).hasNotFailed();
                BlockingDecisionRegistry registry = context.getBean(BlockingDecisionRegistry.class);
                CountedRedissonForDistributedClasspathTests own = context.getBean(CountedRedissonForDistributedClasspathTests.class);

                assertThat(heardFromAnotherServer(registry)).as("a block signal of another server").isTrue();
                assertThat(own.calls()).as("what Contexa sent through the application's client").isEmpty();
                assertThat(context.getBean(ApplicationCode.class).redisson()).isSameAs(own.client());
            });
        }
    }

    @Test
    @DisplayName("without a client of the application's own the signals go through Contexa's client, as before")
    void withoutAClientOfTheApplicationsOwn() {
        try (ApplicationNamespace.Scope ignored = ApplicationNamespace.using("")) {
            runner().run(context -> {
                assertThat(context).hasNotFailed();
                assertThat(heardFromAnotherServer(context.getBean(BlockingDecisionRegistry.class))).isTrue();
            });
        }
    }

    /** Another server of the application publishes a block on the topic; the registry of this one hears it. */
    private static boolean heardFromAnotherServer(BlockingDecisionRegistry registry) throws InterruptedException {
        String user = "host-redisson-user-" + UUID.randomUUID();
        Config config = new Config();
        config.useSingleServer().setAddress("redis://" + redisHost + ":" + redisPort);
        RedissonClient anotherServer = Redisson.create(config);
        try {
            anotherServer.getTopic(ApplicationNamespace.key(TOPIC)).publish("BLOCK:" + user + ":BLOCK");
            for (int attempt = 0; attempt < 50 && !registry.isBlocked(user); attempt++) {
                Thread.sleep(100);
            }
            return registry.isBlocked(user);
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
                        CoreInfrastructureAutoConfiguration.class, BlockSignals.class));
    }

    /** The registry's configuration, in the order CoreAutonomousEventAutoConfiguration has: after Contexa's infrastructure. */
    @AutoConfiguration(after = CoreInfrastructureAutoConfiguration.class)
    @Import(CoreAutonomousEventAutoConfiguration.RedissonEventConfiguration.class)
    static class BlockSignals {
    }

    @Configuration(proxyBeanMethods = false)
    @EnableConfigurationProperties(SecurityPlaneProperties.class)
    static class ContexaSide {
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
