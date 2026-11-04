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

import io.contexa.contexacore.properties.SecurityZeroTrustProperties;
import io.contexa.contexaidentity.config.ZeroTrustRedisConfig;
import org.junit.jupiter.api.Test;
import org.springframework.boot.autoconfigure.AutoConfigurations;
import org.springframework.boot.autoconfigure.data.redis.RedisAutoConfiguration;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.data.redis.connection.RedisConnectionFactory;
import org.springframework.data.redis.connection.lettuce.LettuceConnectionFactory;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * An application that has its Redis configured (database, TLS, user) keeps that connection when Contexa runs in the distributed mode:
 * Contexa's templates use the application's connection factory, and Contexa makes one of its own only for an application that has none.
 */
class ZeroTrustRedisHostCoexistenceTest {

    @Configuration(proxyBeanMethods = false)
    static class Properties {
        @Bean
        SecurityZeroTrustProperties securityZeroTrustProperties() {
            return new SecurityZeroTrustProperties();
        }
    }

    private ApplicationContextRunner runner(Class<?>... configurations) {
        return new ApplicationContextRunner()
                .withPropertyValues("contexa.infrastructure.mode=distributed", "spring.data.redis.host=redis.example",
                        "spring.data.redis.database=5", "spring.data.redis.username=svc", "spring.data.redis.password=s3cret")
                .withUserConfiguration(Properties.class)
                .withConfiguration(AutoConfigurations.of(configurations));
    }

    @Test
    void theApplicationsRedisIsTheOneContexaUsesAndSpringBootsSettingsAreNotLost() {
        runner(RedisAutoConfiguration.class, ZeroTrustRedisConfig.class).run(context -> {
            assertThat(context).hasNotFailed();

            RedisConnectionFactory factory = context.getBean(RedisConnectionFactory.class);
            assertThat(factory).isInstanceOf(LettuceConnectionFactory.class);
            assertThat(((LettuceConnectionFactory) factory).getDatabase()).as("the application's database").isEqualTo(5);
            assertThat(((LettuceConnectionFactory) factory).getStandaloneConfiguration().getUsername()).isEqualTo("svc");
            assertThat(context).as("Contexa makes no connection of its own beside the application's")
                    .doesNotHaveBean("contexaRedisConnectionFactory").doesNotHaveBean("contexaClientResources")
                    .doesNotHaveBean("contexaLettuceClientConfiguration");
            assertThat(context.getBeansOfType(io.lettuce.core.resource.ClientResources.class))
                    .as("Spring Boot's own client resources, not Contexa's").hasSize(1);
        });
    }

    @Test
    void anApplicationWithoutRedisConfigurationOfItsOwnGetsContexasConnectionWithTheSameSettings() {
        runner(ZeroTrustRedisConfig.class).run(context -> {
            assertThat(context).hasNotFailed();

            LettuceConnectionFactory factory = (LettuceConnectionFactory) context.getBean("contexaRedisConnectionFactory");
            assertThat(factory.getDatabase()).isEqualTo(5);
            assertThat(factory.getStandaloneConfiguration().getUsername()).isEqualTo("svc");
            assertThat(factory.getStandaloneConfiguration().getHostName()).isEqualTo("redis.example");
        });
    }
}
