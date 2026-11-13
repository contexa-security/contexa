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
package io.contexa.contexacommon.cache;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.support.AbstractBeanDefinition;
import org.springframework.boot.autoconfigure.AutoConfigurations;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;
import org.springframework.data.redis.connection.RedisConnectionFactory;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.test.util.ReflectionTestUtils;

import java.util.concurrent.atomic.AtomicInteger;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;

/**
 * In the distributed mode the cache is on Contexa's own template. The application's {@code stringRedisTemplate} is the application's:
 * Contexa reads it only when its own is missing, so in an application with lazy initialisation Contexa does not make it (the grid's
 * {@code start-lazy} host saw Spring Boot's {@code stringRedisTemplate} made once Contexa was mounted).
 */
class ContexaCacheLeavesTheApplicationsTemplateTest {

    private final ApplicationContextRunner runner = new ApplicationContextRunner()
            .withPropertyValues("contexa.infrastructure.mode=distributed")
            .withConfiguration(AutoConfigurations.of(ContexaCacheAutoConfiguration.class));

    private static StringRedisTemplate template() {
        return new StringRedisTemplate(mock(RedisConnectionFactory.class));
    }

    @Test
    void theApplicationsLazyTemplateIsNotMadeWhenContexasOwnIsThere() {
        AtomicInteger made = new AtomicInteger();
        StringRedisTemplate contexas = template();

        runner.withBean("stringRedisTemplate", StringRedisTemplate.class, () -> {
                    made.incrementAndGet();
                    return template();
                }, definition -> definition.setLazyInit(true))
                .withBean("contexaStringRedisTemplate", StringRedisTemplate.class, () -> contexas,
                        definition -> ((AbstractBeanDefinition) definition).setDefaultCandidate(false))
                .run(context -> {
                    assertThat(context).hasNotFailed();

                    assertThat(ReflectionTestUtils.getField(context.getBean(ContexaCacheService.class), "redisTemplate")).isSameAs(contexas);
                    assertThat(made).as("the application's lazy template is not made by Contexa").hasValue(0);
                });
    }

    @Test
    void theApplicationsTemplateIsStillTheFallback() {
        StringRedisTemplate applications = template();

        runner.withBean("stringRedisTemplate", StringRedisTemplate.class, () -> applications).run(context -> {
            assertThat(context).hasNotFailed();

            assertThat(ReflectionTestUtils.getField(context.getBean(ContexaCacheService.class), "redisTemplate")).isSameAs(applications);
        });
    }
}
