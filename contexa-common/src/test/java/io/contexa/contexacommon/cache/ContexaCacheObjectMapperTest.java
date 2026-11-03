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

import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Test;
import org.springframework.boot.autoconfigure.AutoConfigurations;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;
import org.springframework.test.util.ReflectionTestUtils;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * What the cache stores must not depend on how an application configured its JSON: the cache takes Contexa's mapper, and a mapper of its
 * own when this library is used without the Contexa core, and never the application's.
 */
class ContexaCacheObjectMapperTest {

    private final ApplicationContextRunner runner = new ApplicationContextRunner()
            .withConfiguration(AutoConfigurations.of(ContexaCacheAutoConfiguration.class));

    @Test
    void startsWithoutTheContexaCoreAndUsesAMapperOfItsOwn() {
        runner.run(context -> {
            assertThat(context).hasNotFailed();
            Object mapper = ReflectionTestUtils.getField(context.getBean(ContexaCacheService.class), "objectMapper");

            assertThat(mapper).isInstanceOf(ObjectMapper.class);
        });
    }

    @Test
    void neverTakesTheApplicationsMapper() {
        ObjectMapper applications = new ObjectMapper();

        runner.withBean("objectMapper", ObjectMapper.class, () -> applications).run(context -> {
            assertThat(context).hasNotFailed();
            Object mapper = ReflectionTestUtils.getField(context.getBean(ContexaCacheService.class), "objectMapper");

            assertThat(mapper).isNotNull().isNotSameAs(applications);
        });
    }

    @Test
    void takesContexasMapperWhenTheCoreProvidesIt() {
        ObjectMapper contexas = new ObjectMapper();
        ObjectMapper applications = new ObjectMapper();

        runner.withBean("contexaObjectMapper", ObjectMapper.class, () -> contexas)
                .withBean("objectMapper", ObjectMapper.class, () -> applications)
                .run(context -> {
                    assertThat(context).hasNotFailed();

                    assertThat(ReflectionTestUtils.getField(context.getBean(ContexaCacheService.class), "objectMapper")).isSameAs(contexas);
                });
    }
}
