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
package io.contexa.autoconfigure.core;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.contexa.contexacore.config.ApplicationConfig;
import org.junit.jupiter.api.Test;
import org.springframework.boot.autoconfigure.AutoConfigurations;
import org.springframework.boot.autoconfigure.jackson.JacksonAutoConfiguration;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * The application's JSON mapper stays the application's: code of the application that asks for an {@link ObjectMapper} gets the one
 * Spring Boot (or the application) provides, never Contexa's, and Contexa's own code asks for its mapper by name.
 */
class ContexaObjectMapperIsolationTest {

    static class Consumer {
        final ObjectMapper mapper;

        Consumer(ObjectMapper mapper) {
            this.mapper = mapper;
        }
    }

    @Configuration(proxyBeanMethods = false)
    static class ApplicationWithoutItsOwnMapper {
        @Bean
        Consumer consumer(ObjectMapper mapper) {
            return new Consumer(mapper);
        }
    }

    @Configuration(proxyBeanMethods = false)
    static class ApplicationWithItsOwnMapper {
        @Bean
        ObjectMapper applicationsMapper() {
            return new ObjectMapper();
        }

        @Bean
        Consumer consumer(ObjectMapper mapper) {
            return new Consumer(mapper);
        }
    }

    private ApplicationContextRunner runner(Class<?> application) {
        return new ApplicationContextRunner()
                .withUserConfiguration(application)
                .withConfiguration(AutoConfigurations.of(JacksonAutoConfiguration.class))
                .withUserConfiguration(ApplicationConfig.class);
    }

    @Test
    void anApplicationWithoutItsOwnMapperGetsSpringBootsAndNotContexas() {
        runner(ApplicationWithoutItsOwnMapper.class).run(context -> {
            assertThat(context).hasNotFailed();
            ObjectMapper contexas = context.getBean("contexaObjectMapper", ObjectMapper.class);

            assertThat(context.getBean(Consumer.class).mapper).as("the application's request for a mapper").isNotSameAs(contexas);
            assertThat(context).as("Spring Boot's own mapper is there").hasBean("jacksonObjectMapper");
            assertThat(context.getBean(Consumer.class).mapper).isSameAs(context.getBean("jacksonObjectMapper"));
        });
    }

    @Test
    void anApplicationWithItsOwnMapperKeepsIt() {
        runner(ApplicationWithItsOwnMapper.class).run(context -> {
            assertThat(context).hasNotFailed();

            assertThat(context.getBean(Consumer.class).mapper).isSameAs(context.getBean("applicationsMapper"));
            assertThat(context.getBean(Consumer.class).mapper).isNotSameAs(context.getBean("contexaObjectMapper"));
        });
    }
}
