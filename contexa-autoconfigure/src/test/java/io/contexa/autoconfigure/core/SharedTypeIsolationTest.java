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
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.boot.autoconfigure.AutoConfigurations;
import org.springframework.boot.autoconfigure.jackson.JacksonAutoConfiguration;
import org.springframework.boot.autoconfigure.task.TaskExecutionAutoConfiguration;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.task.SimpleAsyncTaskExecutor;

import java.util.concurrent.Executor;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * What Spring does with beans that are not default candidates (the way Contexa's mapper and executors are defined): the application
 * that has none of its own still gets the one Spring Boot provides, and the application's own is what its code is given.
 */
class SharedTypeIsolationTest {

    /** Stands in for Contexa's configuration. */
    @Configuration(proxyBeanMethods = false)
    static class LibraryBeans {

        @Bean(name = "libraryObjectMapper", defaultCandidate = false)
        ObjectMapper libraryObjectMapper() {
            return new ObjectMapper();
        }

        @Bean(name = "libraryExecutor", defaultCandidate = false)
        Executor libraryExecutor() {
            return new SimpleAsyncTaskExecutor("library-");
        }

        @Bean
        LibraryUser libraryUser(@Qualifier("libraryObjectMapper") ObjectMapper mapper, @Qualifier("libraryExecutor") Executor executor) {
            return new LibraryUser(mapper, executor);
        }
    }

    record LibraryUser(ObjectMapper mapper, Executor executor) {
    }

    /** The application's code: takes the mapper and the executor by type, as application code does. */
    record ApplicationUser(ObjectMapper mapper, Executor executor) {
    }

    @Configuration(proxyBeanMethods = false)
    static class ApplicationWithNone {
        @Bean
        ApplicationUser applicationUser(ObjectMapper mapper, Executor executor) {
            return new ApplicationUser(mapper, executor);
        }
    }

    @Configuration(proxyBeanMethods = false)
    static class ApplicationWithItsOwn {
        @Bean
        ObjectMapper applicationMapper() {
            return new ObjectMapper();
        }

        @Bean
        Executor applicationExecutor() {
            return new SimpleAsyncTaskExecutor("application-");
        }

        @Bean
        ApplicationUser applicationUser(ObjectMapper mapper, Executor executor) {
            return new ApplicationUser(mapper, executor);
        }
    }

    private ApplicationContextRunner runner(Class<?> application) {
        return new ApplicationContextRunner()
                .withUserConfiguration(application)
                .withConfiguration(AutoConfigurations.of(JacksonAutoConfiguration.class, TaskExecutionAutoConfiguration.class))
                .withUserConfiguration(LibraryBeans.class);
    }

    @Test
    void anApplicationWithoutItsOwnStillGetsSpringBootsMapperAndExecutor() {
        runner(ApplicationWithNone.class).run(context -> {
            assertThat(context).hasNotFailed();
            ApplicationUser user = context.getBean(ApplicationUser.class);
            assertThat(user.mapper()).isSameAs(context.getBean("jacksonObjectMapper"));
            assertThat(user.executor()).isSameAs(context.getBean("applicationTaskExecutor"));
            assertThat(user.mapper()).isNotSameAs(context.getBean("libraryObjectMapper"));
            assertThat(user.executor()).isNotSameAs(context.getBean("libraryExecutor"));
        });
    }

    @Test
    void anApplicationWithItsOwnIsGivenItsOwn() {
        runner(ApplicationWithItsOwn.class).run(context -> {
            assertThat(context).hasNotFailed();
            ApplicationUser user = context.getBean(ApplicationUser.class);
            assertThat(user.mapper()).isSameAs(context.getBean("applicationMapper"));
            assertThat(user.executor()).isSameAs(context.getBean("applicationExecutor"));
        });
    }

    @Test
    void theLibraryGetsItsOwnByQualifierWhateverTheApplicationHas() {
        runner(ApplicationWithItsOwn.class).run(context -> {
            LibraryUser user = context.getBean(LibraryUser.class);
            assertThat(user.mapper()).isSameAs(context.getBean("libraryObjectMapper"));
            assertThat(user.executor()).isSameAs(context.getBean("libraryExecutor"));
        });
        runner(ApplicationWithNone.class).run(context -> {
            LibraryUser user = context.getBean(LibraryUser.class);
            assertThat(user.mapper()).isSameAs(context.getBean("libraryObjectMapper"));
        });
    }
}
