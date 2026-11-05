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
package io.contexa.contexaidentity.security.statemachine.config;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.springframework.beans.factory.config.BeanFactoryPostProcessor;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;
import org.springframework.boot.test.system.CapturedOutput;
import org.springframework.boot.test.system.OutputCaptureExtension;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.statemachine.config.EnableStateMachineFactory;
import org.springframework.statemachine.config.StateMachineConfigurerAdapter;
import org.springframework.statemachine.config.builders.StateMachineStateConfigurer;

import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * PR-29: Spring State Machine declares its annotation post processor on a configuration of its own, and Spring's checker
 * wrote a warning about that library into the start log of every application that turned Contexa on.
 */
@ExtendWith(OutputCaptureExtension.class)
class StateMachineInfrastructureRoleTest {

    private static final String WARNING = "StateMachineAnnotationPostProcessorConfiguration' of type";

    @Test
    @DisplayName("what this stands on: the library's configuration warns by itself")
    void theLibraryAloneWarns(CapturedOutput output) {
        new ApplicationContextRunner().withUserConfiguration(Machine.class).run(context -> {
            assertThat(context).hasNotFailed();
            assertThat(output).contains(WARNING);
        });
    }

    @Test
    @DisplayName("the role Contexa gives the library's configuration keeps the application's start log clean")
    void theRoleKeepsTheStartLogClean(CapturedOutput output) {
        new ApplicationContextRunner().withUserConfiguration(Machine.class, Role.class).run(context -> {
            assertThat(context).hasNotFailed();
            assertThat(output).doesNotContain(WARNING);
        });
    }

    @Configuration(proxyBeanMethods = false)
    static class Role {

        @Bean
        static BeanFactoryPostProcessor role() {
            return MfaStateMachineConfiguration.contexaStateMachineInfrastructureRole();
        }
    }

    @Configuration(proxyBeanMethods = false)
    @EnableStateMachineFactory(name = "sampleMachineFactory")
    static class Machine extends StateMachineConfigurerAdapter<String, String> {

        @Override
        public void configure(StateMachineStateConfigurer<String, String> states) throws Exception {
            states.withStates().initial("START").states(Set.of("START", "END"));
        }
    }
}
