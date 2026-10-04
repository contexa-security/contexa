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
package io.contexa.autoconfigure.ai;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.springframework.boot.autoconfigure.AutoConfigurations;
import org.springframework.boot.autoconfigure.security.servlet.SecurityAutoConfiguration;
import org.springframework.boot.test.context.runner.WebApplicationContextRunner;
import org.springframework.boot.test.system.CapturedOutput;
import org.springframework.boot.test.system.OutputCaptureExtension;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.web.SecurityFilterChain;

import static org.assertj.core.api.Assertions.assertThat;

@ExtendWith(OutputCaptureExtension.class)
class HostOwnedSecurityChainDiagnosticsTest {

    private final WebApplicationContextRunner runner = new WebApplicationContextRunner()
            .withConfiguration(AutoConfigurations.of(SecurityAutoConfiguration.class))
            .withBean(HostOwnedSecurityChainDiagnostics.class);

    @Test
    void reportsWhenOnlySpringBootDefaultChainIsPresent(CapturedOutput output) {
        runner.run(context -> {
            assertThat(context).hasNotFailed();
            assertThat(context.getBean(HostOwnedSecurityChainDiagnostics.class).onlySpringBootDefaultChains()).isTrue();
            assertThat(output).contains("HOST_OWNED mode: no SecurityFilterChain is declared by the application");
        });
    }

    @Test
    void staysSilentWhenTheHostDeclaresItsOwnChain(CapturedOutput output) {
        runner.withUserConfiguration(HostChainConfiguration.class).run(context -> {
            assertThat(context).hasNotFailed();
            assertThat(context.getBean(HostOwnedSecurityChainDiagnostics.class).onlySpringBootDefaultChains()).isFalse();
            assertThat(output).doesNotContain("HOST_OWNED mode: no SecurityFilterChain is declared by the application");
        });
    }

    @Configuration(proxyBeanMethods = false)
    static class HostChainConfiguration {

        @Bean
        SecurityFilterChain hostChain(HttpSecurity http) throws Exception {
            return http.authorizeHttpRequests(auth -> auth.anyRequest().permitAll()).build();
        }
    }
}
