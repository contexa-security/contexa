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

import io.contexa.autoconfigure.compat.BootDefaultUserPropertySource;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.support.DefaultListableBeanFactory;
import org.springframework.boot.autoconfigure.condition.ConditionOutcome;
import org.springframework.boot.context.properties.source.ConfigurationPropertySources;
import org.springframework.context.annotation.ConditionContext;
import org.springframework.core.env.MapPropertySource;
import org.springframework.core.env.StandardEnvironment;
import org.springframework.core.env.SystemEnvironmentPropertySource;
import org.springframework.core.type.AnnotatedTypeMetadata;

import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/**
 * R-15 of docs/agent/운영모드-정상화-구현계획.md: an application with users of its own and no chain keeps Spring Boot's
 * default chain. Spring Boot's user named by the application's settings is such a user; the name Contexa gives Boot's user
 * so that Boot keeps it is not the application's.
 */
@DisplayName("SANDBOX 격리 체인은 앱이 설정으로 정한 Boot 계정을 앱 사용자로 본다(R-15)")
class SandboxIsolationConditionTest {

    private final SandboxIsolationAutoConfiguration.NoApplicationSecurityCondition condition =
            new SandboxIsolationAutoConfiguration.NoApplicationSecurityCondition();

    private ConditionOutcome outcome(StandardEnvironment environment) {
        ConditionContext context = mock(ConditionContext.class);
        when(context.getBeanFactory()).thenReturn(new DefaultListableBeanFactory());
        when(context.getEnvironment()).thenReturn(environment);
        return condition.getMatchOutcome(context, mock(AnnotatedTypeMetadata.class));
    }

    private static StandardEnvironment environment(MapPropertySource... sources) {
        StandardEnvironment environment = new StandardEnvironment();
        environment.getPropertySources().remove(StandardEnvironment.SYSTEM_ENVIRONMENT_PROPERTY_SOURCE_NAME);
        environment.getPropertySources().remove(StandardEnvironment.SYSTEM_PROPERTIES_PROPERTY_SOURCE_NAME);
        for (MapPropertySource source : sources) {
            environment.getPropertySources().addLast(source);
        }
        return environment;
    }

    @Test
    @DisplayName("앱이 설정으로 Boot 계정 이름을 정하면 격리 체인을 두지 않는다")
    void anApplicationThatNamesBootsUserKeepsBootsChain() {
        StandardEnvironment environment = environment(
                new MapPropertySource("application", Map.of("spring.security.user.name", "ops")));

        assertThat(outcome(environment).isMatch()).isFalse();
    }

    @Test
    @DisplayName("환경 변수로 Boot 계정 비밀번호를 정해도 앱 사용자로 본다")
    void aPasswordFromTheEnvironmentIsTheApplicationsToo() {
        StandardEnvironment environment = environment();
        environment.getPropertySources().addLast(new SystemEnvironmentPropertySource("environment",
                Map.of("SPRING_SECURITY_USER_PASSWORD", "secret")));

        assertThat(outcome(environment).isMatch()).isFalse();
    }

    @Test
    @DisplayName("Contexa가 Boot 계정에 붙이는 이름만 있으면 앱 사용자가 아니어서 격리 체인을 둔다")
    void theNameContexaGivesBootsUserIsNotTheApplications() {
        StandardEnvironment environment = environment(new MapPropertySource(BootDefaultUserPropertySource.SOURCE_NAME,
                Map.of("spring.security.user.name", "user")));
        ConfigurationPropertySources.attach(environment);

        assertThat(outcome(environment).isMatch()).isTrue();
    }

    @Test
    @DisplayName("체인도 사용자도 설정도 없으면 격리 체인을 둔다")
    void anApplicationWithoutSecurityOfItsOwnIsKeptApart() {
        assertThat(outcome(environment()).isMatch()).isTrue();
    }
}
