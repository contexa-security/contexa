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
package io.contexa.contexacommon.operating;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * R-17 of docs/agent/운영모드-정상화-구현계획.md: a bean Spring Boot would build from the application's settings is offered by
 * Contexa only where the application set nothing of the kind, whatever the spelling of the settings.
 */
@DisplayName("앱이 Boot 설정을 쓰면 Contexa는 그 종류의 빈을 내놓지 않는다(R-17)")
class ConditionalOnNoApplicationSettingTest {

    private final ApplicationContextRunner runner = new ApplicationContextRunner().withUserConfiguration(Offered.class);

    @Test
    @DisplayName("접두어 아래에 설정이 없으면 빈을 내놓는다")
    void withoutASettingTheBeanIsOffered() {
        runner.withPropertyValues("spring.security.oauth2.resourceserver.opaquetoken.introspection-uri=http://127.0.0.1/introspect")
                .run(context -> assertThat(context).hasBean("contexaOffered"));
    }

    @Test
    @DisplayName("접두어 아래에 설정이 하나라도 있으면 빈을 내놓지 않는다")
    void anySettingUnderThePrefixKeepsTheBeanBack() {
        runner.withPropertyValues("spring.security.oauth2.client.registration.host-idp.client-id=host")
                .run(context -> assertThat(context).doesNotHaveBean("contexaOffered"));
        runner.withPropertyValues("spring.security.oauth2.resourceserver.jwt.jwk-set-uri=http://127.0.0.1/jwks")
                .run(context -> assertThat(context).doesNotHaveBean("contexaOffered"));
    }

    @Configuration(proxyBeanMethods = false)
    static class Offered {

        @Bean
        @ConditionalOnNoApplicationSetting(prefix = {"spring.security.oauth2.client.registration",
                "spring.security.oauth2.resourceserver.jwt"})
        String contexaOffered() {
            return "offered";
        }
    }
}
