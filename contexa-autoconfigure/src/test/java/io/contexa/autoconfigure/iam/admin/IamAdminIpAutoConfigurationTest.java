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
package io.contexa.autoconfigure.iam.admin;

import io.contexa.contexacommon.operating.ContexaOperatingProfile;
import io.contexa.contexacommon.security.bridge.BridgeProperties;
import io.contexa.contexaiam.admin.web.common.CsvExportService;
import io.contexa.contexaiam.repository.IpAccessRuleRepository;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.springframework.boot.autoconfigure.AutoConfigurations;
import org.springframework.boot.autoconfigure.security.SecurityProperties;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;
import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.context.annotation.Configuration;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;

/**
 * M4 of docs/agent/운영모드-정상화-구현계획.md (R-12): the address control covers the paths its setting names, every path
 * unless the operator narrows them, whatever the mode and the ownership; it runs ahead of the Spring Security filter
 * chain, so an address its rules shut out reaches no chain, the application's or Contexa's.
 */
@DisplayName("주소 통제의 적용 경로와 순서(M4)")
class IamAdminIpAutoConfigurationTest {

    private final ApplicationContextRunner runner = new ApplicationContextRunner()
            .withConfiguration(AutoConfigurations.of(IamAdminIpAutoConfiguration.class))
            .withUserConfiguration(SettingsOfTheApplication.class)
            .withBean(IpAccessRuleRepository.class, () -> mock(IpAccessRuleRepository.class))
            .withBean(CsvExportService.class, () -> mock(CsvExportService.class));

    @ParameterizedTest(name = "{0} + {1}")
    @CsvSource({"SANDBOX, ''", "SANDBOX, CONTEXA_OWNED", "FULL, HOST_OWNED", "FULL, ''"})
    @DisplayName("설정이 없으면 네 조합 모두 모든 경로에 걸린다")
    void everyPathInEveryWayOfRunning(String mode, String ownership) {
        runner.withPropertyValues(ContexaOperatingProfile.PROP_MODE + "=" + mode,
                        ContexaOperatingProfile.PROP_OWNERSHIP + "=" + ownership)
                .run(context -> assertThat(registration(context.getBean("contexaIpAccessFilter")).getUrlPatterns())
                        .containsExactly("/*"));
    }

    @Test
    @DisplayName("운영자가 정한 경로에만 걸린다")
    void thePathsTheOperatorNames() {
        runner.withPropertyValues("contexa.iam.admin.ip-access.url-patterns=/contexa/*,/partner/*")
                .run(context -> assertThat(registration(context.getBean("contexaIpAccessFilter")).getUrlPatterns())
                        .containsExactly("/contexa/*", "/partner/*"));
    }

    @Test
    @DisplayName("Spring Security 필터 체인보다 앞에서 돈다")
    void aheadOfTheSpringSecurityFilterChain() {
        runner.run(context -> assertThat(registration(context.getBean("contexaIpAccessFilter")).getOrder())
                .isLessThan(SecurityProperties.DEFAULT_FILTER_ORDER - 1));
    }

    @Test
    @DisplayName("앱이 Spring Security 필터 순서를 옮기면 그 앞을 따라간다")
    void followsAMovedSpringSecurityFilterChain() {
        runner.withPropertyValues("spring.security.filter.order=10")
                .run(context -> assertThat(registration(context.getBean("contexaIpAccessFilter")).getOrder())
                        .isLessThan(10 - 1));
    }

    private static FilterRegistrationBean<?> registration(Object bean) {
        assertThat(bean).isInstanceOf(FilterRegistrationBean.class);
        return (FilterRegistrationBean<?>) bean;
    }

    /** What an application with Spring Security and Contexa binds: Boot's security settings and Contexa's bridge settings. */
    @Configuration(proxyBeanMethods = false)
    @EnableConfigurationProperties({SecurityProperties.class, BridgeProperties.class})
    static class SettingsOfTheApplication {
    }
}
