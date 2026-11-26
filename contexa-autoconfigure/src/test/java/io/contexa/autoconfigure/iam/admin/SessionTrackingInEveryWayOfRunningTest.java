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
import io.contexa.contexaiam.admin.web.auth.filter.ActiveSessionEndListener;
import io.contexa.contexaiam.admin.web.auth.filter.SessionTrackingFilter;
import io.contexa.contexaiam.admin.web.auth.service.ActiveSessionCleanupScheduler;
import io.contexa.contexaiam.admin.web.auth.service.SessionManagementService;
import io.contexa.contexaiam.repository.ActiveSessionRepository;
import jakarta.servlet.http.HttpSessionEvent;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.springframework.boot.autoconfigure.security.SecurityProperties;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;
import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.boot.web.servlet.ServletListenerRegistrationBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.mock.web.MockFilterChain;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.mock.web.MockHttpSession;
import org.springframework.security.authentication.TestingAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.context.SecurityContextImpl;

import java.util.Collections;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;

/**
 * R-8 of docs/agent/운영모드-정상화-구현계획.md: Contexa tracks the sessions of whoever is signed in, in every way of running
 * Contexa. The tracking observes a session's id only and keeps what it needs on Contexa's side: the application's session
 * carries nothing of Contexa's.
 */
@DisplayName("세션 추적은 네 조합 모두에 있고 앱 세션에 쓰지 않는다(R-8)")
class SessionTrackingInEveryWayOfRunningTest {

    private static final String SESSION_ID = "7A2C4E6F8091B3D5F7092A4C6E8F0B1D";

    private final ApplicationContextRunner runner = new ApplicationContextRunner()
            .withUserConfiguration(Collaborators.class, IamAdminSessionTrackingConfiguration.class);

    @AfterEach
    void clear() {
        SecurityContextHolder.clearContext();
    }

    @ParameterizedTest(name = "{0} + {1}")
    @CsvSource({"SANDBOX, HOST_OWNED", "SANDBOX, CONTEXA_OWNED", "FULL, HOST_OWNED", "FULL, CONTEXA_OWNED"})
    @DisplayName("어느 조합이든 추적 필터·세션 끝 리스너·정리 스케줄러가 있다")
    void theTrackingIsThereInEveryWayOfRunning(String mode, String ownership) {
        runner.withPropertyValues(ContexaOperatingProfile.PROP_MODE + "=" + mode, ContexaOperatingProfile.PROP_OWNERSHIP + "=" + ownership)
                .run(context -> {
                    assertThat(context).hasNotFailed();
                    assertThat(context.getBeansOfType(FilterRegistrationBean.class).values())
                            .anyMatch(registration -> registration.getFilter() instanceof SessionTrackingFilter);
                    assertThat(context).hasBean("contexaActiveSessionEndListener");
                    assertThat(context).hasSingleBean(ActiveSessionCleanupScheduler.class);
                });
    }

    @ParameterizedTest(name = "spring.security.filter.order={0}")
    @CsvSource({"-100", "300"})
    @DisplayName("추적 필터는 앱이 정한 보안 필터 순서가 무엇이든 그 뒤에 선다")
    void theTrackingFilterStandsBehindTheSecurityFilterChainWhateverItsOrder(int securityFilterOrder) {
        runner.withPropertyValues(ContexaOperatingProfile.PROP_MODE + "=SANDBOX", ContexaOperatingProfile.PROP_OWNERSHIP + "=HOST_OWNED")
                .withBean(SecurityProperties.class, () -> {
                    SecurityProperties properties = new SecurityProperties();
                    properties.getFilter().setOrder(securityFilterOrder);
                    return properties;
                })
                .run(context -> {
                    FilterRegistrationBean<?> tracking = context.getBeansOfType(FilterRegistrationBean.class).values().stream()
                            .filter(registration -> registration.getFilter() instanceof SessionTrackingFilter)
                            .findFirst()
                            .orElseThrow();
                    assertThat(tracking.getOrder()).isGreaterThan(securityFilterOrder);
                });
    }

    @ParameterizedTest(name = "{0} + {1}")
    @CsvSource({"SANDBOX, HOST_OWNED", "SANDBOX, CONTEXA_OWNED", "FULL, HOST_OWNED", "FULL, CONTEXA_OWNED"})
    @DisplayName("추적한 세션이 끝나면 끝을 기록하고, 앱 세션에는 Contexa의 값이 남지 않는다")
    @SuppressWarnings("unchecked")
    void aTrackedSessionIsEndedAtItsEndAndTheApplicationsSessionCarriesNothingOfContexas(String mode, String ownership) {
        runner.withPropertyValues(ContexaOperatingProfile.PROP_MODE + "=" + mode, ContexaOperatingProfile.PROP_OWNERSHIP + "=" + ownership)
                .run(context -> {
                    assertThat(context).hasNotFailed();
                    SessionTrackingFilter filter = (SessionTrackingFilter) context.getBeansOfType(FilterRegistrationBean.class).values()
                            .stream()
                            .map(FilterRegistrationBean::getFilter)
                            .filter(SessionTrackingFilter.class::isInstance)
                            .findFirst()
                            .orElseThrow();
                    ActiveSessionEndListener listener = ((ServletListenerRegistrationBean<ActiveSessionEndListener>)
                            context.getBean("contexaActiveSessionEndListener")).getListener();
                    SessionManagementService sessions = context.getBean(SessionManagementService.class);
                    MockHttpSession session = new MockHttpSession(null, SESSION_ID);
                    MockHttpServletRequest request = new MockHttpServletRequest("GET", "/orders");
                    request.setSession(session);
                    SecurityContextHolder.setContext(new SecurityContextImpl(new TestingAuthenticationToken("alice", "x", "ROLE_USER")));

                    filter.doFilter(request, new MockHttpServletResponse(), new MockFilterChain());

                    verify(sessions).trackSession(anyString(), eq("alice"), eq("alice"), anyString(), any());
                    assertThat(Collections.list(session.getAttributeNames()))
                            .as("the application's session carries nothing of Contexa's").isEmpty();

                    listener.sessionDestroyed(new HttpSessionEvent(session));

                    verify(sessions).markExpired(SESSION_ID);
                });
    }

    @Configuration(proxyBeanMethods = false)
    static class Collaborators {

        @Bean
        SessionManagementService contexaSessionManagementService() {
            return mock(SessionManagementService.class);
        }

        @Bean
        ActiveSessionRepository activeSessionRepository() {
            return mock(ActiveSessionRepository.class);
        }
    }
}
