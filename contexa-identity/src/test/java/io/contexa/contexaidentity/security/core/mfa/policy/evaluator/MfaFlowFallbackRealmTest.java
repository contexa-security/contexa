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
package io.contexa.contexaidentity.security.core.mfa.policy.evaluator;

import io.contexa.contexacommon.security.ConsoleSession;
import io.contexa.contexaidentity.security.core.adapter.auth.ContexaSignInRealm;
import io.contexa.contexaidentity.security.core.config.AuthenticationFlowConfig;
import io.contexa.contexaidentity.security.core.config.PlatformConfig;
import io.contexa.contexaidentity.security.core.mfa.context.FactorContext;
import io.contexa.contexaidentity.security.core.mfa.model.MfaDecision;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.context.ApplicationContext;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/**
 * R-13 of docs/agent/운영모드-정상화-구현계획.md: the flow a policy reads when the context names no flow of the configuration
 * is the first MFA flow, and the flow of Contexa's administrators, which joins an application's own flows, is that first
 * one for the console's requests only.
 */
@DisplayName("MFA 정책의 '첫 MFA 흐름' 대체는 콘솔 요청이 아니면 관리 흐름을 고르지 않는다(R-13)")
class MfaFlowFallbackRealmTest {

    private final AuthenticationFlowConfig form = flow("form_flow");
    private final AuthenticationFlowConfig admin = flow(ContexaSignInRealm.adminFlowTypeName());
    private final Probe probe = new Probe(PlatformConfig.builder().addFlow(form).addFlow(admin).build());

    @AfterEach
    void clear() {
        RequestContextHolder.resetRequestAttributes();
    }

    @Test
    @DisplayName("콘솔 요청이 아니면 이름 없는 흐름의 대체가 관리 흐름이 되지 않는다")
    void outsideTheConsoleTheFallbackIsNotTheAdministratorsFlow() {
        RequestContextHolder.setRequestAttributes(new ServletRequestAttributes(new MockHttpServletRequest("GET", "/h/reports")));

        assertThat(probe.flowOf("mfa")).isNull();
    }

    @Test
    @DisplayName("콘솔 요청이면 대체는 지금처럼 관리 흐름이다")
    void onTheConsoleTheFallbackIsTheAdministratorsFlow() {
        MockHttpServletRequest console = new MockHttpServletRequest("GET", "/contexa/admin/users");
        ConsoleSession.mark(console);
        RequestContextHolder.setRequestAttributes(new ServletRequestAttributes(console));

        assertThat(probe.flowOf("mfa")).isSameAs(admin);
    }

    @Test
    @DisplayName("흐름 이름이 관리 흐름이면 대체가 아니라 그 흐름이다")
    void aFlowNamedIsThatFlow() {
        assertThat(probe.flowOf(ContexaSignInRealm.adminFlowTypeName())).isSameAs(admin);
    }

    private static AuthenticationFlowConfig flow(String typeName) {
        AuthenticationFlowConfig flow = mock(AuthenticationFlowConfig.class);
        when(flow.getTypeName()).thenReturn(typeName);
        return flow;
    }

    /** The lookup every policy evaluator shares, over one configuration of flows. */
    static final class Probe extends AbstractMfaPolicyEvaluator {

        Probe(PlatformConfig config) {
            super(null, context(config));
        }

        private static ApplicationContext context(PlatformConfig config) {
            ApplicationContext context = mock(ApplicationContext.class);
            when(context.getBean(PlatformConfig.class)).thenReturn(config);
            return context;
        }

        AuthenticationFlowConfig flowOf(String flowTypeName) {
            return findMfaFlowConfigFromContext(flowTypeName);
        }

        @Override
        protected MfaDecision doEvaluatePolicy(FactorContext context) {
            return MfaDecision.builder().required(true).build();
        }

        @Override
        public String getName() {
            return "probe";
        }

        @Override
        public int getPriority() {
            return 0;
        }
    }
}
