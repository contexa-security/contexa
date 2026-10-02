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
package io.contexa.contexaidentity.security.filter;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;
import io.contexa.contexacommon.enums.AuthType;
import io.contexa.contexacommon.properties.AuthContextProperties;
import io.contexa.contexaidentity.security.core.config.AuthenticationFlowConfig;
import io.contexa.contexaidentity.security.core.config.AuthenticationStepConfig;
import io.contexa.contexaidentity.security.core.dsl.option.AuthenticationProcessingOptions;
import io.contexa.contexaidentity.security.core.mfa.context.FactorContext;
import io.contexa.contexaidentity.security.core.mfa.options.PrimaryAuthenticationOptions;
import io.contexa.contexaidentity.security.core.mfa.util.MfaPasskeyRegistrationIntent;
import io.contexa.contexaidentity.security.core.mfa.util.MfaPendingSessionMarker;
import io.contexa.contexaidentity.security.filter.handler.MfaStateMachineIntegrator;
import io.contexa.contexaidentity.security.service.AuthUrlProvider;
import jakarta.servlet.http.HttpServletRequest;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.springframework.context.support.ResourceBundleMessageSource;
import org.springframework.mock.web.MockFilterChain;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.context.SecurityContextImpl;
import org.springframework.security.web.csrf.CsrfToken;
import org.springframework.security.web.csrf.DefaultCsrfToken;

class DefaultMfaPageGeneratingFilterTest {

    private static final String PASSKEY_PAGE = "/mfa/challenge/passkey";
    private static final String CSRF_TOKEN = "csrf-token-value";

    private final AuthContextProperties properties = new AuthContextProperties();
    private MfaStateMachineIntegrator stateMachineIntegrator;

    @BeforeEach
    void setUp() {
        stateMachineIntegrator = mock(MfaStateMachineIntegrator.class);
        SecurityContextHolder.setContext(new SecurityContextImpl(
                UsernamePasswordAuthenticationToken.authenticated("user", null, List.of())));
    }

    @AfterEach
    void tearDown() {
        SecurityContextHolder.clearContext();
    }

    @Nested
    @DisplayName("Passkey registration section of the MFA passkey page")
    class PasskeyRegistrationSection {

        @Test
        @DisplayName("Pending MFA with the OTT factor shows the notice and the button that continues with OTT")
        void pendingMfaWithOttShowsNoticeAndButton() throws Exception {
            DefaultMfaPageGeneratingFilter filter = filter(AuthType.MFA_OTT, AuthType.MFA_PASSKEY);
            factorContext(Set.of(AuthType.MFA_OTT, AuthType.MFA_PASSKEY), Set.of(AuthType.MFA_OTT, AuthType.MFA_PASSKEY));
            MockHttpServletRequest request = passkeyPageRequest(true);

            String html = render(filter, request);

            assertThat(html)
                    .contains("id=\"passkey-registration-notice\"")
                    .contains("For your security, a passkey can be registered only after your identity is verified.")
                    .contains("<form id=\"passkey-registration-form\" method=\"post\" action=\"/mfa/select-factor\"")
                    .contains("data-factor-type=\"MFA_OTT\"")
                    .contains("<input type=\"hidden\" name=\"factorType\" value=\"MFA_OTT\">")
                    .contains("<input type=\"hidden\" name=\""
                            + MfaPasskeyRegistrationIntent.REQUEST_PARAMETER + "\" value=\"true\">")
                    .contains("value=\"" + CSRF_TOKEN + "\"")
                    .contains("Continue with email verification and register a passkey")
                    .contains("mfa.selectFactor(registrationForm.dataset.factorType")
                    .doesNotContain("href=\"/webauthn/register\"")
                    .doesNotContain("{{");
        }

        @Test
        @DisplayName("Pending MFA of a passkey-only flow shows only the operator notice")
        void pendingMfaWithoutOttShowsOperatorNoticeOnly() throws Exception {
            DefaultMfaPageGeneratingFilter filter = filter(AuthType.MFA_PASSKEY);
            factorContext(Set.of(AuthType.MFA_PASSKEY), Set.of(AuthType.MFA_PASSKEY));
            MockHttpServletRequest request = passkeyPageRequest(true);

            String html = render(filter, request);

            assertThat(html)
                    .contains("id=\"passkey-registration-notice\"")
                    .contains("A passkey cannot be registered for the first time with the current sign-in configuration.")
                    .contains("Ask your system administrator to add email verification as an authentication method.")
                    .doesNotContain("id=\"passkey-registration-form\"")
                    .doesNotContain("Continue with email verification and register a passkey")
                    .doesNotContain("href=\"/webauthn/register\"");
        }

        @Test
        @DisplayName("Pending MFA whose OTT factor is already completed shows only the operator notice")
        void pendingMfaWithCompletedOttShowsOperatorNotice() throws Exception {
            DefaultMfaPageGeneratingFilter filter = filter(AuthType.MFA_OTT, AuthType.MFA_PASSKEY);
            factorContext(Set.of(AuthType.MFA_OTT, AuthType.MFA_PASSKEY), Set.of(AuthType.MFA_PASSKEY));
            MockHttpServletRequest request = passkeyPageRequest(true);

            String html = render(filter, request);

            assertThat(html)
                    .contains("A passkey cannot be registered for the first time")
                    .doesNotContain("id=\"passkey-registration-form\"");
        }

        @Test
        @DisplayName("Without a factor context the factors registered for the flow decide")
        void registeredFactorsDecideWithoutFactorContext() throws Exception {
            when(stateMachineIntegrator.loadFactorContextFromRequest(any(HttpServletRequest.class))).thenReturn(null);

            String withOtt = render(filter(AuthType.MFA_OTT, AuthType.MFA_PASSKEY), passkeyPageRequest(true));
            String passkeyOnly = render(filter(AuthType.MFA_PASSKEY), passkeyPageRequest(true));

            assertThat(withOtt).contains("id=\"passkey-registration-form\"");
            assertThat(passkeyOnly)
                    .contains("A passkey cannot be registered for the first time")
                    .doesNotContain("id=\"passkey-registration-form\"");
        }

        @Test
        @DisplayName("Without pending MFA the existing passkey registration link is kept")
        void withoutPendingMfaRegistrationLinkIsKept() throws Exception {
            DefaultMfaPageGeneratingFilter filter = filter(AuthType.MFA_OTT, AuthType.MFA_PASSKEY);
            factorContext(Set.of(AuthType.MFA_OTT, AuthType.MFA_PASSKEY), Set.of(AuthType.MFA_OTT, AuthType.MFA_PASSKEY));
            MockHttpServletRequest request = passkeyPageRequest(false);
            request.setContextPath("/app");
            request.setRequestURI("/app" + PASSKEY_PAGE);

            String html = render(filter, request);

            assertThat(html)
                    .contains("<a href=\"/app/webauthn/register\"")
                    .contains("Don&#x27;t have a registered Passkey?")
                    .contains("Register Passkey")
                    .doesNotContain("id=\"passkey-registration-notice\"")
                    .doesNotContain("id=\"passkey-registration-form\"");
        }

        @Test
        @DisplayName("Notice and button are localized with the Korean and English message bundles")
        void noticeIsLocalized() throws Exception {
            DefaultMfaPageGeneratingFilter filter = filter(AuthType.MFA_OTT, AuthType.MFA_PASSKEY);
            filter.setMessageSource(messageSource());
            factorContext(Set.of(AuthType.MFA_OTT, AuthType.MFA_PASSKEY), Set.of(AuthType.MFA_OTT, AuthType.MFA_PASSKEY));

            MockHttpServletRequest korean = passkeyPageRequest(true);
            korean.addPreferredLocale(Locale.KOREAN);
            MockHttpServletRequest english = passkeyPageRequest(true);
            english.addPreferredLocale(Locale.ENGLISH);

            assertThat(render(filter, korean))
                    .contains("아직 등록된 패스키가 없으신가요? 보안을 위해 패스키는 본인 확인 후 등록할 수 있습니다. "
                            + "이메일 인증 코드로 로그인을 완료하면 패스키 등록 화면으로 바로 이동합니다.")
                    .contains("이메일 인증으로 계속하고 패스키 등록하기");
            assertThat(render(filter, english))
                    .contains("Don&#x27;t have a registered passkey yet?")
                    .contains("Continue with email verification and register a passkey");

            DefaultMfaPageGeneratingFilter passkeyOnly = filter(AuthType.MFA_PASSKEY);
            passkeyOnly.setMessageSource(messageSource());
            factorContext(Set.of(AuthType.MFA_PASSKEY), Set.of(AuthType.MFA_PASSKEY));
            MockHttpServletRequest koreanPasskeyOnly = passkeyPageRequest(true);
            koreanPasskeyOnly.addPreferredLocale(Locale.KOREAN);
            assertThat(render(passkeyOnly, koreanPasskeyOnly))
                    .contains("현재 로그인 구성에서는 패스키를 처음 등록할 수 없습니다. "
                            + "시스템 관리자에게 이메일 인증 수단 추가를 요청하세요.");
        }
    }

    private DefaultMfaPageGeneratingFilter filter(AuthType... factors) {
        List<AuthenticationStepConfig> steps = new ArrayList<>();
        steps.add(new AuthenticationStepConfig("mfa", AuthType.MFA_FORM.name(), 0, true));
        Map<AuthType, AuthenticationProcessingOptions> factorOptions = new LinkedHashMap<>();
        int order = 1;
        for (AuthType factor : factors) {
            steps.add(new AuthenticationStepConfig("mfa", factor.name(), order++, false));
            factorOptions.put(factor, mock(AuthenticationProcessingOptions.class));
        }
        AuthenticationFlowConfig flowConfig = AuthenticationFlowConfig.builder("mfa")
                .primaryAuthenticationOptions(mock(PrimaryAuthenticationOptions.class))
                .stepConfigs(steps)
                .registeredFactorOptions(factorOptions)
                .build();
        return new DefaultMfaPageGeneratingFilter(flowConfig, stateMachineIntegrator, new AuthUrlProvider(properties),
                properties.getMfa(), "sessionStorage", true);
    }

    private void factorContext(Set<AuthType> availableFactors, Set<AuthType> remainingFactors) {
        FactorContext factorContext = mock(FactorContext.class);
        when(factorContext.getMfaSessionId()).thenReturn("mfa-session-id");
        when(factorContext.getUsername()).thenReturn("user");
        when(factorContext.getAvailableFactors()).thenReturn(availableFactors);
        when(factorContext.getRemainingFactors()).thenReturn(remainingFactors);
        when(stateMachineIntegrator.loadFactorContextFromRequest(any(HttpServletRequest.class))).thenReturn(factorContext);
    }

    private MockHttpServletRequest passkeyPageRequest(boolean mfaPending) {
        MockHttpServletRequest request = new MockHttpServletRequest("GET", PASSKEY_PAGE);
        request.setAttribute(CsrfToken.class.getName(),
                new DefaultCsrfToken("X-CSRF-TOKEN", "_csrf", CSRF_TOKEN));
        if (mfaPending) {
            MfaPendingSessionMarker.mark(request, "mfa");
        } else {
            request.getSession(true);
        }
        return request;
    }

    private String render(DefaultMfaPageGeneratingFilter filter, MockHttpServletRequest request) throws Exception {
        MockHttpServletResponse response = new MockHttpServletResponse();
        MockFilterChain chain = new MockFilterChain();

        filter.doFilter(request, response, chain);

        assertThat(chain.getRequest()).isNull();
        return response.getContentAsString();
    }

    private ResourceBundleMessageSource messageSource() {
        ResourceBundleMessageSource source = new ResourceBundleMessageSource();
        source.setBasenames("i18n/messages");
        source.setDefaultEncoding("UTF-8");
        source.setFallbackToSystemLocale(false);
        return source;
    }
}
