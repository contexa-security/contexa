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
package io.contexa.contexaidentity.security.core.bootstrap.customizer;

import io.contexa.contexacommon.operating.ContexaOperatingProfile;
import io.contexa.contexaidentity.security.core.adapter.auth.ContexaSignInRealm;
import io.contexa.contexaidentity.security.core.config.AuthenticationFlowConfig;
import io.contexa.contexaidentity.security.filter.ContexaWebAuthnRegistrationPageFilter;
import io.contexa.contexaidentity.security.zerotrust.stepup.ContexaPasskeyStores;
import jakarta.servlet.Filter;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.context.support.StaticApplicationContext;
import org.springframework.mock.env.MockEnvironment;
import org.springframework.security.web.DefaultSecurityFilterChain;
import org.springframework.security.web.util.matcher.AnyRequestMatcher;
import org.springframework.security.web.webauthn.management.MapPublicKeyCredentialUserEntityRepository;
import org.springframework.security.web.webauthn.management.MapUserCredentialRepository;
import org.springframework.security.web.webauthn.management.PublicKeyCredentialUserEntityRepository;
import org.springframework.security.web.webauthn.management.UserCredentialRepository;
import org.springframework.security.web.webauthn.registration.DefaultWebAuthnRegistrationPageGeneratingFilter;
import org.springframework.test.util.ReflectionTestUtils;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/**
 * Contexa's registration page reads the passkeys the flow's {@code webAuthn()} was given: Contexa's held ones on a flow of
 * Contexa's accounts, whatever beans of those types the application has or lacks, and the only beans of their types on a
 * flow of the application's users.
 */
@DisplayName("패스키 등록 화면은 그 흐름이 받은 패스키 저장소를 쓴다")
class PasskeyFilterCustomizerRegistrationPageTest {

    private final PasskeyFilterCustomizer customizer = new PasskeyFilterCustomizer();
    private final ContexaPasskeyStores held = new ContexaPasskeyStores(new MapPublicKeyCredentialUserEntityRepository(),
            new MapUserCredentialRepository());

    private static AuthenticationFlowConfig flow(String typeName) {
        AuthenticationFlowConfig flow = mock(AuthenticationFlowConfig.class);
        when(flow.getTypeName()).thenReturn(typeName);
        return flow;
    }

    private static StaticApplicationContext context(String mode, String ownership) {
        StaticApplicationContext context = new StaticApplicationContext();
        context.setEnvironment(new MockEnvironment()
                .withProperty(ContexaOperatingProfile.PROP_MODE, mode)
                .withProperty(ContexaOperatingProfile.PROP_OWNERSHIP, ownership));
        return context;
    }

    private static DefaultSecurityFilterChain chainWithSpringsPage() {
        return new DefaultSecurityFilterChain(AnyRequestMatcher.INSTANCE, new DefaultWebAuthnRegistrationPageGeneratingFilter(
                new MapPublicKeyCredentialUserEntityRepository(), new MapUserCredentialRepository()));
    }

    private static Filter onlyFilter(DefaultSecurityFilterChain chain) {
        assertThat(chain.getFilters()).hasSize(1);
        return chain.getFilters().get(0);
    }

    @Test
    @DisplayName("SANDBOX 관리 흐름은 타입 빈이 없어도 Contexa가 보유한 저장소로 등록 화면을 바꾼다")
    void theAdministratorsFlowReadsContexasHeldPasskeys() {
        StaticApplicationContext context = context("SANDBOX", "HOST_OWNED");
        context.getBeanFactory().registerSingleton(ContexaPasskeyStores.BEAN_NAME, held);
        context.refresh();
        DefaultSecurityFilterChain chain = chainWithSpringsPage();

        customizer.replaceRegistrationPage(chain, flow(ContexaSignInRealm.adminFlowTypeName()), context);

        Filter page = onlyFilter(chain);
        assertThat(page).isInstanceOf(ContexaWebAuthnRegistrationPageFilter.class);
        assertThat(ReflectionTestUtils.getField(page, "userEntities")).isSameAs(held.userEntities());
        assertThat(ReflectionTestUtils.getField(page, "userCredentials")).isSameAs(held.userCredentials());
    }

    @Test
    @DisplayName("FULL + HOST_OWNED의 앱 흐름은 Contexa 보유 저장소가 아니라 앱의 타입 빈으로 등록 화면을 바꾼다")
    void anApplicationFlowWhereTheApplicationsComponentsWinReadsTheOnlyBeansOfTheirTypes() {
        StaticApplicationContext context = context("FULL", "HOST_OWNED");
        context.getBeanFactory().registerSingleton(ContexaPasskeyStores.BEAN_NAME, held);
        PublicKeyCredentialUserEntityRepository applicationsEntities = new MapPublicKeyCredentialUserEntityRepository();
        UserCredentialRepository applicationsCredentials = new MapUserCredentialRepository();
        context.getBeanFactory().registerSingleton("applicationsEntities", applicationsEntities);
        context.getBeanFactory().registerSingleton("applicationsCredentials", applicationsCredentials);
        context.refresh();
        DefaultSecurityFilterChain chain = chainWithSpringsPage();

        customizer.replaceRegistrationPage(chain, flow("mfa"), context);

        Filter page = onlyFilter(chain);
        assertThat(page).isInstanceOf(ContexaWebAuthnRegistrationPageFilter.class);
        assertThat(ReflectionTestUtils.getField(page, "userEntities")).isSameAs(applicationsEntities);
        assertThat(ReflectionTestUtils.getField(page, "userCredentials")).isSameAs(applicationsCredentials);
    }

    @Test
    @DisplayName("쓸 저장소가 없으면 Spring Security의 등록 화면을 그대로 둔다")
    void withoutPasskeysForTheFlowSpringsPageStays() {
        StaticApplicationContext context = context("FULL", "HOST_OWNED");
        context.refresh();
        DefaultSecurityFilterChain chain = chainWithSpringsPage();

        customizer.replaceRegistrationPage(chain, flow("mfa"), context);

        assertThat(onlyFilter(chain)).isInstanceOf(DefaultWebAuthnRegistrationPageGeneratingFilter.class);
    }
}
