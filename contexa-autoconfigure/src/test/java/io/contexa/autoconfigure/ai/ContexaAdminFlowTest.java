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

import io.contexa.contexaiam.security.xacml.pep.CustomDynamicAuthorizationManager;
import io.contexa.contexaidentity.security.core.adapter.auth.ContexaAdminRealm;
import io.contexa.contexaidentity.security.core.adapter.auth.ContexaSignInRealm;
import io.contexa.contexaidentity.security.core.config.AuthenticationFlowConfig;
import io.contexa.contexaidentity.security.core.config.PlatformConfig;
import io.contexa.contexaidentity.security.core.dsl.IdentityDslRegistry;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.context.annotation.AnnotationConfigApplicationContext;
import org.springframework.core.PriorityOrdered;
import org.springframework.mock.env.MockEnvironment;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;

/**
 * R-13 of docs/agent/운영모드-정상화-구현계획.md: the flow of Contexa's administrators is part of every configuration of
 * flows wherever they sign in apart from the application's users, the application's own included, and is declared once.
 */
@DisplayName("Contexa 관리 흐름은 앱이 둔 흐름 설정에도 하나만 들어간다(R-13)")
class ContexaAdminFlowTest {

    private final AnnotationConfigApplicationContext context = new AnnotationConfigApplicationContext();

    @AfterEach
    void close() {
        context.close();
    }

    @Test
    @DisplayName("FULL + HOST_OWNED: 앱 흐름 설정 뒤에 관리 흐름을 더하고 앱의 흐름과 전역 설정은 그대로 둔다")
    void theAdministratorsFlowJoinsTheApplicationsOwnConfiguration() throws Exception {
        start("FULL", "HOST_OWNED");
        PlatformConfig application = applicationConfiguration();

        PlatformConfig joined = postProcessed(application);

        assertThat(typeNames(joined)).containsExactly("form_flow", ContexaSignInRealm.adminFlowTypeName());
        assertThat(joined.getFlows().get(0)).isSameAs(application.getFlows().get(0));
        assertThat(joined.getGlobalCustomizer()).isSameAs(application.getGlobalCustomizer());
        AuthenticationFlowConfig admin = joined.getFlows().get(1);
        assertThat(admin.getUrlPrefix()).isEqualTo(ContexaAdminRealm.URL_PREFIX);
        assertThat(admin.getOrder()).isEqualTo(ContexaAdminRealm.FLOW_ORDER);
    }

    @Test
    @DisplayName("FULL + CONTEXA_OWNED: 관리자와 앱 사용자가 하나이므로 앱 흐름 설정에 아무것도 더하지 않는다")
    void nothingJoinsWhereTheAdministratorsAndTheUsersAreOne() throws Exception {
        start("FULL", "CONTEXA_OWNED");
        PlatformConfig application = applicationConfiguration();

        assertThat(postProcessed(application)).isSameAs(application);
    }

    @Test
    @DisplayName("이미 관리 흐름을 가진 설정은 그대로 두어 관리 흐름이 둘이 되지 않는다")
    void aConfigurationWithTheFlowKeepsItOnce() throws Exception {
        start("SANDBOX", "HOST_OWNED");
        IdentityDslRegistry<HttpSecurity> registry = new IdentityDslRegistry<>(context);
        ContexaAdminFlow.declare(registry);
        PlatformConfig withTheFlow = registry.build();

        assertThat(postProcessed(withTheFlow)).isSameAs(withTheFlow);
    }

    @Test
    @DisplayName("기본 흐름 설정은 지금처럼 관리 흐름을 하나 가지고, 후처리가 다시 더하지 않는다")
    void theDefaultConfigurationHasTheFlowOnce() throws Exception {
        start("FULL", "HOST_OWNED");
        PlatformConfig defaults = new AiSecurityConfiguration(context.getEnvironment())
                .platformDslConfig(context, mock(CustomDynamicAuthorizationManager.class));

        PlatformConfig processed = postProcessed(defaults);

        assertThat(processed).isSameAs(defaults);
        assertThat(typeNames(processed)).containsExactly("mfa", ContexaSignInRealm.adminFlowTypeName());
    }

    /** Spring orders a post-processor by the type its factory method declares, before the post-processor is made. */
    @Test
    @DisplayName("후처리기는 먼저 등록되는 후처리기 묶음(PriorityOrdered)으로 선언되어 늦게 등록되어 놓치는 흐름 설정이 없다")
    void thePostProcessorIsDeclaredWithTheFirstOnes() throws Exception {
        Class<?> declared = AiSecurityConfiguration.class.getMethod("contexaAdminFlowPostProcessor").getReturnType();

        assertThat(PriorityOrdered.class).isAssignableFrom(declared);
    }

    private void start(String mode, String ownership) {
        context.setEnvironment(new MockEnvironment()
                .withProperty("contexa.ai.security.mode", mode)
                .withProperty("contexa.bridge.ownership", ownership));
        context.register(ContexaAdminFlowBeans.class);
        context.refresh();
    }

    private PlatformConfig applicationConfiguration() throws Exception {
        return new IdentityDslRegistry<HttpSecurity>(context)
                .global(http -> http.authorizeHttpRequests(requests -> requests.anyRequest().authenticated()))
                .form(form -> form.defaultSuccessUrl("/signed-in"))
                .session(Customizer.withDefaults())
                .build();
    }

    private PlatformConfig postProcessed(PlatformConfig config) {
        ContexaAdminFlow.PostProcessor postProcessor = AiSecurityConfiguration.contexaAdminFlowPostProcessor();
        postProcessor.setApplicationContext(context);
        return (PlatformConfig) postProcessor.postProcessAfterInitialization(config, "applicationPlatform");
    }

    private static List<String> typeNames(PlatformConfig config) {
        return config.getFlows().stream().map(AuthenticationFlowConfig::getTypeName).toList();
    }
}
