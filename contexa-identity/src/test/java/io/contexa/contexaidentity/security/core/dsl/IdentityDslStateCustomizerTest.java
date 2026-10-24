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
package io.contexa.contexaidentity.security.core.dsl;

import io.contexa.contexacommon.enums.OAuth2ServerMode;
import io.contexa.contexacommon.enums.StateType;
import io.contexa.contexacommon.properties.AuthContextProperties;
import io.contexa.contexaidentity.security.core.adapter.state.oauth2.OAuth2RequestScope;
import io.contexa.contexaidentity.security.core.adapter.state.oauth2.OAuth2StateConfigurer;
import io.contexa.contexaidentity.security.core.adapter.state.session.SessionStateConfigurer;
import io.contexa.contexaidentity.security.core.config.AuthenticationFlowConfig;
import io.contexa.contexaidentity.security.core.config.AuthenticationStepConfig;
import io.contexa.contexaidentity.security.core.config.PlatformConfig;
import io.contexa.contexaidentity.security.core.config.StateConfig;
import io.contexa.contexaidentity.security.service.AuthUrlProvider;
import org.junit.jupiter.api.Test;
import org.springframework.context.ApplicationContext;
import org.springframework.security.config.Customizer;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/**
 * A1-10: the customizer given to {@code .oauth2(customizer)} or {@code .session(customizer)} reaches the flow, so the
 * state adapter applies it; it was dropped before.
 */
class IdentityDslStateCustomizerTest {

    @Test
    void oauth2CustomizerIsKeptOnTheFlowAndSetsTheRequestScope() throws Exception {
        Customizer<OAuth2StateConfigurer> tokenScope = oauth2 -> oauth2.requestScope(OAuth2RequestScope.TOKEN_REQUESTS);

        PlatformConfig config = registry()
                .rest(rest -> rest.loginProcessingUrl("/api/agent/login").order(150)).oauth2(tokenScope)
                .build();

        AuthenticationFlowConfig flow = config.getFlows().get(0);
        assertThat(flow.getStateConfig().stateType()).isEqualTo(StateType.OAUTH2);
        assertThat(flow.stateCustomizer(OAuth2StateConfigurer.class)).isSameAs(tokenScope);
        OAuth2StateConfigurer configurer = new OAuth2StateConfigurer(OAuth2ServerMode.COMBINED);
        flow.stateCustomizer(OAuth2StateConfigurer.class).customize(configurer);
        assertThat(configurer.getRequestScope()).isEqualTo(OAuth2RequestScope.TOKEN_REQUESTS);
    }

    @Test
    void sessionCustomizerIsKeptOnItsOwnFlow() throws Exception {
        Customizer<SessionStateConfigurer> sessionCustomizer = session -> { };
        Customizer<OAuth2StateConfigurer> oauth2Customizer = oauth2 -> { };

        PlatformConfig config = registry()
                .form(form -> form.loginPage("/login")).session(sessionCustomizer)
                .rest(rest -> rest.loginProcessingUrl("/api/agent/login")).oauth2(oauth2Customizer)
                .build();

        List<AuthenticationFlowConfig> flows = config.getFlows();
        assertThat(flows).hasSize(2);
        assertThat(flows.get(0).stateCustomizer(SessionStateConfigurer.class)).isSameAs(sessionCustomizer);
        assertThat(flows.get(1).stateCustomizer(OAuth2StateConfigurer.class)).isSameAs(oauth2Customizer);
    }

    @Test
    void customizerSurvivesARenameAndDefaultsWithoutOne() {
        AuthenticationFlowConfig flow = AuthenticationFlowConfig.builder("rest_flow")
                .stepConfigs(List.of(new AuthenticationStepConfig("rest_flow", "REST", 200, false)))
                .build();
        Customizer<OAuth2StateConfigurer> customizer = oauth2 -> { };

        assertThat(flow.stateCustomizer(OAuth2StateConfigurer.class)).isNotNull();
        AuthenticationFlowConfig withState = flow.withStateConfig(new StateConfig("oauth2", StateType.OAUTH2), customizer);
        assertThat(withState.withTypeName("rest_flow_2").stateCustomizer(OAuth2StateConfigurer.class)).isSameAs(customizer);
        assertThat(withState.withStateConfig(new StateConfig("oauth2", StateType.OAUTH2))
                .stateCustomizer(OAuth2StateConfigurer.class)).isSameAs(customizer);
    }

    private static IdentityDslRegistry<?> registry() {
        ApplicationContext context = mock(ApplicationContext.class);
        when(context.getBean(AuthUrlProvider.class)).thenReturn(new AuthUrlProvider(new AuthContextProperties()));
        when(context.getBean(AuthContextProperties.class)).thenReturn(new AuthContextProperties());
        return new IdentityDslRegistry<>(context);
    }
}
