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
package io.contexa.contexaidentity.security.core.bootstrap.configurer;

import io.contexa.contexacommon.enums.StateType;
import io.contexa.contexacommon.security.bridge.web.BridgeResolutionFilter;
import io.contexa.contexaidentity.security.core.config.AuthenticationFlowConfig;
import io.contexa.contexaidentity.security.core.config.PlatformConfig;
import io.contexa.contexaidentity.security.core.config.StateConfig;
import io.contexa.contexaidentity.security.core.context.FlowContext;
import io.contexa.contexaidentity.security.core.context.PlatformContext;
import org.junit.jupiter.api.Test;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.oauth2.server.resource.web.authentication.BearerTokenAuthenticationFilter;
import org.springframework.security.web.context.SecurityContextHolderFilter;

import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

class BridgeResolutionConfigurerTest {

    @Test
    void configureShouldRegisterBridgeResolutionFilterAfterSecurityContextHolderFilter() throws Exception {
        BridgeResolutionFilter bridgeResolutionFilter = mock(BridgeResolutionFilter.class);
        BridgeResolutionConfigurer configurer = new BridgeResolutionConfigurer(bridgeResolutionFilter);
        AuthenticationFlowConfig flowConfig = mock(AuthenticationFlowConfig.class);
        HttpSecurity httpSecurity = mock(HttpSecurity.class);
        PlatformContext platformContext = mock(PlatformContext.class);
        PlatformConfig platformConfig = PlatformConfig.builder().build();
        when(flowConfig.getTypeName()).thenReturn("form");
        when(flowConfig.getStateConfig()).thenReturn(new StateConfig("session", StateType.SESSION));

        FlowContext flowContext = new FlowContext(flowConfig, httpSecurity, platformContext, platformConfig);

        configurer.configure(flowContext);

        verify(httpSecurity).addFilterAfter(bridgeResolutionFilter, SecurityContextHolderFilter.class);
    }

    @Test
    void configureShouldRegisterBridgeResolutionFilterAfterBearerTokenFilterOnTheTokenState() throws Exception {
        BridgeResolutionFilter bridgeResolutionFilter = mock(BridgeResolutionFilter.class);
        BridgeResolutionConfigurer configurer = new BridgeResolutionConfigurer(bridgeResolutionFilter);
        AuthenticationFlowConfig flowConfig = mock(AuthenticationFlowConfig.class);
        HttpSecurity httpSecurity = mock(HttpSecurity.class);
        PlatformContext platformContext = mock(PlatformContext.class);
        PlatformConfig platformConfig = PlatformConfig.builder().build();
        when(flowConfig.getTypeName()).thenReturn("rest");
        when(flowConfig.getStateConfig()).thenReturn(new StateConfig("oauth2", StateType.OAUTH2));
        FlowContext flowContext = new FlowContext(flowConfig, httpSecurity, platformContext, platformConfig);

        configurer.configure(flowContext);

        // A token state authenticates in the bearer token filter; the bridge absorbs that authentication after it.
        verify(httpSecurity).addFilterAfter(bridgeResolutionFilter, BearerTokenAuthenticationFilter.class);
    }
}
