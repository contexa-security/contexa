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
import io.contexa.contexacommon.properties.AuthContextProperties;
import io.contexa.contexacommon.security.bridge.web.BridgeResolutionFilter;
import io.contexa.contexaidentity.security.core.config.PlatformConfig;
import io.contexa.contexaidentity.security.core.config.StateConfig;
import io.contexa.contexaidentity.security.core.context.FlowContext;
import io.contexa.contexaidentity.security.core.context.PlatformContext;
import org.springframework.context.ApplicationContext;
import org.springframework.security.oauth2.server.resource.web.authentication.BearerTokenAuthenticationFilter;
import org.springframework.security.web.context.SecurityContextHolderFilter;

/**
 * Puts the bridge resolution filter into each flow's chain where the flow has established the authentication, since
 * the bridge absorbs that authentication: a session flow restores it in the security context holder filter, a token
 * (OAuth2) flow sets it in the bearer token filter, which comes later in the chain.
 */
public class BridgeResolutionConfigurer implements SecurityConfigurer {

    private static final int ORDER = SecurityConfigurer.HIGHEST_PRECEDENCE + 110;

    private final BridgeResolutionFilter bridgeResolutionFilter;

    public BridgeResolutionConfigurer(BridgeResolutionFilter bridgeResolutionFilter) {
        this.bridgeResolutionFilter = bridgeResolutionFilter;
    }

    @Override
    public void init(PlatformContext ctx, PlatformConfig config) {
    }

    @Override
    public void configure(FlowContext fc) throws Exception {
        if (bridgeResolutionFilter == null) {
            return;
        }
        if (isTokenState(fc)) {
            fc.http().addFilterAfter(bridgeResolutionFilter, BearerTokenAuthenticationFilter.class);
            return;
        }
        fc.http().addFilterAfter(bridgeResolutionFilter, SecurityContextHolderFilter.class);
    }

    /**
     * The flow's state as the authentication adapters decide it: the flow's own state, otherwise the configured state,
     * and the token state when the configuration cannot be read.
     */
    private static boolean isTokenState(FlowContext fc) {
        StateConfig stateConfig = fc.flow() != null ? fc.flow().getStateConfig() : null;
        if (stateConfig != null && stateConfig.stateType() != null) {
            return stateConfig.stateType() == StateType.OAUTH2;
        }
        ApplicationContext applicationContext = fc.context() != null ? fc.context().applicationContext() : null;
        AuthContextProperties properties = applicationContext != null
                ? applicationContext.getBeanProvider(AuthContextProperties.class).getIfAvailable()
                : null;
        return properties == null || properties.getStateType() == StateType.OAUTH2;
    }

    @Override
    public int getOrder() {
        return ORDER;
    }
}
