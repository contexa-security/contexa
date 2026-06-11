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
package io.contexa.contexaidentity.security.core.bootstrap;

import io.contexa.contexaidentity.security.core.bootstrap.configurer.AuthConfigurerAdapter;
import io.contexa.contexaidentity.security.core.bootstrap.configurer.SecurityConfigurer;
import io.contexa.contexaidentity.security.core.bootstrap.configurer.StateConfigurerAdapter;
import io.contexa.contexaidentity.security.core.config.AuthenticationFlowConfig;
import io.contexa.contexaidentity.security.core.config.PlatformConfig;
import io.contexa.contexaidentity.security.core.context.PlatformContext;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.ApplicationContext;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Objects;

@Slf4j
public final class DefaultSecurityConfigurerProvider implements SecurityConfigurerProvider {

    private final List<SecurityConfigurer> collectedBaseConfigurers;
    private final AdapterRegistry adapterRegistry;

    public DefaultSecurityConfigurerProvider(
            List<SecurityConfigurer> baseConfigurers,
            AdapterRegistry adapterRegistry) {
        this.collectedBaseConfigurers = (baseConfigurers != null) ? new ArrayList<>(baseConfigurers) : new ArrayList<>();
        this.adapterRegistry = Objects.requireNonNull(adapterRegistry, "FeatureRegistry cannot be null");
    }

    @Override
    public List<SecurityConfigurer> getGlobalConfigurers(PlatformContext platformContext, PlatformConfig platformConfig) {

        return List.copyOf(this.collectedBaseConfigurers);
    }

    @Override
    public List<SecurityConfigurer> getFlowSpecificConfigurers(
            PlatformContext platformContext,
            PlatformConfig platformConfig,
            HttpSecurity httpForScope) {
        Objects.requireNonNull(httpForScope, "HttpSecurity (httpForScope) cannot be null for getFlowSpecificConfigurers");

        List<SecurityConfigurer> flowSpecificAdapters = new ArrayList<>();
        AuthenticationFlowConfig currentFlow = httpForScope.getSharedObject(AuthenticationFlowConfig.class);

        if (currentFlow == null) {
            log.warn("DefaultSecurityConfigurerProvider: AuthenticationFlowConfig not found in HttpSecurity sharedObjects for hash {}. " +
                            "Cannot determine flow-specific features. No feature adapters will be added for this scope.",
                    httpForScope.hashCode());
            return Collections.emptyList();
        }

        List<AuthenticationFlowConfig> singleFlowList = Collections.singletonList(currentFlow);

        adapterRegistry.getAuthAdaptersFor(singleFlowList)
                .forEach(authAdapter -> {
                    flowSpecificAdapters.add(new AuthConfigurerAdapter(authAdapter));
                });

        adapterRegistry.getStateAdaptersFor(singleFlowList)
                .forEach(stateAdapter -> {
                    flowSpecificAdapters.add(new StateConfigurerAdapter(stateAdapter, platformContext));
                });

        return List.copyOf(flowSpecificAdapters);
    }
}
