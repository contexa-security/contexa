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

import io.contexa.contexaidentity.security.core.config.PlatformConfig;
import io.contexa.contexaidentity.security.core.context.FlowContext;
import io.contexa.contexaidentity.security.core.context.FlowContextFactory;
import io.contexa.contexaidentity.security.core.context.PlatformContext;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

import java.util.List;

@Slf4j
@RequiredArgsConstructor
public class SecurityPlatformInitializer implements SecurityPlatform {
    private final PlatformContext context;
    private final PlatformConfig config;
    private final SecurityFilterChainRegistrar registrar;
    private final FlowContextFactory flowContextFactory;
    private final SecurityConfigurerOrchestrator securityConfigurerOrchestrator;

    @Override
    public void prepareGlobal(PlatformConfig config, List<?> features) {
    }

    @Override
    public void initialize() throws Exception {

        List<FlowContext> flows = flowContextFactory.createAndSortFlows(config, context);
        context.flowContexts(flows);
        config.setPlatformContext(context);

        if (flows.isEmpty() && !this.config.getFlows().isEmpty()) {
            log.warn("No FlowContexts were created by FlowContextFactory, but PlatformConfig has flows defined. Check FlowContextFactory logic and HttpSecurity provider.");
        }

        securityConfigurerOrchestrator.applyConfigurations(flows, context, config);
        registrar.registerSecurityFilterChains(flows, context.applicationContext());
    }
}

