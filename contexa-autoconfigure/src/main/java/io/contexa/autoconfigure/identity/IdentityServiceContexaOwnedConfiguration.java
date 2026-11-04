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
package io.contexa.autoconfigure.identity;

import io.contexa.contexacommon.operating.ConditionalOnOwnership;
import io.contexa.contexacommon.security.bridge.SecurityOwnershipMode;
import io.contexa.contexaidentity.controller.MfaConfigController;
import io.contexa.contexaidentity.security.filter.handler.MfaStateMachineIntegrator;
import io.contexa.contexaidentity.security.service.AuthUrlProvider;
import io.contexa.contexaidentity.security.service.MfaFlowUrlRegistry;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

/** The MFA SDK's endpoint, only where Contexa owns the sign-in. */
@Configuration(proxyBeanMethods = false)
@ConditionalOnOwnership(SecurityOwnershipMode.CONTEXA_OWNED)
public class IdentityServiceContexaOwnedConfiguration {

    /** The MFA SDK's endpoint, outside Contexa's own path space ({@code /api/mfa/config}): only where Contexa owns the sign-in and its MFA flows. */
    @Bean(name = "contexaMfaConfigController")
    @ConditionalOnMissingBean
    public MfaConfigController mfaConfigController(AuthUrlProvider contexaAuthUrlProvider,
                                                     MfaFlowUrlRegistry contexaMfaFlowUrlRegistry,
                                                     MfaStateMachineIntegrator stateMachineIntegrator) {
        return new MfaConfigController(contexaAuthUrlProvider, contexaMfaFlowUrlRegistry, stateMachineIntegrator);
    }
}
