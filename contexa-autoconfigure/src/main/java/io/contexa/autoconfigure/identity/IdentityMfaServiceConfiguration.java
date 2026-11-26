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

import io.contexa.contexacommon.operating.ConditionalOnMode;
import io.contexa.contexacommon.security.bridge.SecurityMode;
import io.contexa.contexaidentity.controller.MfaConfigController;
import io.contexa.contexaidentity.security.filter.handler.MfaStateMachineIntegrator;
import io.contexa.contexaidentity.security.service.AuthUrlProvider;
import io.contexa.contexaidentity.security.service.MfaFlowUrlRegistry;
import io.contexa.contexaidentity.security.service.ott.MagicLinkHandler;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

/**
 * The MFA SDK's endpoint, in every way of running Contexa: its administrators sign in with MFA wherever they sign in. The
 * magic-link handler only where Contexa's main chain signs the application's users in (FULL).
 */
@Configuration(proxyBeanMethods = false)
public class IdentityMfaServiceConfiguration {

    // Only in mode FULL, where Contexa's main chain signs the users in: the one-time token login of an application that signs its
    // own users in (SANDBOX) takes its OneTimeTokenGenerationSuccessHandler by type, and does not start with two of them (with
    // none of its own it would take this one).
    @Bean(name = "contexaMagicLinkHandler")
    @ConditionalOnMode(SecurityMode.FULL)
    @ConditionalOnMissingBean
    public MagicLinkHandler magicLinkHandler() {
        return new MagicLinkHandler();
    }

    /** The MFA SDK's endpoint, outside Contexa's own path space ({@code /api/mfa/config}): in every way of running Contexa, for its MFA flows. */
    @Bean(name = "contexaMfaConfigController")
    @ConditionalOnMissingBean
    public MfaConfigController mfaConfigController(AuthUrlProvider contexaAuthUrlProvider,
                                                     MfaFlowUrlRegistry contexaMfaFlowUrlRegistry,
                                                     MfaStateMachineIntegrator stateMachineIntegrator) {
        return new MfaConfigController(contexaAuthUrlProvider, contexaMfaFlowUrlRegistry, stateMachineIntegrator);
    }
}
