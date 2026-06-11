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
package io.contexa.contexaidentity.security.core.dsl.configurer;

import io.contexa.contexaidentity.security.core.asep.dsl.MfaAsepAttributes;
import io.contexa.contexaidentity.security.core.config.AuthenticationFlowConfig;
import io.contexa.contexaidentity.security.core.dsl.common.SecurityConfigurerDsl;
import io.contexa.contexaidentity.security.core.mfa.policy.MfaPolicyProvider;
import io.contexa.contexaidentity.security.handler.PlatformAuthenticationFailureHandler;
import io.contexa.contexaidentity.security.handler.PlatformAuthenticationSuccessHandler;
import org.springframework.security.config.Customizer;

public interface MfaDslConfigurer extends SecurityConfigurerDsl {
    MfaDslConfigurer name(String flowName);
    MfaDslConfigurer urlPrefix(String urlPrefix);
    MfaDslConfigurer order(int order);
    MfaDslConfigurer form(Customizer<FormConfigurerConfigurer> formConfigurer); 
    MfaDslConfigurer rest(Customizer<RestConfigurerConfigurer> restConfigurer); 
    MfaDslConfigurer ott(Customizer<OttConfigurerConfigurer> ottConfigurer);   
    MfaDslConfigurer passkey(Customizer<PasskeyConfigurerConfigurer> passkeyConfigurer); 
    MfaDslConfigurer mfaFailureHandler(PlatformAuthenticationFailureHandler failureHandler);
    MfaDslConfigurer mfaSuccessHandler(PlatformAuthenticationSuccessHandler successHandler);
    MfaDslConfigurer policyProvider(MfaPolicyProvider policyProvider);
    MfaDslConfigurer defaultDeviceTrustEnabled(boolean enable);
    MfaDslConfigurer requiredFactors(int count);
    AuthenticationFlowConfig build(); 
    MfaDslConfigurer asep(Customizer<MfaAsepAttributes> mfaAsepAttributesCustomizer);
    MfaDslConfigurer primaryAuthentication(Customizer<PrimaryAuthDslConfigurer> primaryAuthConfig);
    MfaDslConfigurer mfaPage(Customizer<MfaPageConfigurer> mfaPageConfigurer);
}