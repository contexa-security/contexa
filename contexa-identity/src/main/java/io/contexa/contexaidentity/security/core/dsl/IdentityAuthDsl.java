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

import io.contexa.contexaidentity.security.core.config.PlatformConfig;
import io.contexa.contexaidentity.security.core.dsl.common.SafeHttpCustomizer;
import io.contexa.contexaidentity.security.core.dsl.configurer.*;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;

public interface IdentityAuthDsl {

    IdentityAuthDsl global(SafeHttpCustomizer<HttpSecurity> customizer);

    IdentityStateDsl form(Customizer<FormConfigurerConfigurer> customizer) throws Exception; 

    IdentityStateDsl rest(Customizer<RestConfigurerConfigurer> customizer) throws Exception;

    IdentityStateDsl ott(Customizer<OttConfigurerConfigurer> customizer) throws Exception;

    IdentityStateDsl passkey(Customizer<PasskeyConfigurerConfigurer> customizer) throws Exception;

    IdentityStateDsl mfa(Customizer<MfaDslConfigurer> customizer) throws Exception;

    PlatformConfig build();
}

