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

import io.contexa.contexaidentity.security.core.asep.dsl.OttAsepAttributes;
import io.contexa.contexaidentity.security.core.dsl.option.OttOptions;
import org.springframework.security.authentication.ott.OneTimeTokenService;
import org.springframework.security.web.authentication.ott.OneTimeTokenGenerationSuccessHandler;

public interface OttConfigurerConfigurer extends AuthenticationFactorConfigurer<OttOptions, OttAsepAttributes, OttConfigurerConfigurer> {

    OttConfigurerConfigurer defaultSubmitPageUrl(String url);
    OttConfigurerConfigurer tokenGeneratingUrl(String url);
    OttConfigurerConfigurer showDefaultSubmitPage(boolean show);
    OttConfigurerConfigurer tokenService(OneTimeTokenService service);
    OttConfigurerConfigurer tokenGenerationSuccessHandler(OneTimeTokenGenerationSuccessHandler handler);
}

