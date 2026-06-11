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
package io.contexa.contexaidentity.security.core.bootstrap.customizer;

import io.contexa.contexaidentity.security.service.AuthUrlProvider;
import jakarta.servlet.Filter;
import org.springframework.security.web.DefaultSecurityFilterChain;
import org.springframework.security.web.authentication.AbstractAuthenticationProcessingFilter;
import org.springframework.security.web.authentication.ott.GenerateOneTimeTokenFilter;
import org.springframework.util.StringUtils;

/**
 * Applies per-flow URL prefix to OTT (One-Time Token) filters.
 * Targets: OneTimeTokenAuthenticationFilter, GenerateOneTimeTokenFilter
 */
public class OttFilterCustomizer extends AbstractFilterCustomizer {

    @Override
    public void customize(DefaultSecurityFilterChain builtChain, AuthUrlProvider flowUrlProvider, Object context) {
        String loginProcessingUrl = flowUrlProvider.getOttLoginProcessing();
        String tokenGeneratingUrl = flowUrlProvider.getOttCodeGeneration();

        for (Filter filter : getFilters(builtChain)) {

            if (filter instanceof AbstractAuthenticationProcessingFilter authFilter && isOttAuth(filter)) {
                setMatcherIfPresent(authFilter, loginProcessingUrl);
            }

            if (filter instanceof GenerateOneTimeTokenFilter genFilter && StringUtils.hasText(tokenGeneratingUrl)) {
                genFilter.setRequestMatcher(createPostMatcher(tokenGeneratingUrl));
            }
        }
    }

    private boolean isOttAuth(Filter filter) {
        String name = filter.getClass().getSimpleName();
        return name.contains("OneTimeToken") && name.contains("Authentication");
    }
}
