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
import org.springframework.http.HttpMethod;
import org.springframework.security.web.DefaultSecurityFilterChain;
import org.springframework.security.web.authentication.AbstractAuthenticationProcessingFilter;
import org.springframework.security.web.servlet.util.matcher.PathPatternRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.util.StringUtils;

import java.util.List;

/**
 * Base class for filter chain customizers that apply per-flow URLs after http.build().
 */
public abstract class AbstractFilterCustomizer {

    protected RequestMatcher createPostMatcher(String url) {
        return PathPatternRequestMatcher.withDefaults().matcher(HttpMethod.POST, url);
    }

    protected RequestMatcher createGetMatcher(String url) {
        return PathPatternRequestMatcher.withDefaults().matcher(HttpMethod.GET, url);
    }

    protected void setMatcherIfPresent(AbstractAuthenticationProcessingFilter filter, String url) {
        if (StringUtils.hasText(url)) {
            filter.setRequiresAuthenticationRequestMatcher(createPostMatcher(url));
        }
    }

    protected List<Filter> getFilters(DefaultSecurityFilterChain builtChain) {
        return builtChain.getFilters();
    }

    /**
     * Apply per-flow customizations to the filter chain.
     */
    public abstract void customize(DefaultSecurityFilterChain builtChain, AuthUrlProvider flowUrlProvider,
                                    Object context);
}
