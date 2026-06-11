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

import io.contexa.contexaidentity.security.filter.MfaFormAuthenticationFilter;
import io.contexa.contexaidentity.security.filter.MfaRestAuthenticationFilter;
import io.contexa.contexaidentity.security.service.AuthUrlProvider;
import jakarta.servlet.Filter;
import org.springframework.security.web.DefaultSecurityFilterChain;
import org.springframework.util.StringUtils;

/**
 * Applies per-flow URL prefix to MFA primary authentication filters.
 * Targets: MfaFormAuthenticationFilter, MfaRestAuthenticationFilter
 */
public class PrimaryAuthFilterCustomizer extends AbstractFilterCustomizer {

    @Override
    public void customize(DefaultSecurityFilterChain builtChain, AuthUrlProvider flowUrlProvider, Object context) {
        String formUrl = flowUrlProvider.getPrimaryFormLoginProcessing();
        String restUrl = flowUrlProvider.getPrimaryRestLoginProcessing();

        for (Filter filter : getFilters(builtChain)) {
            if (filter instanceof MfaFormAuthenticationFilter formFilter && StringUtils.hasText(formUrl)) {
                formFilter.setRequestMatcher(createPostMatcher(formUrl));
            }

            if (filter instanceof MfaRestAuthenticationFilter restFilter && StringUtils.hasText(restUrl)) {
                restFilter.setRequestMatcher(createPostMatcher(restUrl));
            }
        }
    }
}
