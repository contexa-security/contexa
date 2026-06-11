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

import io.contexa.contexaidentity.security.filter.DefaultMfaPageGeneratingFilter;
import io.contexa.contexaidentity.security.service.AuthUrlProvider;
import jakarta.servlet.Filter;
import org.springframework.security.web.DefaultSecurityFilterChain;

/**
 * Injects per-flow AuthUrlProvider into DefaultMfaPageGeneratingFilter.
 * This ensures MFA page generation uses flow-specific URLs with urlPrefix applied.
 */
public class MfaPageFilterCustomizer extends AbstractFilterCustomizer {

    @Override
    public void customize(DefaultSecurityFilterChain builtChain, AuthUrlProvider flowUrlProvider, Object context) {
        for (Filter filter : getFilters(builtChain)) {
            if (filter instanceof DefaultMfaPageGeneratingFilter pageFilter) {
                pageFilter.setAuthUrlProvider(flowUrlProvider);
                return;
            }
        }
    }
}
