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
package io.contexa.contexaidentity.security.core.bootstrap.configurer;

import io.contexa.contexaidentity.security.core.config.PlatformConfig;
import io.contexa.contexaidentity.security.core.context.FlowContext;
import io.contexa.contexaidentity.security.core.context.PlatformContext;
import io.contexa.contexaidentity.security.filter.MfaPendingAccessControlFilter;
import org.springframework.security.web.authentication.logout.LogoutFilter;

/**
 * Registers {@link MfaPendingAccessControlFilter} in every flow chain, not only in MFA flow chains,
 * because the HTTP session of an incomplete MFA login is shared by all chains.
 *
 * <p>The filter is placed directly after {@link LogoutFilter}: the SecurityContext has already been
 * loaded, header writing, CORS, CSRF and logout (whatever its URL) have already been applied, and every
 * endpoint or authentication filter that acts on the current principal before the AuthorizationFilter,
 * such as the authorization server endpoints, the Zero Trust challenge and access control filters and
 * the AuthorizationFilter itself, runs after the MFA completion check. The MFA continuation filters are
 * placed before {@link LogoutFilter} and keep handling MFA requests first.</p>
 */
public class MfaPendingAccessControlConfigurer implements SecurityConfigurer {

    private static final int ORDER = 44;

    private final MfaPendingAccessControlFilter mfaPendingAccessControlFilter;

    public MfaPendingAccessControlConfigurer(MfaPendingAccessControlFilter mfaPendingAccessControlFilter) {
        this.mfaPendingAccessControlFilter = mfaPendingAccessControlFilter;
    }

    @Override
    public void init(PlatformContext ctx, PlatformConfig config) {
    }

    @Override
    public void configure(FlowContext fc) throws Exception {
        if (mfaPendingAccessControlFilter == null) {
            return;
        }

        fc.http().addFilterAfter(mfaPendingAccessControlFilter, LogoutFilter.class);
    }

    @Override
    public int getOrder() {
        return ORDER;
    }
}
