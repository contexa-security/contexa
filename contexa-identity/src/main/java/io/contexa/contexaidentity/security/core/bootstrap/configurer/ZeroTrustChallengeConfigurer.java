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

import io.contexa.contexaidentity.security.core.config.AuthenticationFlowConfig;
import io.contexa.contexaidentity.security.core.config.PlatformConfig;
import io.contexa.contexaidentity.security.core.context.FlowContext;
import io.contexa.contexaidentity.security.core.context.PlatformContext;
import io.contexa.contexaidentity.security.core.mfa.util.MfaFlowTypeUtils;
import io.contexa.contexaidentity.security.filter.DefaultMfaPageGeneratingFilter;
import io.contexa.contexaidentity.security.zerotrust.ZeroTrustChallengeFilter;
import lombok.extern.slf4j.Slf4j;

@Slf4j
public class ZeroTrustChallengeConfigurer implements SecurityConfigurer {

    private static final int ORDER = 50;

    private final ZeroTrustChallengeFilter zeroTrustChallengeFilter;

    public ZeroTrustChallengeConfigurer(ZeroTrustChallengeFilter zeroTrustChallengeFilter) {
        this.zeroTrustChallengeFilter = zeroTrustChallengeFilter;
    }

    @Override
    public void init(PlatformContext ctx, PlatformConfig config) {
        log.debug("ZeroTrustChallengeConfigurer initialized");
    }

    @Override
    public void configure(FlowContext fc) throws Exception {
        if (zeroTrustChallengeFilter == null) {
            log.warn("ZeroTrustChallengeFilter is not available, skipping registration");
            return;
        }

        AuthenticationFlowConfig flowConfig = fc.flow();

        if (!MfaFlowTypeUtils.isMfaFlow(flowConfig.getTypeName())) {
            log.debug("Skipping MfaPageGeneratingFilter for non-MFA flow: {}", flowConfig.getTypeName());
            return;
        }

        fc.http().addFilterAfter(zeroTrustChallengeFilter, DefaultMfaPageGeneratingFilter.class);
        log.debug("ZeroTrustChallengeFilter registered before LogoutFilter for flow: {}",
                fc.flow().getTypeName());
    }

    @Override
    public int getOrder() {
        return ORDER;
    }
}
