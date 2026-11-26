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

import org.springframework.security.web.access.intercept.AuthorizationFilter;
import io.contexa.contexaidentity.security.core.adapter.auth.ContexaSignInRealm;
import io.contexa.contexaidentity.security.core.config.AuthenticationFlowConfig;
import io.contexa.contexaidentity.security.core.config.PlatformConfig;
import io.contexa.contexaidentity.security.core.context.FlowContext;
import io.contexa.contexaidentity.security.core.context.PlatformContext;
import io.contexa.contexaidentity.security.core.mfa.util.MfaFlowTypeUtils;
import io.contexa.contexaidentity.security.filter.DefaultMfaPageGeneratingFilter;
import io.contexa.contexaidentity.security.zerotrust.ZeroTrustChallengeFilter;
import io.contexa.contexacommon.enums.StateType;
import io.contexa.contexacommon.properties.AuthContextProperties;
import io.contexa.contexaidentity.security.core.config.StateConfig;
import org.springframework.context.ApplicationContext;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;

import java.util.List;

public class ZeroTrustChallengeConfigurer implements SecurityConfigurer {

    private static final int ORDER = 50;

    private final ZeroTrustChallengeFilter zeroTrustChallengeFilter;

    public ZeroTrustChallengeConfigurer(ZeroTrustChallengeFilter zeroTrustChallengeFilter) {
        this.zeroTrustChallengeFilter = zeroTrustChallengeFilter;
    }

    /**
     * Tells the filter, for each realm, whether a challenged user can step up in an MFA flow (R-13 of
     * docs/agent/운영모드-정상화-구현계획.md). The application's users step up in a flow of the application's; the flow of
     * Contexa's administrators ({@link ContexaSignInRealm#ADMIN_FLOW_NAME}) joins the application's flows too, and it is
     * the console's procedure only.
     */
    @Override
    public void init(PlatformContext ctx, PlatformConfig config) {
        if (zeroTrustChallengeFilter == null) {
            return;
        }
        List<AuthenticationFlowConfig> flows = config != null && config.getFlows() != null
                ? config.getFlows() : List.of();
        boolean applicationUsers = flows.stream()
                .anyMatch(flow -> MfaFlowTypeUtils.isMfaFlow(flow.getTypeName())
                        && !ContexaSignInRealm.isAdminFlow(flow));
        boolean console = flows.stream().anyMatch(ContexaSignInRealm::isAdminFlow);
        zeroTrustChallengeFilter.setChallengeProcedures(applicationUsers, console);
    }

    @Override
    public void configure(FlowContext fc) throws Exception {
        if (zeroTrustChallengeFilter == null) {
            return;
        }

        AuthenticationFlowConfig flowConfig = fc.flow();

        // A CHALLENGE restricts the user in every session, so every chain enforces it, not only the MFA flow chains;
        // a chain without the MFA page filter places it right before authorization.
        if (!MfaFlowTypeUtils.isMfaFlow(flowConfig.getTypeName())) {
            if (isTokenState(fc)) {
                fc.http().addFilterBefore(zeroTrustChallengeFilter, BasicAuthenticationFilter.class);
            } else {
                fc.http().addFilterBefore(zeroTrustChallengeFilter, AuthorizationFilter.class);
            }
            return;
        }

        if (isTokenState(fc)) {
            // A token state authenticates the request in the bearer token filter, which runs after the MFA
            // page filter; right after it (and after the OAuth2 zero trust filter) the challenge can see
            // the user, still before access control and authorization.
            fc.http().addFilterBefore(zeroTrustChallengeFilter, BasicAuthenticationFilter.class);
        } else {
            fc.http().addFilterAfter(zeroTrustChallengeFilter, DefaultMfaPageGeneratingFilter.class);
        }
    }

    private static boolean isTokenState(FlowContext fc) {
        StateConfig stateConfig = fc.flow().getStateConfig();
        if (stateConfig != null && stateConfig.stateType() != null) {
            return stateConfig.stateType() != StateType.SESSION;
        }
        ApplicationContext applicationContext = fc.http().getSharedObject(ApplicationContext.class);
        if (applicationContext == null) {
            return false;
        }
        return applicationContext.getBean(AuthContextProperties.class).getStateType() != StateType.SESSION;
    }

    @Override
    public int getOrder() {
        return ORDER;
    }
}
