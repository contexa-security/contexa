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
package io.contexa.contexaidentity.security.core.adapter.auth;

import io.contexa.contexacommon.operating.ContexaOperatingProfile;
import io.contexa.contexacommon.operating.OperatingBehaviour;
import io.contexa.contexacore.security.ContexaUserStore;
import io.contexa.contexaidentity.security.core.config.AuthenticationFlowConfig;
import io.contexa.contexaidentity.security.core.mfa.util.MfaFlowTypeUtils;
import org.springframework.context.ApplicationContext;
import org.springframework.core.env.Environment;
import org.springframework.lang.Nullable;
import org.springframework.security.config.annotation.web.HttpSecurityBuilder;
import org.springframework.security.core.userdetails.UserDetailsService;

/**
 * Whose accounts a flow of Contexa's signs in. The flow of Contexa's administrators ({@link #ADMIN_FLOW_NAME}) always signs
 * Contexa's own accounts in, from Contexa's own store. Any other flow signs the application's users in: from the
 * application's store where its components win (HOST_OWNED), from Contexa's own where they do not (CONTEXA_OWNED).
 */
public final class ContexaSignInRealm {

    /** The name of the flow Contexa's administrators sign in with, apart from the application's users. */
    public static final String ADMIN_FLOW_NAME = "contexa-admin";

    private ContexaSignInRealm() {
    }

    /** The type name the flow of Contexa's administrators gets from its name. */
    public static String adminFlowTypeName() {
        return MfaFlowTypeUtils.generateTypeName(ADMIN_FLOW_NAME);
    }

    public static boolean isAdminFlow(@Nullable AuthenticationFlowConfig flow) {
        return flow != null && adminFlowTypeName().equalsIgnoreCase(flow.getTypeName());
    }

    /**
     * Whether the flow of this chain signs Contexa's own accounts in. A context without an environment (one outside a running
     * application) declares no way of running Contexa, and is read as Contexa's own sign-in, as the sign-in stores were read
     * before the ways of running were told apart.
     */
    public static boolean signsInContexaAccounts(@Nullable HttpSecurityBuilder<?> http, ApplicationContext context) {
        return signsInContexaAccounts(http != null ? http.getSharedObject(AuthenticationFlowConfig.class) : null, context);
    }

    /** The same answer for a flow whose chain is already built. */
    public static boolean signsInContexaAccounts(@Nullable AuthenticationFlowConfig flow, ApplicationContext context) {
        if (isAdminFlow(flow)) {
            return true;
        }
        Environment environment = context.getEnvironment();
        return environment == null || !OperatingBehaviour.of(ContexaOperatingProfile.resolve(environment)).hostComponentsWin();
    }

    /** The user store the flow of this chain signs its users in from. */
    public static UserDetailsService store(@Nullable HttpSecurityBuilder<?> http, ApplicationContext context) {
        return signsInContexaAccounts(http, context) ? ContexaUserStore.forSignIn(context) : ContexaUserStore.of(context);
    }
}
