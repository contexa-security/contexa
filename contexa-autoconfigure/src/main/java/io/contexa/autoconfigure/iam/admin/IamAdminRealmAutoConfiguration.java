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
package io.contexa.autoconfigure.iam.admin;

import io.contexa.contexacommon.operating.ContexaOperatingProfile;
import io.contexa.contexacommon.operating.OperatingBehaviour;
import io.contexa.contexacommon.security.HeldBean;
import io.contexa.contexacommon.security.LoginPolicyHandler;
import io.contexa.contexaidentity.security.core.adapter.auth.ContexaAdminRealm;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnClass;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnWebApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.core.env.Environment;
import org.springframework.security.authentication.AuthenticationEventPublisher;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.web.SecurityFilterChain;

/**
 * What the console of Contexa's administrators needs where they sign in apart from the application's users, on the chain
 * of their own flow ({@link ContexaAdminRealm}, R-13 of docs/agent/운영모드-정상화-구현계획.md): the sign-in policy of their
 * sign-in (an address throttle ahead of the password, and the events the policy counts failed attempts and locks from),
 * held so that Spring's global authentication manager never finds them, and the sign-out the console header posts to.
 */
@AutoConfiguration
@ConditionalOnWebApplication(type = ConditionalOnWebApplication.Type.SERVLET)
@ConditionalOnClass(SecurityFilterChain.class)
public class IamAdminRealmAutoConfiguration {

    /** The bean name the console's own chain had before it became the flow of Contexa's administrators. */
    public static final String ADMIN_CHAIN = "contexaAdminConsoleSecurityFilterChain";

    /** The console's sign-out; the application's {@code /logout} stays the application's. */
    public static final String LOGOUT_URL = ContexaAdminRealm.LOGOUT_URL;

    @Bean(name = "contexaAdminSignInAddressGate")
    @ConditionalOnMissingBean(name = ContexaAdminRealm.ADDRESS_GATE_BEAN)
    public HeldBean<AuthenticationProvider> contexaAdminSignInAddressGate(ObjectProvider<LoginPolicyHandler> loginPolicy) {
        return new HeldBean<>(new ConsoleAddressGate(loginPolicy));
    }

    @Bean(name = "contexaAdminSignInEvents")
    @ConditionalOnMissingBean(name = ContexaAdminRealm.SIGN_IN_EVENTS_BEAN)
    public HeldBean<AuthenticationEventPublisher> contexaAdminSignInEvents(ObjectProvider<LoginPolicyHandler> loginPolicy) {
        return new HeldBean<>(new ConsoleLoginPolicyEvents(loginPolicy));
    }

    @Bean(name = "contexaConsoleLogoutModelAdvice")
    @ConditionalOnMissingBean
    public ConsoleLogoutModelAdvice consoleLogoutModelAdvice(Environment environment) {
        boolean apart = OperatingBehaviour.of(ContexaOperatingProfile.resolve(environment)).adminRealmOnItsOwnChain();
        return new ConsoleLogoutModelAdvice(apart ? ContexaAdminRealm.LOGOUT_URL : "/logout");
    }
}
