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
package io.contexa.autoconfigure.identity;

import io.contexa.contexacommon.properties.AuthContextProperties;
import io.contexa.contexacore.infra.session.MfaSessionRepository;
import io.contexa.contexacore.security.session.SessionIdResolver;
import io.contexa.contexacore.security.zerotrust.ZeroTrustSecurityService;
import io.contexa.contexaidentity.security.core.config.PlatformConfig;
import io.contexa.contexaidentity.security.handler.logout.CompositeLogoutHandler;
import io.contexa.contexaidentity.security.handler.logout.LogoutStrategy;
import io.contexa.contexaidentity.security.handler.logout.MfaFlowLogoutStrategy;
import io.contexa.contexaidentity.security.handler.logout.SessionLogoutStrategy;
import io.contexa.contexaidentity.security.handler.logout.ZeroTrustLogoutStrategy;
import io.contexa.contexaidentity.security.statemachine.core.service.MfaStateMachineService;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.context.annotation.Bean;
import org.springframework.security.web.csrf.HttpSessionCsrfTokenRepository;

import java.util.ArrayList;
import java.util.List;

/**
 * The sign-out of Contexa's flows on session state where Contexa's OAuth2 plane is not there (an application without the
 * library of Spring's authorization server): the strategies of the MFA flow, the session and Zero Trust, without the tokens.
 * It is also the forced sign-out service, which ends a user's sessions. Where the OAuth2 plane is there its handler, which ends the tokens as well, stands in this one's place: this configuration comes after it.
 */
@AutoConfiguration(after = IdentityOAuth2AutoConfiguration.class)
@ConditionalOnBean(PlatformConfig.class)
public class IdentitySessionLogoutAutoConfiguration {

    @Bean("contexaCompositeLogoutHandler")
    @ConditionalOnMissingBean(name = "contexaCompositeLogoutHandler")
    public CompositeLogoutHandler sessionCompositeLogoutHandler(
            AuthContextProperties authContextProperties,
            ObjectProvider<ZeroTrustSecurityService> zeroTrustSecurityServiceProvider,
            SessionIdResolver sessionIdResolver,
            ObjectProvider<MfaSessionRepository> mfaSessionRepository,
            ObjectProvider<MfaStateMachineService> mfaStateMachineService) {
        ZeroTrustSecurityService zeroTrustService = zeroTrustSecurityServiceProvider.getIfAvailable();
        List<LogoutStrategy> strategies = new ArrayList<>();
        strategies.add(new MfaFlowLogoutStrategy(mfaSessionRepository, mfaStateMachineService));
        strategies.add(new SessionLogoutStrategy(new HttpSessionCsrfTokenRepository(), authContextProperties));
        if (zeroTrustService != null) {
            strategies.add(new ZeroTrustLogoutStrategy(zeroTrustService, sessionIdResolver));
        }
        return new CompositeLogoutHandler(strategies, null, zeroTrustService, null);
    }
}
