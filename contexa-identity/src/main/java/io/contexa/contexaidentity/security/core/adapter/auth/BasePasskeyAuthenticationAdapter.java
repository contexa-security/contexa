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

import io.contexa.contexaidentity.security.core.context.PlatformContext;
import io.contexa.contexaidentity.security.exception.DslConfigurationException;
import io.contexa.contexaidentity.security.webauthn.PasskeyLibrary;
import io.contexa.contexaidentity.security.zerotrust.stepup.ContexaPasskeyStores;
import org.springframework.context.ApplicationContext;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.webauthn.management.PublicKeyCredentialUserEntityRepository;
import org.springframework.security.web.webauthn.management.UserCredentialRepository;
import io.contexa.contexaidentity.security.core.config.AuthenticationFlowConfig;
import io.contexa.contexaidentity.security.core.dsl.option.PasskeyOptions;
import io.contexa.contexaidentity.security.handler.PlatformAuthenticationFailureHandler;
import io.contexa.contexaidentity.security.handler.PlatformAuthenticationSuccessHandler;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;

public abstract class BasePasskeyAuthenticationAdapter extends AbstractAuthenticationAdapter<PasskeyOptions> {

    @Override
    protected void configureHttpSecurity(HttpSecurity http, PasskeyOptions opts,
                                         AuthenticationFlowConfig currentFlow,
                                         PlatformAuthenticationSuccessHandler successHandler,
                                         PlatformAuthenticationFailureHandler failureHandler) throws Exception {
        if (!PasskeyLibrary.available(http.getSharedObject(PlatformContext.class).applicationContext().getClassLoader())) {
            // The DSL leaves the factor out without webauthn4j; a flow that still names it is refused with the reason.
            throw new DslConfigurationException("The passkey factor of flow [" + currentFlow.getTypeName()
                    + "] needs webauthn4j on the class path, and it is not there.");
        }

        // WebAuthn looks for the store as the only bean of its type, and the application may have several. Spring's passkey
        // provider takes the account the key names as it is: the store refuses a locked or disabled one.
        ApplicationContext context = http.getSharedObject(PlatformContext.class).applicationContext();
        http.setSharedObject(UserDetailsService.class, new AccountStateCheckingUserDetailsService(ContexaSignInRealm.store(http, context)));
        // Contexa's passkeys are held, out of reach of the application's webAuthn(): a flow of Contexa's accounts is handed them
        // as shared objects, which Spring's webAuthn() reads before it looks for beans.
        ContexaPasskeyStores stores = context.containsBean(ContexaPasskeyStores.BEAN_NAME)
                && context.getBean(ContexaPasskeyStores.BEAN_NAME) instanceof ContexaPasskeyStores held ? held : null;
        if (stores != null && ContexaSignInRealm.signsInContexaAccounts(http, context)) {
            http.setSharedObject(PublicKeyCredentialUserEntityRepository.class, stores.userEntities());
            http.setSharedObject(UserCredentialRepository.class, stores.userCredentials());
        }
        http.webAuthn(web -> {
            web.rpName(opts.getRpName())
                    .rpId(opts.getRpId())
                    .allowedOrigins(opts.getAllowedOrigins());
        });
    }
}
