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

import io.contexa.contexacommon.security.LoginPolicyHandler;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;

/**
 * Stands before the provider of the HOST_OWNED console and holds its sign-ins to the address throttle of the login
 * policy. It decides nothing about the credentials: it refuses a blocked address, and any other sign-in goes on.
 */
final class ConsoleAddressGate implements AuthenticationProvider {

    private final ObjectProvider<LoginPolicyHandler> policy;

    ConsoleAddressGate(ObjectProvider<LoginPolicyHandler> policy) {
        this.policy = policy;
    }

    @Override
    public Authentication authenticate(Authentication authentication) {
        LoginPolicyHandler handler = policy.getIfAvailable();
        if (handler != null) {
            handler.checkSignInAddress(authentication.getName());
        }
        return null;
    }

    @Override
    public boolean supports(Class<?> authentication) {
        return UsernamePasswordAuthenticationToken.class.isAssignableFrom(authentication);
    }
}
