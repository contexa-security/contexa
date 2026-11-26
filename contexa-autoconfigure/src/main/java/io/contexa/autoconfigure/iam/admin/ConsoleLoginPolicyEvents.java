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
import io.contexa.contexaiam.security.core.LoginPolicyService;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.security.authentication.AuthenticationEventPublisher;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;

/**
 * Feeds Contexa's login policy (the count of failed sign-ins, the lock, the address throttle) from the sign-ins of
 * the flow of Contexa's administrators ({@code contexa-admin}, in every combination of mode and ownership but FULL with
 * CONTEXA_OWNED): the console chain, whose accounts are Contexa's, hands its outcomes to the policy itself. The policy's
 * listener of Spring Security's events hears every sign-in as well, in every way of running Contexa, and tells the
 * sign-ins of Contexa's accounts apart ({@code ContexaAccountRequests}), so that the application's own sign-ins never
 * count against Contexa's accounts.
 * <p>
 * The policy never makes a sign-in fail: whatever it throws is logged and the sign-in goes on as the credentials say.
 */
@Slf4j
final class ConsoleLoginPolicyEvents implements AuthenticationEventPublisher {

    private static final String SOURCE = "CONSOLE";

    private final ObjectProvider<LoginPolicyHandler> policy;

    ConsoleLoginPolicyEvents(ObjectProvider<LoginPolicyHandler> policy) {
        this.policy = policy;
    }

    @Override
    public void publishAuthenticationSuccess(Authentication authentication) {
        record(authentication, null);
    }

    @Override
    public void publishAuthenticationFailure(AuthenticationException exception, Authentication authentication) {
        record(authentication, exception);
    }

    private void record(Authentication authentication, AuthenticationException failure) {
        LoginPolicyHandler handler = policy.getIfAvailable();
        if (handler == null || authentication == null) {
            return;
        }
        try {
            String username = authentication.getName();
            if (failure == null) {
                handler.onLoginSuccess(username, LoginPolicyService.currentAddress(), SOURCE);
            } else {
                handler.onLoginFailure(username, LoginPolicyService.currentAddress(), failure.getClass().getSimpleName(), SOURCE);
            }
        } catch (RuntimeException e) {
            log.error("[Console] The login policy could not record a sign-in: {}", e.getMessage());
        } finally {
            // Cleared at the end of each request as well, by the clean-up filter every way of running Contexa registers.
            LoginPolicyService.clearRequestState();
        }
    }
}
