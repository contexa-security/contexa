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
package io.contexa.contexaiam.security.core;

import io.contexa.contexacommon.security.LoginPolicyHandler;
import io.contexa.contexacommon.security.bridge.OAuth2AuthenticationSupport;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.event.EventListener;
import org.springframework.security.authentication.event.AbstractAuthenticationEvent;
import org.springframework.security.authentication.event.AbstractAuthenticationFailureEvent;
import org.springframework.security.authentication.event.AuthenticationSuccessEvent;

import java.util.function.BooleanSupplier;

/**
 * Records login outcomes from Spring Security's authentication events.
 *
 * <p>Why an event listener instead of editing each {@code AuthenticationSuccessHandler} /
 * {@code AuthenticationFailureHandler}: events fire for <em>every</em> authentication path
 * (form, JSON, OAuth2, REST, Passkey, Bridge). Existing handlers continue to call
 * {@link LoginPolicyHandler} directly — the {@link io.contexa.contexaiam.security.core.LoginPolicyService}
 * uses an idempotent guard so a request that goes through both paths records exactly once.</p>
 *
 * <p>Locked / disabled / expired accounts produce specific failure events (e.g.
 * {@code AuthenticationFailureLockedEvent}); we record them all uniformly so per-IP
 * throttling reflects the real attack surface.</p>
 *
 * <p>The events of the application's own sign-ins arrive here as well. Only a sign-in of an account of Contexa's goes to
 * the account policy; a failed sign-in of the application's own users is kept for the decisions and counted against its
 * address, and touches no account of Contexa's of the same name (the fourth solution of
 * docs/agent/운영모드-정상화-구현계획.md).</p>
 */
@Slf4j
public class LoginAttemptEventListener {

    private final LoginPolicyHandler loginPolicyHandler;
    private final BooleanSupplier contexaAccounts;

    /** Every sign-in it hears is one of Contexa's accounts. */
    public LoginAttemptEventListener(LoginPolicyHandler loginPolicyHandler) {
        this(loginPolicyHandler, () -> true);
    }

    /**
     * @param contexaAccounts whether the sign-in of the current request is that of an account of Contexa's, asked at each
     *                        event
     */
    public LoginAttemptEventListener(LoginPolicyHandler loginPolicyHandler, BooleanSupplier contexaAccounts) {
        this.loginPolicyHandler = loginPolicyHandler;
        this.contexaAccounts = contexaAccounts;
    }

    @EventListener
    public void onSuccess(AuthenticationSuccessEvent event) {
        if (OAuth2AuthenticationSupport.isTokenTraffic(event.getAuthentication())) return;
        String username = safeName(event);
        if (username == null || !contexaAccounts.getAsBoolean()) return;
        loginPolicyHandler.onLoginSuccess(username, currentIp(), "EVENT");
    }

    @EventListener
    public void onFailure(AbstractAuthenticationFailureEvent event) {
        if (OAuth2AuthenticationSupport.isTokenTraffic(event.getAuthentication())) return;
        String username = safeName(event);
        String type = event.getException() == null
                ? "UNKNOWN"
                : event.getException().getClass().getSimpleName();
        if (contexaAccounts.getAsBoolean()) {
            loginPolicyHandler.onLoginFailure(username, currentIp(), type, "EVENT");
        } else {
            loginPolicyHandler.onHostSignInFailure(username, currentIp(), type, "EVENT");
        }
    }

    private static String safeName(AbstractAuthenticationEvent e) {
        try {
            return e.getAuthentication() != null ? e.getAuthentication().getName() : null;
        } catch (Exception ex) {
            return null;
        }
    }

    private static String currentIp() {
        try {
            return LoginPolicyService.currentAddress();
        } catch (Exception ex) {
            return null;
        }
    }
}
