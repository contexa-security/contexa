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

import io.contexa.contexacommon.security.ClientIpResolver;
import io.contexa.contexacommon.security.LoginPolicyHandler;
import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.event.EventListener;
import org.springframework.security.authentication.event.AbstractAuthenticationEvent;
import org.springframework.security.authentication.event.AbstractAuthenticationFailureEvent;
import org.springframework.security.authentication.event.AuthenticationSuccessEvent;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;

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
 */
@Slf4j
@RequiredArgsConstructor
public class LoginAttemptEventListener {

    private final LoginPolicyHandler loginPolicyHandler;

    @EventListener
    public void onSuccess(AuthenticationSuccessEvent event) {
        String username = safeName(event);
        if (username == null) return;
        loginPolicyHandler.onLoginSuccess(username, currentIp(), "EVENT");
    }

    @EventListener
    public void onFailure(AbstractAuthenticationFailureEvent event) {
        String username = safeName(event);
        String type = event.getException() == null
                ? "UNKNOWN"
                : event.getException().getClass().getSimpleName();
        loginPolicyHandler.onLoginFailure(username, currentIp(), type, "EVENT");
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
            ServletRequestAttributes attrs = (ServletRequestAttributes) RequestContextHolder.getRequestAttributes();
            if (attrs == null) return null;
            HttpServletRequest req = attrs.getRequest();
            return ClientIpResolver.resolve(req);
        } catch (Exception ex) {
            return null;
        }
    }
}
