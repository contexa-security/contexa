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
package io.contexa.contexaidentity.security.zerotrust;

import io.contexa.contexacommon.enums.ZeroTrustAction;
import io.contexa.contexacore.autonomous.event.publisher.ZeroTrustEventPublisher;
import jakarta.servlet.http.HttpServletRequest;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.ApplicationListener;
import org.springframework.security.authentication.event.InteractiveAuthenticationSuccessEvent;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;

import java.util.HashMap;
import java.util.Map;

/**
 * The application's own sign-in (HOST_OWNED, ownership design S-8, D-4). Contexa does not take part in it; it only
 * listens to the event Spring Security publishes when a person signs in interactively (form login, OAuth2 login) and
 * sends the sign-in to the engine, with what a protected call of the same request would carry, so a sign-in that looks
 * wrong is decided right away and the next request meets the decision. A request authenticated on its own (Basic, a
 * bearer token) is no sign-in and publishes no such event. The application's authentication and session are only read.
 */
@Slf4j
public class HostOwnedSignInListener implements ApplicationListener<InteractiveAuthenticationSuccessEvent> {

    private final ZeroTrustEventPublisher publisher;

    public HostOwnedSignInListener(ZeroTrustEventPublisher publisher) {
        this.publisher = publisher;
    }

    @Override
    public void onApplicationEvent(InteractiveAuthenticationSuccessEvent event) {
        try {
            HttpServletRequest request = RequestContextHolder.getRequestAttributes() instanceof
                    ServletRequestAttributes attributes ? attributes.getRequest() : null;
            Map<String, Object> signIn = new HashMap<>();
            signIn.put("authenticationType", "HOST_SIGN_IN");
            signIn.put("signedInBy", event.getGeneratedBy().getSimpleName());
            signIn.put("action", ZeroTrustAction.ALLOW.name());
            publisher.publishAuthenticationSuccess(event.getAuthentication(), request, signIn);
        } catch (RuntimeException e) {
            log.error("[Contexa] The application's sign-in could not be sent for analysis: {}", e.getMessage(), e);
        }
    }
}
