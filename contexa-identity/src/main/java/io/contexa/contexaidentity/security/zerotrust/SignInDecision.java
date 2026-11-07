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
import org.springframework.lang.Nullable;
import org.springframework.security.core.Authentication;

import java.util.HashMap;
import java.util.Map;

/**
 * Sends a person's completed sign-in on where Contexa owns the sign-in, as {@link HostOwnedSignInListener} sends the
 * application's own where the application owns it: the bridge meets the person, and the agent registry sees an agent that
 * signs in. The model is not asked about a sign-in; the first call to a protected resource is decided. A request's sign-in
 * is sent once, and a failure to send it never stops it.
 */
@Slf4j
public final class SignInDecision {

    /** The sign-in completed with one method. */
    public static final String SINGLE = "SINGLE";

    private SignInDecision() {
    }

    /**
     * Sends the sign-in.
     *
     * @param publisher the engine's publisher; nothing is sent without one
     * @param request   the request of the sign-in
     * @param facts     what is known of the sign-in itself
     */
    public static void send(@Nullable ZeroTrustEventPublisher publisher, @Nullable Authentication authentication,
                            @Nullable HttpServletRequest request, Map<String, Object> facts) {
        if (publisher == null || authentication == null) {
            return;
        }
        try {
            Map<String, Object> signIn = new HashMap<>(facts);
            signIn.putIfAbsent("action", ZeroTrustAction.ALLOW.name());
            publisher.publishAuthenticationSuccess(authentication, request, signIn);
        } catch (RuntimeException e) {
            log.error("[Contexa] The sign-in could not be sent for analysis: userId={}, {}", authentication.getName(),
                    e.getMessage(), e);
        }
    }
}
