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
package io.contexa.contexaidentity.security.handler.logout;

import io.contexa.contexacore.security.session.SessionIdResolver;
import io.contexa.contexacore.security.zerotrust.ZeroTrustSecurityService;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.Authentication;

@Slf4j
public class ZeroTrustLogoutStrategy implements LogoutStrategy {

    private final ZeroTrustSecurityService zeroTrustSecurityService;
    private final SessionIdResolver sessionIdResolver;

    public ZeroTrustLogoutStrategy(
            ZeroTrustSecurityService zeroTrustSecurityService,
            SessionIdResolver sessionIdResolver) {
        this.zeroTrustSecurityService = zeroTrustSecurityService;
        this.sessionIdResolver = sessionIdResolver;
    }

    @Override
    public boolean supports(HttpServletRequest request, Authentication authentication) {
        return authentication != null && authentication.isAuthenticated();
    }

    @Override
    public void execute(HttpServletRequest request, HttpServletResponse response,
                        Authentication authentication) {
        String userId = authentication.getName();
        String sessionId = sessionIdResolver.resolve(request);
        try {
            zeroTrustSecurityService.cleanupOnLogout(userId, sessionId);
        } catch (Exception e) {
            log.error("[ZeroTrust] Failed to cleanup Redis on logout: userId={}", userId, e);
        }
    }
}
