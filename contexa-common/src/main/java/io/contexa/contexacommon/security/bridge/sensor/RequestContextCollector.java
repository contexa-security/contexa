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
package io.contexa.contexacommon.security.bridge.sensor;

import io.contexa.contexacommon.security.network.ClientIpResolutionPolicy;
import io.contexa.contexacommon.security.network.ClientIpResolver;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpSession;

import java.time.Instant;
import java.util.List;
import java.util.UUID;

public class RequestContextCollector {

    private final ClientIpResolutionPolicy clientIpResolutionPolicy;

    public RequestContextCollector() {
        this(ClientIpResolutionPolicy.trustedProxy(List.of()));
    }

    public RequestContextCollector(ClientIpResolutionPolicy clientIpResolutionPolicy) {
        this.clientIpResolutionPolicy = clientIpResolutionPolicy != null
                ? clientIpResolutionPolicy
                : ClientIpResolutionPolicy.trustedProxy(List.of());
    }

    public RequestContextSnapshot collect(HttpServletRequest request) {
        HttpSession session = request.getSession(false);
        return new RequestContextSnapshot(
                request.getRequestURI(),
                request.getMethod(),
                extractClientIp(request),
                extractUserAgent(request),
                session != null ? session.getId() : request.getRequestedSessionId(),
                extractRequestId(request),
                request.getServletPath(),
                request.getQueryString(),
                request.isSecure(),
                Instant.now()
        );
    }

    private String extractClientIp(HttpServletRequest request) {
        return ClientIpResolver.resolve(request, clientIpResolutionPolicy);
    }

    private String extractUserAgent(HttpServletRequest request) {
        String userAgent = request.getHeader("User-Agent");
        return userAgent != null ? userAgent : "unknown";
    }

    private String extractRequestId(HttpServletRequest request) {
        String requestId = request.getHeader("X-Request-ID");
        return (requestId != null && !requestId.isBlank()) ? requestId : UUID.randomUUID().toString();
    }
}
