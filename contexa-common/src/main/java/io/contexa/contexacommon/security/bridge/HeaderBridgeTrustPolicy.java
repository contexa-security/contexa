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
package io.contexa.contexacommon.security.bridge;

import io.contexa.contexacommon.security.bridge.authentication.HostPrincipalSnapshot;
import io.contexa.contexacommon.security.bridge.authentication.HostPrincipalSnapshotAdapter;
import io.contexa.contexacommon.security.network.ClientIpResolver;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;

import java.util.Map;

/**
 * Shared fail-closed trust boundary for the optional header bridge.
 */
public final class HeaderBridgeTrustPolicy {

    private HeaderBridgeTrustPolicy() {
    }

    public static boolean accepts(HttpServletRequest request, BridgeProperties properties) {
        if (request == null || properties == null || properties.getAuthentication() == null) {
            return false;
        }
        BridgeProperties.Headers headers = properties.getAuthentication().getHeaders();
        if (headers == null) {
            return false;
        }
        String headerSubject = text(request.getHeader(headers.getPrincipalId()));
        if (headerSubject == null || !isTrustedSource(request, properties)) {
            return false;
        }
        HostPrincipalSnapshot hostPrincipal = resolveHostPrincipal(request);
        if (hostPrincipal == null || !headerSubject.equals(hostPrincipal.principalId())) {
            return false;
        }
        Map<String, Object> trustedAttributes = hostPrincipal.trustedAttributes();
        return matches(request.getHeader(headers.getTenantId()), trustedAttributes.get("tenantId"))
                && matchesEither(
                request.getHeader(headers.getOrganizationId()),
                trustedAttributes.get("organizationId"),
                trustedAttributes.get("orgId"))
                && matchesEither(
                request.getHeader(headers.getOrgId()),
                trustedAttributes.get("orgId"),
                trustedAttributes.get("organizationId"));
    }

    private static boolean isTrustedSource(HttpServletRequest request, BridgeProperties properties) {
        BridgeProperties.Network network = properties.getNetwork();
        return network != null
                && network.isTrustedProxyValidationEnabled()
                && network.getTrustedProxies() != null
                && !network.getTrustedProxies().isEmpty()
                && ClientIpResolver.isTrustedProxy(request.getRemoteAddr(), network.getTrustedProxies());
    }

    private static HostPrincipalSnapshot resolveHostPrincipal(HttpServletRequest request) {
        Object existing = request.getAttribute(BridgeRequestAttributes.HOST_PRINCIPAL_SNAPSHOT);
        if (existing instanceof HostPrincipalSnapshot snapshot) {
            return snapshot;
        }
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        if (authentication == null
                || !authentication.isAuthenticated()
                || authentication instanceof AnonymousAuthenticationToken) {
            return null;
        }
        try {
            return HostPrincipalSnapshotAdapter.INSTANCE.snapshot(authentication);
        }
        catch (IllegalArgumentException ignored) {
            return null;
        }
    }

    private static boolean matches(String headerValue, Object trustedValue) {
        String candidate = text(headerValue);
        if (candidate == null) {
            return true;
        }
        String trusted = text(trustedValue);
        return trusted != null && candidate.equals(trusted);
    }

    private static boolean matchesEither(String headerValue, Object firstTrustedValue, Object secondTrustedValue) {
        String candidate = text(headerValue);
        if (candidate == null) {
            return true;
        }
        String first = text(firstTrustedValue);
        String second = text(secondTrustedValue);
        return candidate.equals(first) || candidate.equals(second);
    }

    private static String text(Object value) {
        if (value == null) {
            return null;
        }
        String text = value.toString().trim();
        return text.isEmpty() ? null : text;
    }
}
