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
package io.contexa.contexacommon.security;

import jakarta.servlet.http.HttpServletRequest;

/**
 * Resolves the real client IP for an inbound HTTP request, honoring common
 * proxy/CDN headers in priority order. Always falls back to {@link HttpServletRequest#getRemoteAddr()}.
 *
 * <p><b>Security note:</b> proxy headers are easily spoofable when the application
 * is reachable directly. In production, place this behind a trusted proxy (Nginx,
 * AWS ELB, CloudFlare) that overwrites the headers, and configure that proxy as
 * the only allowed source. For a stricter setup, replace this resolver with one
 * that ignores proxy headers entirely.</p>
 */
public final class ClientIpResolver {

    private static final String[] HEADER_CANDIDATES = new String[] {
            "CF-Connecting-IP",      // CloudFlare
            "True-Client-IP",        // Akamai / Cloudflare Enterprise
            "X-Real-IP",             // Nginx
            "X-Forwarded-For",       // standard
            "Forwarded"              // RFC 7239
    };

    private ClientIpResolver() {
    }

    public static String resolve(HttpServletRequest request) {
        if (request == null) return null;
        for (String name : HEADER_CANDIDATES) {
            String value = request.getHeader(name);
            if (value == null || value.isBlank() || "unknown".equalsIgnoreCase(value)) continue;
            int comma = value.indexOf(',');
            String first = (comma > 0 ? value.substring(0, comma) : value).trim();
            if (!first.isEmpty()) return stripPort(first);
        }
        return request.getRemoteAddr();
    }

    private static String stripPort(String addr) {
        if (addr.startsWith("[")) {
            int end = addr.indexOf(']');
            if (end > 0) return addr.substring(1, end);
        }
        int colon = addr.indexOf(':');
        if (colon > 0 && addr.indexOf('.') > 0) return addr.substring(0, colon);
        return addr;
    }
}
