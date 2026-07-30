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
package io.contexa.contexacore.autonomous.context.support;

import org.springframework.util.StringUtils;

import java.util.Locale;

public final class SecuritySemanticNormalizer {

    private SecuritySemanticNormalizer() {
    }

    public static String normalizeAuthenticationType(Object... rawValues) {
        for (Object rawValue : rawValues) {
            String candidate = normalizeToken(rawValue);
            if (!StringUtils.hasText(candidate)) {
                continue;
            }
            if (containsAny(candidate, "PASSKEY", "WEBAUTHN", "FIDO")) {
                return "PASSKEY";
            }
            if (containsAny(candidate, "SAML", "OIDC", "OAUTH", "SSO")) {
                return "SSO";
            }
            if (containsAny(candidate, "USERNAMEPASSWORD", "PASSWORD")) {
                return "PASSWORD";
            }
            if (containsAny(candidate, "SESSION", "SECURITY_CONTEXT")) {
                return "SESSION";
            }
            if (containsAny(candidate, "BEARER", "JWT", "APIKEY", "TOKEN")) {
                return "TOKEN";
            }
            if (containsAny(candidate, "MFA", "TOTP", "OTP")) {
                return "MFA_ONLY";
            }
            if ("UNKNOWN".equals(candidate) || containsAny(candidate, "ANONYMOUS", "UNAUTHENTICATED")) {
                return "UNKNOWN";
            }
        }
        return null;
    }

    public static String normalizeActionFamily(Object... rawValues) {
        for (Object rawValue : rawValues) {
            String candidate = normalizeToken(rawValue);
            if (!StringUtils.hasText(candidate)) {
                continue;
            }
            if (containsAny(candidate, "EXPORT")) {
                return "EXPORT";
            }
            if (containsAny(candidate, "GET", "HEAD", "OPTIONS", "READ", "VIEW", "LIST", "SEARCH", "FETCH", "DOWNLOAD")) {
                return "READ";
            }
            if (containsAny(candidate, "POST", "PUT", "PATCH", "WRITE", "CREATE", "UPDATE", "MODIFY", "UPLOAD")) {
                return "WRITE";
            }
            if (containsAny(candidate, "DELETE", "REMOVE", "PURGE")) {
                return "DELETE";
            }
            if (containsAny(candidate, "EXECUTE", "RUN", "INVOKE")) {
                return "EXECUTE";
            }
            if (containsAny(candidate, "ADMIN", "ROLE", "PERMISSION", "POLICY", "GRANT", "APPROVE", "ELEVATE")) {
                return "ADMIN";
            }
            if ("UNKNOWN".equals(candidate)) {
                return "UNKNOWN";
            }
        }
        return null;
    }

    public static String normalizeResourceFamily(Object... rawValues) {
        for (Object rawValue : rawValues) {
            String candidate = normalizeToken(rawValue);
            if (!StringUtils.hasText(candidate)) {
                continue;
            }
            if (containsAny(candidate, "CRITICAL")) {
                return "CRITICAL";
            }
            if (containsAny(candidate, "SENSITIVE", "HIGH")) {
                return "SENSITIVE";
            }
            if (containsAny(candidate, "NORMAL", "MEDIUM", "INTERNAL", "STANDARD")) {
                return "NORMAL";
            }
            if (containsAny(candidate, "PUBLIC", "LOW")) {
                return "PUBLIC";
            }
            if ("UNKNOWN".equals(candidate)) {
                return "UNKNOWN";
            }
        }
        return null;
    }

    public static String normalizeSensitivity(Object... rawValues) {
        for (Object rawValue : rawValues) {
            String candidate = normalizeToken(rawValue);
            if (!StringUtils.hasText(candidate)) {
                continue;
            }
            if (containsAny(candidate, "CRITICAL")) {
                return "CRITICAL";
            }
            if (containsAny(candidate, "HIGH", "SENSITIVE", "SECRET", "CONFIDENTIAL")) {
                return "HIGH";
            }
            if (containsAny(candidate, "MEDIUM", "INTERNAL", "STANDARD", "NORMAL")) {
                return "MEDIUM";
            }
            if (containsAny(candidate, "LOW", "PUBLIC")) {
                return "LOW";
            }
            if ("UNKNOWN".equals(candidate)) {
                return "UNKNOWN";
            }
        }
        return null;
    }

    public static String normalizePathFamily(String rawPath) {
        if (!StringUtils.hasText(rawPath)) {
            return null;
        }
        String path = rawPath.trim();
        if (!path.startsWith("/")) {
            path = "/" + path;
        }
        int queryIndex = path.indexOf('?');
        if (queryIndex >= 0) {
            path = path.substring(0, queryIndex);
        }
        String[] segments = path.split("/");
        StringBuilder normalized = new StringBuilder();
        int appendedSegments = 0;
        for (String segment : segments) {
            if (!StringUtils.hasText(segment)) {
                continue;
            }
            normalized.append('/').append(segment);
            appendedSegments++;
            if (appendedSegments >= 4) {
                normalized.append("/*");
                return normalized.toString();
            }
        }
        return normalized.length() == 0 ? "/" : normalized.toString();
    }

    public static String normalizeNetwork(String sourceIp, String ipBand) {
        String normalizedBand = normalizeToken(ipBand);
        if (StringUtils.hasText(normalizedBand)) {
            return normalizedBand;
        }
        if (!StringUtils.hasText(sourceIp)) {
            return null;
        }
        String ip = sourceIp.trim();
        int lastDot = ip.lastIndexOf('.');
        if (lastDot > 0) {
            return ip.substring(0, lastDot);
        }
        return ip;
    }

    private static String normalizeToken(Object rawValue) {
        if (rawValue == null) {
            return null;
        }
        String text = rawValue.toString().trim();
        if (!StringUtils.hasText(text)) {
            return null;
        }
        return text
                .replace('-', '_')
                .replace(' ', '_')
                .toUpperCase(Locale.ROOT);
    }

    private static boolean containsAny(String candidate, String... fragments) {
        if (!StringUtils.hasText(candidate) || fragments == null) {
            return false;
        }
        for (String fragment : fragments) {
            if (fragment != null && candidate.contains(fragment)) {
                return true;
            }
        }
        return false;
    }
}
