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
package io.contexa.contexacore.autonomous.utils;

import io.contexa.contexacommon.security.network.ClientIpResolver;
import io.contexa.contexacommon.domain.SecurityEvent;
import jakarta.servlet.http.HttpServletRequest;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.HexFormat;
import lombok.extern.slf4j.Slf4j;


@Slf4j
public class SessionFingerprintUtil {

    private static final HexFormat HEX_FORMAT = HexFormat.of();

    public static String generateFingerprint(SecurityEvent event) {
        if (event == null) {
            log.error("[SessionFingerprint] Event is null, returning default fingerprint");
            return "UNKNOWN";
        }

        StringBuilder fingerprint = new StringBuilder();

        if (event.getUserAgent() != null) {
            fingerprint.append("UA:").append(hashString(event.getUserAgent())).append("|");
        }

        if (event.getSourceIp() != null) {
            fingerprint.append("IP:").append(hashString(event.getSourceIp())).append("|");
        }

        int hourOfDay = event.getTimestamp().getHour();
        fingerprint.append("TH:").append(hourOfDay).append("|");

        fingerprint.append("SV:").append(event.getSeverity() != null ? event.getSeverity().toString() : "INFO").append("|");

        if (event.getMetadata() != null && !event.getMetadata().isEmpty()) {
            String metadataHash = hashString(event.getMetadata().toString());
            fingerprint.append("MD:").append(metadataHash).append("|");
        }

        return hashString(fingerprint.toString());
    }

    private static String hashString(String input) {
        if (input == null || input.isEmpty()) {
            return "00000000";
        }

        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            byte[] hash = md.digest(input.getBytes(StandardCharsets.UTF_8));
            String fullHash = HEX_FORMAT.formatHex(hash);
            return fullHash.substring(0, 8);
        } catch (NoSuchAlgorithmException e) {
            log.error("[SessionFingerprint] SHA-256 algorithm not available", e);
            return input.hashCode() + "";
        }
    }

    private static final String CONTEXT_BINDING_HASH_ATTR = "contexa.contextBindingHash";

    public static String generateContextBindingHash(HttpServletRequest request) {
        if (request == null) {
            return null;
        }
        String cached = (String) request.getAttribute(CONTEXT_BINDING_HASH_ATTR);
        if (cached != null) {
            return cached;
        }
        String hash = generateContextBindingHash(
                request.getRequestedSessionId(),
                extractClientIp(request),
                request.getHeader("User-Agent")
        );
        if (hash != null) {
            request.setAttribute(CONTEXT_BINDING_HASH_ATTR, hash);
        }
        return hash;
    }

    public static String generateContextBindingHash(String sessionId, String ip, String userAgent) {
        if (sessionId == null && ip == null && userAgent == null) {
            return null;
        }
        String raw = "CTX:" + (sessionId != null ? sessionId : "")
                + "|" + (ip != null ? ip : "")
                + "|" + (userAgent != null ? userAgent : "");
        return hashStringLong(raw);
    }

    private static String hashStringLong(String input) {
        if (input == null || input.isEmpty()) {
            return "0000000000000000";
        }
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            byte[] hash = md.digest(input.getBytes(StandardCharsets.UTF_8));
            return HEX_FORMAT.formatHex(hash).substring(0, 16);
        } catch (NoSuchAlgorithmException e) {
            log.error("[SessionFingerprint] SHA-256 algorithm not available", e);
            return String.valueOf(input.hashCode());
        }
    }

    public static String extractClientIp(HttpServletRequest request) {
        return ClientIpResolver.resolveLegacy(request);
    }
}
