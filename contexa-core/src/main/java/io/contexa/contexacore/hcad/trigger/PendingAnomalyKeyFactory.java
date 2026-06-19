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
package io.contexa.contexacore.hcad.trigger;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Comparator;
import java.util.HexFormat;
import java.util.List;

public final class PendingAnomalyKeyFactory {

    private static final HexFormat HEX_FORMAT = HexFormat.of();

    private PendingAnomalyKeyFactory() {
    }

    public static String buildActorSessionKey(
            String tenantId,
            String organizationId,
            String userId,
            String contextBindingHash) {
        return hash(String.join("|",
                normalize(tenantId),
                normalize(organizationId),
                normalize(userId),
                normalize(contextBindingHash)));
    }

    public static String buildBaseKey(String userId, String contextBindingHash) {
        return buildActorSessionKey(null, null, userId, contextBindingHash);
    }

    public static String buildBaseKey(String userId, String contextBindingHash, String httpMethod, String requestPath) {
        return buildBaseKey(userId, contextBindingHash);
    }

    public static String buildTriggerKey(
            String userId,
            String contextBindingHash,
            String httpMethod,
            String requestPath,
            String stateSignature) {
        return buildDedupKey(userId, contextBindingHash, stateSignature);
    }
    public static String buildRiskSignature(String httpMethod, String requestPath, List<String> reasonCodes) {
        return hash(String.join("|",
                String.join(",", reasonCodes == null ? List.of() : reasonCodes)));
    }

    public static String buildTrustedAnchorSignature(List<String> anchorSignals) {
        return stableSignalSignature(anchorSignals);
    }

    public static String buildTrustedSignalSignature(List<String> anchorSignals, List<String> corroboratingSignals) {
        String anchorSignature = stableSignalSignature(anchorSignals);
        if (!anchorSignature.isBlank()) {
            return anchorSignature;
        }
        return stableSignalSignature(corroboratingSignals);
    }

    public static String buildDedupKey(String userId, String contextBindingHash, String riskSignature) {
        return hash(String.join("|",
                normalize(userId),
                normalize(contextBindingHash),
                normalize(riskSignature)));
    }

    public static String buildActorSessionDedupKey(String actorSessionKey, String riskSignature) {
        return hash(String.join("|",
                normalize(actorSessionKey),
                normalize(riskSignature)));
    }

    public static String buildEscalationKey(String actorSessionKey, String anchorSignature) {
        return hash(String.join("|",
                "escalation",
                normalize(actorSessionKey),
                normalize(anchorSignature)));
    }

    private static String stableSignalSignature(List<String> signals) {
        if (signals == null || signals.isEmpty()) {
            return "";
        }
        return String.join(",",
                signals.stream()
                        .filter(signal -> signal != null && !signal.isBlank())
                        .map(signal -> signal.trim().toUpperCase())
                        .distinct()
                        .sorted(Comparator.naturalOrder())
                        .toList());
    }

    private static String normalize(String value) {
        return value == null ? "" : value.trim();
    }

    private static String hash(String rawValue) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hash = digest.digest(rawValue.getBytes(StandardCharsets.UTF_8));
            return HEX_FORMAT.formatHex(hash).substring(0, 32);
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-256 is required for trigger key generation", e);
        }
    }
}
