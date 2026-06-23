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
package io.contexa.contexacore.hcad.semantic;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.HexFormat;
import java.util.Objects;

public final class HcadSemanticEvidenceKeyFactory {

    public static final String DEFAULT_NAMESPACE = "hcad:semantic:evidence";

    private HcadSemanticEvidenceKeyFactory() {
    }

    public static String cacheKey(HcadSemanticEvidenceKey key) {
        return cacheKey(DEFAULT_NAMESPACE, key);
    }

    public static String cacheKey(String namespace, HcadSemanticEvidenceKey key) {
        Objects.requireNonNull(key, "key must not be null");
        String prefix = normalizeNamespace(namespace);
        return prefix + ":" + key.type().cacheSegment() + ":" + digest(canonicalIdentity(key));
    }

    public static String compatibilityKey(HcadSemanticEvidenceKey key) {
        return compatibilityKey(DEFAULT_NAMESPACE, key);
    }

    public static String compatibilityKey(String namespace, HcadSemanticEvidenceKey key) {
        Objects.requireNonNull(key, "key must not be null");
        String prefix = normalizeNamespace(namespace);
        return prefix + ":compat:" + key.type().cacheSegment() + ":" + digest(compatibilityIdentity(key));
    }

    public static String negativeCacheKey(HcadSemanticEvidenceKey key) {
        return negativeCacheKey(DEFAULT_NAMESPACE, key);
    }

    public static String negativeCacheKey(String namespace, HcadSemanticEvidenceKey key) {
        Objects.requireNonNull(key, "key must not be null");
        String prefix = normalizeNamespace(namespace);
        return prefix + ":absent:" + key.type().cacheSegment() + ":" + digest(canonicalIdentity(key));
    }

    static String canonicalIdentity(HcadSemanticEvidenceKey key) {
        Objects.requireNonNull(key, "key must not be null");
        return String.join("|",
                value(key.type().name()),
                value(key.tenantId()),
                value(key.userId()),
                value(key.sessionId()),
                value(key.contextBindingHash()),
                value(key.resourceId()),
                value(key.policyVersion()),
                value(key.promptTemplateVersion()),
                value(key.baselineVersion()),
                value(key.flowVersion()),
                value(key.embeddingModel()),
                value(key.dimension()),
                value(key.evidenceVersion()));
    }

    static String compatibilityIdentity(HcadSemanticEvidenceKey key) {
        Objects.requireNonNull(key, "key must not be null");
        return String.join("|",
                value(key.type().name()),
                value(key.tenantId()),
                value(key.userId()),
                value(key.sessionId()),
                value(key.contextBindingHash()),
                value(key.resourceId()));
    }

    private static String normalizeNamespace(String namespace) {
        if (namespace == null || namespace.isBlank()) {
            return DEFAULT_NAMESPACE;
        }
        String trimmed = namespace.trim();
        while (trimmed.endsWith(":")) {
            trimmed = trimmed.substring(0, trimmed.length() - 1);
        }
        return trimmed.isBlank() ? DEFAULT_NAMESPACE : trimmed;
    }

    private static String digest(String value) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hash = digest.digest(value.getBytes(StandardCharsets.UTF_8));
            return HexFormat.of().formatHex(hash).substring(0, 32);
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-256 is not available", e);
        }
    }

    private static String value(Object value) {
        return value == null ? "-" : String.valueOf(value);
    }
}
