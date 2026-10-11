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
package io.contexa.contexacore.std.components.prompt.bundle;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.HashMap;
import java.util.HexFormat;
import java.util.List;
import java.util.Map;

/**
 * Hash rules of prompt bundles: element hashes, marker hashes of non-present elements and the bundle hash.
 */
public final class PromptBundleHashes {

    public static final List<String> ELEMENT_IDS =
            List.of("B1", "B2", "B3", "B4", "B5", "B6", "B7", "B8", "B9", "B10", "B11");

    private PromptBundleHashes() {
    }

    public static String sha256Hex(String value) {
        return sha256Hex(value.getBytes(StandardCharsets.UTF_8));
    }

    public static String sha256Hex(byte[] value) {
        try {
            return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(value));
        }
        catch (NoSuchAlgorithmException exception) {
            throw new IllegalStateException("SHA-256 algorithm is not available.", exception);
        }
    }

    /** Line endings of text content are normalised to LF before hashing, so a checkout's line endings do not count. */
    public static String normalizeText(String value) {
        return value.replace("\r\n", "\n").replace('\r', '\n');
    }

    public static PromptBundleElement present(String id, String content, String detail) {
        return new PromptBundleElement(id, PromptBundleElementState.PRESENT, sha256Hex(normalizeText(content)), detail);
    }

    public static PromptBundleElement presentHash(String id, String hash, String detail) {
        return new PromptBundleElement(id, PromptBundleElementState.PRESENT, hash, detail);
    }

    public static PromptBundleElement marker(String id, PromptBundleElementState state, String detail) {
        if (state == PromptBundleElementState.PRESENT) {
            throw new IllegalArgumentException("A present element hashes its content, not a marker");
        }
        return new PromptBundleElement(id, state, sha256Hex(state.name() + ":" + id), detail);
    }

    public static String bundleHash(List<PromptBundleElement> elements) {
        Map<String, PromptBundleElement> byId = new HashMap<>();
        for (PromptBundleElement element : elements) {
            if (byId.put(element.id(), element) != null) {
                throw new IllegalArgumentException("Prompt bundle element " + element.id() + " is listed twice");
            }
        }
        StringBuilder lines = new StringBuilder();
        for (String id : ELEMENT_IDS) {
            PromptBundleElement element = byId.get(id);
            if (element == null) {
                throw new IllegalArgumentException("Prompt bundle element " + id + " is missing");
            }
            lines.append(id).append(':').append(element.hash()).append('\n');
        }
        return sha256Hex(lines.toString());
    }
}
