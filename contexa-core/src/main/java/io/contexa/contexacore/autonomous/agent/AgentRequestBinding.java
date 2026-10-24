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
package io.contexa.contexacore.autonomous.agent;

import org.springframework.lang.Nullable;

import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.HexFormat;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.TreeMap;

/**
 * The request a confirmation is bound to (docs/agent A5-9, AG-11l): the SHA-256 of the tenant, the user, the agent,
 * the method, the path, the query parameters sorted, and the body's SHA-256. The same request sent again binds the
 * same; any other request, another agent's or another person's, binds another. Time is left out, so that the agent
 * can send the confirmed request again.
 */
public final class AgentRequestBinding {

    /** The version of the bound fields; a change of them takes another version. */
    public static final String VERSION = "ctxa.agent-request.v1";

    private AgentRequestBinding() {
    }

    /**
     * @param query        the raw query string, or null
     * @param bodySha256   the body's SHA-256 in hexadecimal, or null for no body
     * @param form         the form parameters of a form post (they stand in for the body and the query), or null
     */
    public static String hash(@Nullable String tenantId, String userId, String agentId, String method, String path,
                              @Nullable String query, @Nullable String bodySha256,
                              @Nullable Map<String, String[]> form) {
        StringBuilder canonical = new StringBuilder(VERSION);
        field(canonical, tenantId);
        field(canonical, userId);
        field(canonical, agentId);
        field(canonical, method != null ? method.trim().toUpperCase(Locale.ROOT) : null);
        field(canonical, path);
        field(canonical, form != null ? parameters(form) : parameters(query));
        field(canonical, form != null ? null : bodySha256 != null ? bodySha256.toLowerCase(Locale.ROOT) : null);
        return sha256Hex(canonical.toString().getBytes(StandardCharsets.UTF_8));
    }

    /** The SHA-256 of the bytes, in hexadecimal. */
    public static String sha256Hex(byte[] bytes) {
        try {
            return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(bytes));
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-256 is not available", e);
        }
    }

    /** The query's parameters, decoded, sorted by name and then by value. */
    static String parameters(@Nullable String query) {
        Map<String, List<String>> sorted = new TreeMap<>();
        if (query != null && !query.isBlank()) {
            for (String pair : query.split("&")) {
                if (pair.isEmpty()) {
                    continue;
                }
                int equals = pair.indexOf('=');
                String name = decode(equals < 0 ? pair : pair.substring(0, equals));
                String value = equals < 0 ? "" : decode(pair.substring(equals + 1));
                sorted.computeIfAbsent(name, key -> new ArrayList<>()).add(value);
            }
        }
        return joined(sorted);
    }

    private static String parameters(Map<String, String[]> form) {
        Map<String, List<String>> sorted = new TreeMap<>();
        form.forEach((name, values) -> sorted.put(name, values != null ? List.of(values) : List.of()));
        return joined(sorted);
    }

    private static String joined(Map<String, List<String>> sorted) {
        StringBuilder joined = new StringBuilder();
        sorted.forEach((name, values) -> values.stream().sorted().forEach(value -> {
            field(joined, name);
            field(joined, value);
        }));
        return joined.toString();
    }

    private static String decode(String value) {
        try {
            return URLDecoder.decode(value, StandardCharsets.UTF_8);
        } catch (IllegalArgumentException malformed) {
            return value;
        }
    }

    /** A field with its length first, so that no two field lists read the same. */
    private static void field(StringBuilder canonical, @Nullable String value) {
        if (value == null) {
            canonical.append("|-");
            return;
        }
        canonical.append('|').append(value.length()).append(':').append(value);
    }
}
