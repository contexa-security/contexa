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
package io.contexa.contexacore.std.rag.service;

import java.util.Map;
import java.util.StringJoiner;
import java.util.regex.Pattern;

public final class VectorFilterExpressionBuilder {

    private static final Pattern SAFE_FILTER_KEY = Pattern.compile("[A-Za-z_][A-Za-z0-9_.-]*");

    private VectorFilterExpressionBuilder() {
    }

    public static String buildEqualityExpression(Map<String, Object> filters) {
        if (filters == null || filters.isEmpty()) {
            return null;
        }

        StringJoiner joiner = new StringJoiner(" && ");
        for (Map.Entry<String, Object> entry : filters.entrySet()) {
            String key = validateKey(entry.getKey());
            Object value = entry.getValue();
            if (value instanceof Number || value instanceof Boolean) {
                joiner.add(key + " == " + value);
            } else {
                joiner.add(key + " == '" + escapeLiteral(value) + "'");
            }
        }
        return joiner.toString();
    }

    private static String validateKey(String key) {
        if (key == null || !SAFE_FILTER_KEY.matcher(key).matches()) {
            throw new IllegalArgumentException("Unsafe vector filter key: " + key);
        }
        return key;
    }

    private static String escapeLiteral(Object value) {
        if (value == null) {
            return "";
        }
        return String.valueOf(value)
                .replace("\\", "\\\\")
                .replace("'", "\\'");
    }
}
