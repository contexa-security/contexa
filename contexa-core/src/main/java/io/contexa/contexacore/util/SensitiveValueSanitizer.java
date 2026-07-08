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
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package io.contexa.contexacore.util;

import java.lang.reflect.Array;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.regex.Pattern;

public final class SensitiveValueSanitizer {

    private static final Pattern OPENAI_KEY = Pattern.compile("sk-[A-Za-z0-9_*\\-]{8,}");
    private static final Pattern BEARER_TOKEN = Pattern.compile("(?i)(authorization\\s*[:=]\\s*bearer\\s+)([^\\s,'\"}]+)");
    private static final Pattern API_KEY_ASSIGNMENT = Pattern.compile("(?i)((?:api[_ -]?key|secret[_ -]?key|access[_ -]?token|bearer[_ -]?token)\\s*[:=]\\s*)([^\\s,'\"}]+)");

    private SensitiveValueSanitizer() {
    }

    public static String sanitizeText(String value) {
        if (value == null || value.isBlank()) {
            return value;
        }
        String sanitized = OPENAI_KEY.matcher(value).replaceAll("[REDACTED_OPENAI_API_KEY]");
        sanitized = BEARER_TOKEN.matcher(sanitized).replaceAll("$1[REDACTED_TOKEN]");
        sanitized = API_KEY_ASSIGNMENT.matcher(sanitized).replaceAll("$1[REDACTED_SECRET]");
        return sanitized;
    }

    public static Object sanitizeObject(Object value) {
        if (value == null) {
            return null;
        }
        if (value instanceof String text) {
            return sanitizeText(text);
        }
        if (value instanceof Map<?, ?> map) {
            Map<String, Object> sanitized = new LinkedHashMap<>();
            map.forEach((key, mapValue) -> {
                if (key != null) {
                    String stringKey = String.valueOf(key);
                    sanitized.put(stringKey, sanitizeValueForKey(stringKey, mapValue));
                }
            });
            return sanitized;
        }
        if (value instanceof Iterable<?> iterable) {
            List<Object> sanitized = new ArrayList<>();
            for (Object item : iterable) {
                sanitized.add(sanitizeObject(item));
            }
            return sanitized;
        }
        if (value.getClass().isArray()) {
            int length = Array.getLength(value);
            List<Object> sanitized = new ArrayList<>(length);
            for (int index = 0; index < length; index++) {
                sanitized.add(sanitizeObject(Array.get(value, index)));
            }
            return sanitized;
        }
        return value;
    }

    public static Object sanitizeValueForKey(String key, Object value) {
        if (value == null) {
            return null;
        }
        String normalizedKey = key == null ? "" : key.toLowerCase(Locale.ROOT);
        if (normalizedKey.contains("apikey")
                || normalizedKey.contains("api_key")
                || normalizedKey.contains("secret")
                || normalizedKey.contains("authorization")
                || normalizedKey.equals("token")
                || normalizedKey.endsWith("token")
                || normalizedKey.contains("bearer")) {
            return "[REDACTED]";
        }
        return sanitizeObject(value);
    }
}