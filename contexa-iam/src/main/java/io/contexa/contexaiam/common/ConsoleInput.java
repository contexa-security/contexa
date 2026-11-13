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
package io.contexa.contexaiam.common;

import org.springframework.context.MessageSource;
import org.springframework.context.i18n.LocaleContextHolder;

/**
 * The checks of a value an administrator typed into a console form, made before it reaches the database.
 * <p>
 * The database refuses a value longer than its column, and a required column without a value, with a constraint nobody
 * can read; a blank name it keeps. A value is taken without the blanks around it, and is refused here with an
 * {@link IllegalArgumentException} that names the field, which the console shows as a refusal.
 */
public final class ConsoleInput {

    private ConsoleInput() {
    }

    /**
     * The value without the blanks around it.
     *
     * @param fieldKey the message key of the field's name
     * @param max      the length of the field's column
     * @throws IllegalArgumentException when the value is blank or longer than {@code max}
     */
    public static String required(MessageSource messages, String fieldKey, String value, int max) {
        String trimmed = value == null ? "" : value.trim();
        if (trimmed.isEmpty()) {
            throw new IllegalArgumentException(text(messages, "msg.input.required", field(messages, fieldKey)));
        }
        return limited(messages, fieldKey, trimmed, max);
    }

    /**
     * The value without the blanks around it, or {@code null} when it is blank.
     *
     * @param fieldKey the message key of the field's name
     * @param max      the length of the field's column
     * @throws IllegalArgumentException when the value is longer than {@code max}
     */
    public static String optional(MessageSource messages, String fieldKey, String value, int max) {
        if (value == null || value.trim().isEmpty()) {
            return null;
        }
        return limited(messages, fieldKey, value.trim(), max);
    }

    /**
     * The value as it was typed, refused when longer than {@code max}: for a value whose blanks are its own.
     *
     * @throws IllegalArgumentException when the value is longer than {@code max}
     */
    public static String unchanged(MessageSource messages, String fieldKey, String value, int max) {
        if (value == null) {
            return null;
        }
        return limited(messages, fieldKey, value, max);
    }

    private static String limited(MessageSource messages, String fieldKey, String value, int max) {
        if (value.length() > max) {
            throw new IllegalArgumentException(text(messages, "msg.input.too.long", field(messages, fieldKey),
                    String.valueOf(max), String.valueOf(value.length())));
        }
        return value;
    }

    private static String field(MessageSource messages, String fieldKey) {
        return messages.getMessage(fieldKey, null, fieldKey, LocaleContextHolder.getLocale());
    }

    private static String text(MessageSource messages, String key, Object... args) {
        return messages.getMessage(key, args, LocaleContextHolder.getLocale());
    }
}
