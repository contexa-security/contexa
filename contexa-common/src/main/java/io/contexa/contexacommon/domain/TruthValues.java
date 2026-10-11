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
package io.contexa.contexacommon.domain;

import java.util.Locale;

/**
 * The one reading of true and false for request attributes, headers and event metadata: a boolean, the number 1 or 0,
 * or the text true, yes, y, 1, false, no, n or 0 in any case. Any other value is not a truth value, never false.
 */
public final class TruthValues {

    private TruthValues() {
    }

    /** The value as true or false; null when it is not a truth value. */
    public static Boolean parse(Object value) {
        if (value == null) {
            return null;
        }
        if (value instanceof Boolean booleanValue) {
            return booleanValue;
        }
        if (value instanceof Number number) {
            double numeric = number.doubleValue();
            return numeric == 1d ? Boolean.TRUE : numeric == 0d ? Boolean.FALSE : null;
        }
        return switch (value.toString().trim().toLowerCase(Locale.ROOT)) {
            case "true", "yes", "y", "1" -> Boolean.TRUE;
            case "false", "no", "n", "0" -> Boolean.FALSE;
            default -> null;
        };
    }

    /** The first value that is a truth value; values that are not are skipped. */
    public static Boolean first(Object... values) {
        if (values == null) {
            return null;
        }
        for (Object value : values) {
            Boolean parsed = parse(value);
            if (parsed != null) {
                return parsed;
            }
        }
        return null;
    }
}
