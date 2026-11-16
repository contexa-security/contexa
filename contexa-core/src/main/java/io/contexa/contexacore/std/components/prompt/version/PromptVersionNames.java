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
package io.contexa.contexacore.std.components.prompt.version;

import java.util.OptionalInt;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * The name of a version (plan 3.3): one whole number per scope and prompt, shown as {@code v1.0}, {@code v2.0} and so
 * on. A name is read with or without its {@code .0} and its {@code v}.
 */
public final class PromptVersionNames {

    private static final Pattern NAME = Pattern.compile("^[vV]?(\\d{1,9})(\\.0)?$");

    private PromptVersionNames() {
    }

    /** The name of the number: {@code v2.0} for 2. */
    public static String name(int number) {
        if (number < 1) {
            throw new IllegalArgumentException("A version number starts at 1, was " + number);
        }
        return "v" + number + ".0";
    }

    /** The number a name stands for; empty when the text is not a version name. */
    public static OptionalInt number(String name) {
        if (name == null) {
            return OptionalInt.empty();
        }
        Matcher matcher = NAME.matcher(name.trim());
        if (!matcher.matches()) {
            return OptionalInt.empty();
        }
        int number = Integer.parseInt(matcher.group(1));
        return number > 0 ? OptionalInt.of(number) : OptionalInt.empty();
    }
}
