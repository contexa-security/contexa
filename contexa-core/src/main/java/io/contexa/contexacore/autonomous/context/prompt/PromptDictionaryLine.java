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
package io.contexa.contexacore.autonomous.context.prompt;

import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * A line of a v20 block as the dictionary renderer draws it: its indent, its fact id head ({@code [F3] }, empty when
 * the line has none), the entry label and the value.
 */
public record PromptDictionaryLine(String indent, String factId, String label, String value) {

    private static final Pattern LINE = Pattern.compile("^(\\s*)(\\[[A-Z]\\d+\\] )?([A-Za-z][A-Za-z0-9]*): (.*)$");

    /** The line of a label and a value, or null for any other line (a header, a blank line, a sentence). */
    public static PromptDictionaryLine parse(String line) {
        if (line == null) {
            return null;
        }
        Matcher matcher = LINE.matcher(line);
        return matcher.matches()
                ? new PromptDictionaryLine(matcher.group(1), matcher.group(2) == null ? "" : matcher.group(2),
                        matcher.group(3), matcher.group(4))
                : null;
    }

    /** The same line with another value, keeping its indent and fact id. */
    public String withValue(String newValue) {
        return indent + factId + label + ": " + newValue;
    }

    /** The line as drawn. */
    public String text() {
        return withValue(value);
    }
}
