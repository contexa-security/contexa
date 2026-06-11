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
package io.contexa.contexacore.std.security;

import org.springframework.util.StringUtils;

import java.util.ArrayList;
import java.util.List;
import java.util.regex.Pattern;

public class PromptContextSanitizer {

    private static final List<SanitizerRule> RULES = List.of(
            new SanitizerRule("SYSTEM_DIRECTIVE_LINE", Pattern.compile("(?i)^\\s*(system|developer|assistant)\\s*:\\s*.*$")),
            new SanitizerRule("TOOL_CALL_MARKUP", Pattern.compile("(?i)<\\s*/?tool_?call[^>]*>")),
            new SanitizerRule("PROMPT_OVERRIDE_MARKUP", Pattern.compile("(?i)^\\s*#+\\s*(system|developer|override).*$")),
            new SanitizerRule("MEMORY_OVERRIDE_MARKUP", Pattern.compile("(?i)^\\s*(write\\s+this\\s+to\\s+memory|store\\s+this\\s+forever).*$"))
    );

    public SanitizationDecision sanitize(String text) {
        if (!StringUtils.hasText(text)) {
            return SanitizationDecision.unchanged(text);
        }

        List<String> sanitizedLines = new ArrayList<>();
        List<String> flags = new ArrayList<>();
        for (String line : text.split("\\r?\\n")) {
            String candidate = line == null ? "" : line;
            boolean blocked = false;
            for (SanitizerRule rule : RULES) {
                if (rule.pattern().matcher(candidate).find()) {
                    flags.add(rule.flag());
                    blocked = true;
                }
            }
            if (!blocked) {
                sanitizedLines.add(candidate);
            }
        }

        if (flags.isEmpty()) {
            return SanitizationDecision.unchanged(text);
        }

        String sanitized = sanitizedLines.stream()
                .filter(StringUtils::hasText)
                .map(String::trim)
                .reduce((left, right) -> left + System.lineSeparator() + right)
                .orElse("");
        if (!StringUtils.hasText(sanitized)) {
            return SanitizationDecision.empty(flags);
        }
        return SanitizationDecision.sanitized(sanitized, flags);
    }

    private record SanitizerRule(String flag, Pattern pattern) {
    }

    public record SanitizationDecision(
            boolean changed,
            boolean emptyAfterSanitize,
            String sanitizedText,
            String decision,
            List<String> flags) {

        public SanitizationDecision {
            flags = flags == null ? List.of() : List.copyOf(flags);
            sanitizedText = StringUtils.hasText(sanitizedText) ? sanitizedText : null;
        }

        public static SanitizationDecision unchanged(String originalText) {
            return new SanitizationDecision(false, false, originalText, "UNCHANGED", List.of());
        }

        public static SanitizationDecision sanitized(String sanitizedText, List<String> flags) {
            return new SanitizationDecision(true, false, sanitizedText, "SANITIZED_REVIEW", flags);
        }

        public static SanitizationDecision empty(List<String> flags) {
            return new SanitizationDecision(true, true, null, "EMPTY_AFTER_SANITIZE", flags);
        }
    }
}