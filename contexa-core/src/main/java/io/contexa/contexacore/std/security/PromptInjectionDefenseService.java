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

import org.springframework.ai.document.Document;

import java.util.List;

public class PromptInjectionDefenseService {

    private final PromptSafetyGuardService promptSafetyGuardService;
    private final PromptContextSanitizer promptContextSanitizer;

    public PromptInjectionDefenseService(
            PromptSafetyGuardService promptSafetyGuardService,
            PromptContextSanitizer promptContextSanitizer) {
        this.promptSafetyGuardService = promptSafetyGuardService != null ? promptSafetyGuardService : new PromptSafetyGuardService();
        this.promptContextSanitizer = promptContextSanitizer != null ? promptContextSanitizer : new PromptContextSanitizer();
    }

    public PromptInjectionDefenseDecision evaluate(Document document) {
        PromptSafetyDecision promptSafetyDecision = promptSafetyGuardService.evaluate(document);
        if (!promptSafetyDecision.allowed()) {
            return new PromptInjectionDefenseDecision(
                    false,
                    promptSafetyDecision.decision(),
                    "QUARANTINED",
                    document != null ? document.getText() : null,
                    promptSafetyDecision.flags(),
                    "Prompt safety guard quarantined the context.");
        }

        PromptContextSanitizer.SanitizationDecision sanitizationDecision = promptContextSanitizer.sanitize(document != null ? document.getText() : null);
        if (sanitizationDecision.emptyAfterSanitize()) {
            return new PromptInjectionDefenseDecision(
                    false,
                    "DENIED_PROMPT_SANITIZATION_EMPTY",
                    "QUARANTINED",
                    null,
                    sanitizationDecision.flags(),
                    "Prompt context became empty after sanitization.");
        }
        if (sanitizationDecision.changed()) {
            return new PromptInjectionDefenseDecision(
                    true,
                    "ALLOWED_PROMPT_SANITIZED",
                    "REVIEW_REQUIRED",
                    sanitizationDecision.sanitizedText(),
                    sanitizationDecision.flags(),
                    "Prompt context was sanitized before runtime use.");
        }
        return new PromptInjectionDefenseDecision(
                true,
                promptSafetyDecision.decision(),
                "ACTIVE",
                document != null ? document.getText() : null,
                List.of(),
                "Prompt context passed safety guard without sanitization.");
    }

    public record PromptInjectionDefenseDecision(
            boolean allowed,
            String decision,
            String quarantineState,
            String sanitizedText,
            List<String> flags,
            String summary) {

        public PromptInjectionDefenseDecision {
            flags = flags == null ? List.of() : List.copyOf(flags);
        }
    }
}