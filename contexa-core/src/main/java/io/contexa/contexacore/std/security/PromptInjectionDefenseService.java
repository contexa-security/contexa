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