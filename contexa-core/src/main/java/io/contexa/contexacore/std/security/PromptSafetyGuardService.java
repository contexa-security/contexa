package io.contexa.contexacore.std.security;

import org.springframework.ai.document.Document;
import org.springframework.util.StringUtils;

import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.regex.Pattern;

public class PromptSafetyGuardService {

    private static final List<SafetyPattern> HARD_BLOCK_PATTERNS = List.of(
            new SafetyPattern("IGNORE_PREVIOUS_INSTRUCTIONS", Pattern.compile("(?i)ignore\\s+(all\\s+)?previous\\s+instructions")),
            new SafetyPattern("FORGET_PREVIOUS_INSTRUCTIONS", Pattern.compile("(?i)forget\\s+(all\\s+)?previous\\s+instructions")),
            new SafetyPattern("SYSTEM_PROMPT_DISCLOSURE", Pattern.compile("(?i)(system\\s+prompt|developer\\s+message|reveal\\s+the\\s+prompt)")),
            new SafetyPattern("SAFETY_BYPASS", Pattern.compile("(?i)(disable|bypass)\\s+(security|guardrails|safety|tenant\\s+filter|approval)")),
            new SafetyPattern("TOOL_OVERRIDE", Pattern.compile("(?i)(call\\s+the\\s+tool|function_call|<\\s*tool_?call|execute\\s+the\\s+tool)")),
            new SafetyPattern("MEMORY_OVERRIDE", Pattern.compile("(?i)(write\\s+this\\s+to\\s+memory|overwrite\\s+memory|store\\s+this\\s+forever)")),
            new SafetyPattern("SECRET_DISCLOSURE", Pattern.compile("(?i)(print\\s+all\\s+secrets|reveal\\s+(api\\s+key|secret|password|token))"))
    );

    public PromptSafetyDecision evaluate(Document document) {
        if (document == null) {
            return PromptSafetyDecision.deny(List.of("MISSING_DOCUMENT"));
        }

        Map<String, Object> metadata = document.getMetadata() != null ? document.getMetadata() : Map.of();
        String trustLevel = text(metadata.get("contentTrustLevel"));
        if (StringUtils.hasText(trustLevel) && "TRUSTED_RUNTIME".equalsIgnoreCase(trustLevel)) {
            return PromptSafetyDecision.allow();
        }

        String text = document.getText();
        if (!StringUtils.hasText(text)) {
            return PromptSafetyDecision.allow();
        }

        String normalized = text.replace('\r', ' ').replace('\n', ' ');
        List<String> flags = new ArrayList<>();
        for (SafetyPattern pattern : HARD_BLOCK_PATTERNS) {
            if (pattern.pattern().matcher(normalized).find()) {
                flags.add(pattern.name());
            }
        }

        if (flags.isEmpty()) {
            return PromptSafetyDecision.allow();
        }
        return PromptSafetyDecision.deny(flags);
    }

    private String text(Object value) {
        if (value == null) {
            return null;
        }
        String normalized = value.toString().trim();
        return normalized.isEmpty() ? null : normalized.toUpperCase(Locale.ROOT);
    }

    private record SafetyPattern(String name, Pattern pattern) {
    }
}