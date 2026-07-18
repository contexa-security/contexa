package io.contexa.contexaiam.admin.promptquality.official.application;

import io.contexa.contexacore.verification.metric.OfficialPromptQualityNarrativeCatalog;
import io.contexa.contexaiam.admin.promptquality.official.common.PromptQualityCustomerSentencePolicy;
import org.springframework.util.StringUtils;

import java.util.Locale;

final class OfficialVerificationCustomerTextPolicy {

    private static final int TEXT_MAX = 1200;
    private static final int TITLE_MAX = 120;

    String require(String fieldName, String value) {
        String text = concise(value, maxLength(fieldName));
        if (normalize(fieldName).contains("OWNER")
                && OfficialPromptQualityNarrativeCatalog.containsBrokenText(text)) {
            text = "Official verification process";
        }
        if (OfficialPromptQualityNarrativeCatalog.containsBrokenText(text)) {
            return "";
        }
        return PromptQualityCustomerSentencePolicy.requireCustomerSentence(fieldName, text);
    }

    String optional(String fieldName, String value) {
        return StringUtils.hasText(value) ? require(fieldName, value) : "";
    }

    String concise(String value, int maxLength) {
        if (!StringUtils.hasText(value)) {
            return value;
        }
        String cleaned = value.trim().replaceAll("\\s+", " ").trim();
        if (cleaned.length() <= maxLength) {
            return cleaned;
        }
        int sentenceEnd = cleaned.lastIndexOf('.', maxLength - 1);
        return sentenceEnd >= Math.max(80, maxLength / 2)
                ? cleaned.substring(0, sentenceEnd + 1).trim()
                : cleaned.substring(0, Math.max(1, maxLength)).trim();
    }

    private int maxLength(String fieldName) {
        String normalized = normalize(fieldName);
        return normalized.contains("TITLE") || normalized.contains("OWNER") || normalized.contains("SEVERITY")
                ? TITLE_MAX : TEXT_MAX;
    }

    private String normalize(String value) {
        return value == null ? "" : value.trim().toUpperCase(Locale.ROOT);
    }
}
