package io.contexa.contexacore.verification.runtime.prompt;

import io.contexa.contexacore.verification.runtime.OfficialVerificationMessageResolver;
import org.springframework.util.StringUtils;

import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.Map;

final class FinalPromptDisplayValues {

    private FinalPromptDisplayValues() {
    }

    static String firstNonBlank(String... values) {
        if (values == null) {
            return "";
        }
        for (String value : values) {
            if (StringUtils.hasText(value)) {
                return value;
            }
        }
        return "";
    }

    static String lowerFirst(String value) {
        if (!StringUtils.hasText(value)) {
            return "";
        }
        String trimmed = value.trim();
        return trimmed.substring(0, 1).toLowerCase(Locale.ROOT) + trimmed.substring(1);
    }

    static Object firstPresent(Map<String, Object> values, String... keys) {
        if (values == null || keys == null) {
            return "";
        }
        for (String key : keys) {
            Object value = values.get(key);
            if (value != null && StringUtils.hasText(String.valueOf(value))) {
                return value;
            }
        }
        return "";
    }

    static String presentText(String value, OfficialVerificationMessageResolver messageResolver) {
        String key = StringUtils.hasText(value)
                ? "verification.finalPrompt.value.present"
                : "verification.finalPrompt.value.absent";
        return messageResolver.resolve(key);
    }

    static String preview(String value) {
        if (!StringUtils.hasText(value) || "null".equalsIgnoreCase(value)) {
            return "missing";
        }
        String normalized = value.trim()
                .replace("|", ", ")
                .replace("...", " omitted ")
                .replaceAll("\\s+", " ");
        return normalized.length() <= 80 ? normalized : normalized.substring(0, 77).trim() + " omitted";
    }

    static String clippedCustomerList(
            List<String> values,
            int limit,
            OfficialVerificationMessageResolver messageResolver) {
        if (values == null || values.isEmpty()) {
            return "";
        }
        List<String> clipped = values.stream()
                .filter(StringUtils::hasText)
                .map(String::trim)
                .distinct()
                .limit(Math.max(1, limit))
                .toList();
        int remaining = (int) values.stream()
                .filter(StringUtils::hasText)
                .map(String::trim)
                .distinct()
                .count() - clipped.size();
        return remaining > 0
                ? messageResolver.resolve(
                        "verification.finalPrompt.list.remaining",
                        String.join(", ", clipped),
                        remaining)
                : String.join(", ", clipped);
    }

    static String customerRuntimeValue(Object value) {
        return customerRuntimeValue(value, OfficialVerificationMessageResolver.classpath(Locale.KOREAN));
    }

    static String customerRuntimeValue(
            Object value,
            OfficialVerificationMessageResolver messageResolver) {
        if (value == null) {
            return "";
        }
        if (value instanceof Iterable<?> iterable) {
            List<String> values = new ArrayList<>();
            for (Object item : iterable) {
                String text = customerRuntimeValue(item, messageResolver);
                if (StringUtils.hasText(text)) {
                    values.add(text);
                }
            }
            return clippedCustomerList(values, 3, messageResolver);
        }
        if (value instanceof Map<?, ?> map) {
            List<String> values = new ArrayList<>();
            for (Map.Entry<?, ?> entry : map.entrySet()) {
                String key = entry.getKey() == null ? "" : String.valueOf(entry.getKey());
                String text = customerRuntimeValue(entry.getValue(), messageResolver);
                if (StringUtils.hasText(key) && StringUtils.hasText(text)) {
                    values.add(key + " " + text);
                }
            }
            return clippedCustomerList(values, 5, messageResolver);
        }
        String text = String.valueOf(value).trim();
        if ("null".equalsIgnoreCase(text)) {
            return "";
        }
        return text.replaceAll("\\s*\\R+\\s*", ", ")
                .replaceAll("\\s{2,}", " ")
                .trim();
    }
}