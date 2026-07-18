package io.contexa.contexaiam.admin.promptquality.official.common;

import java.util.Locale;
import java.util.Map;

public interface PromptQualityMessageResolver {

    String resolve(String key, Object... args);

    String resolve(Locale locale, String key, Object... args);

    default String resolveRequired(String key, Object... args) {
        String resolved = resolve(key, args);
        if (resolved == null || resolved.isBlank() || key.equals(resolved)) {
            throw new IllegalStateException("Missing prompt-quality message key: " + key);
        }
        return resolved;
    }

    Map<String, String> bundleByPrefix(Locale locale, String prefix);

    Locale currentLocale();
}
