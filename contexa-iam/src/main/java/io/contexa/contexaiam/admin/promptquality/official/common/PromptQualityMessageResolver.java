package io.contexa.contexaiam.admin.promptquality.official.common;

import java.util.Locale;
import java.util.Map;

public interface PromptQualityMessageResolver {

    String resolve(String key, Object... args);

    String resolve(Locale locale, String key, Object... args);

    Map<String, String> bundleByPrefix(Locale locale, String prefix);

    Locale currentLocale();
}
