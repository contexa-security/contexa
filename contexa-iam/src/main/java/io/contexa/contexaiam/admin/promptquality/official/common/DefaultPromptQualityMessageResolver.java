package io.contexa.contexaiam.admin.promptquality.official.common;

import org.springframework.context.MessageSource;
import org.springframework.context.NoSuchMessageException;
import org.springframework.context.i18n.LocaleContextHolder;

import java.util.Collections;
import java.util.Enumeration;
import java.util.LinkedHashMap;
import java.util.Locale;
import java.util.Map;
import java.util.ResourceBundle;

public class DefaultPromptQualityMessageResolver implements PromptQualityMessageResolver {

    private static final String CORE_BUNDLE_BASE_NAME = "i18n.messages";
    private static final String ENTERPRISE_BUNDLE_BASE_NAME = "i18n.messages-enterprise";

    private final MessageSource messageSource;

    public DefaultPromptQualityMessageResolver(MessageSource messageSource) {
        this.messageSource = messageSource;
    }

    @Override
    public String resolve(String key, Object... args) {
        return resolve(currentLocale(), key, args);
    }

    @Override
    public String resolve(Locale locale, String key, Object... args) {
        try {
            return messageSource.getMessage(key, args, locale);
        }
        catch (NoSuchMessageException ignored) {
            return key;
        }
    }

    @Override
    public Map<String, String> bundleByPrefix(Locale locale, String prefix) {
        if (prefix == null || prefix.isBlank()) {
            return Collections.emptyMap();
        }
        Locale effective = locale != null ? locale : currentLocale();
        Map<String, String> collected = new LinkedHashMap<>();
        collectBundleByPrefix(collected, ENTERPRISE_BUNDLE_BASE_NAME, effective, prefix);
        collectBundleByPrefix(collected, CORE_BUNDLE_BASE_NAME, effective, prefix);
        return collected;
    }

    @Override
    public Locale currentLocale() {
        return LocaleContextHolder.getLocale();
    }

    private void collectBundleByPrefix(
            Map<String, String> collected,
            String baseName,
            Locale locale,
            String prefix
    ) {
        try {
            ResourceBundle bundle = ResourceBundle.getBundle(baseName, locale);
            Enumeration<String> keys = bundle.getKeys();
            while (keys.hasMoreElements()) {
                String key = keys.nextElement();
                if (key.startsWith(prefix)) {
                    collected.put(key, bundle.getString(key));
                }
            }
        }
        catch (RuntimeException ignored) {
        }
    }
}
