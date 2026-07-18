package io.contexa.contexaiam.testsupport;

import io.contexa.contexaiam.admin.promptquality.official.common.DefaultPromptQualityMessageResolver;
import io.contexa.contexaiam.admin.promptquality.official.common.PromptQualityMessageResolver;
import java.nio.charset.StandardCharsets;
import java.util.Collections;
import java.util.Locale;
import java.util.Map;
import org.springframework.context.i18n.LocaleContextHolder;
import org.springframework.context.support.ResourceBundleMessageSource;

public final class PromptQualityTestResolvers {

    private PromptQualityTestResolvers() {
    }

    public static PromptQualityMessageResolver keyEcho() {
        return new PromptQualityMessageResolver() {
            @Override
            public String resolve(String key, Object... args) {
                return key;
            }

            @Override
            public String resolve(Locale locale, String key, Object... args) {
                return key;
            }

            @Override
            public Map<String, String> bundleByPrefix(Locale locale, String prefix) {
                return Collections.emptyMap();
            }

            @Override
            public Locale currentLocale() {
                return Locale.KOREAN;
            }
        };
    }

    public static PromptQualityMessageResolver koreanBundle() {
        return bundle(Locale.KOREAN);
    }

    public static PromptQualityMessageResolver englishBundle() {
        return bundle(Locale.ENGLISH);
    }

    private static PromptQualityMessageResolver bundle(Locale locale) {
        LocaleContextHolder.setLocale(locale);
        ResourceBundleMessageSource messageSource = new ResourceBundleMessageSource();
        messageSource.setBasenames("i18n/messages", "i18n/messages-enterprise");
        messageSource.setDefaultEncoding(StandardCharsets.UTF_8.name());
        messageSource.setFallbackToSystemLocale(false);
        return new DefaultPromptQualityMessageResolver(messageSource);
    }
}
