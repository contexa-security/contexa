package io.contexa.contexacore.verification.runtime;

import java.text.MessageFormat;
import java.util.Locale;
import java.util.ResourceBundle;

@FunctionalInterface
public interface OfficialVerificationMessageResolver {

    /** The core's own bundle, so the core resolves its messages without the IAM module on the classpath. */
    String CORE_BUNDLE_BASE_NAME = "i18n.core-verification-messages";

    String resolve(String key, Object... args);

    static OfficialVerificationMessageResolver classpath(Locale locale) {
        Locale effectiveLocale = locale == null ? Locale.KOREAN : locale;
        return (key, args) -> {
            ResourceBundle bundle = ResourceBundle.getBundle(
                    CORE_BUNDLE_BASE_NAME,
                    effectiveLocale,
                    ResourceBundle.Control.getNoFallbackControl(ResourceBundle.Control.FORMAT_DEFAULT));
            String pattern = bundle.getString(key);
            return new MessageFormat(pattern, effectiveLocale)
                    .format(args == null ? new Object[0] : args);
        };
    }
}