package io.contexa.contexacore.verification.runtime;

import java.text.MessageFormat;
import java.util.Locale;
import java.util.ResourceBundle;

@FunctionalInterface
public interface OfficialVerificationMessageResolver {

    String resolve(String key, Object... args);

    static OfficialVerificationMessageResolver classpath(Locale locale) {
        Locale effectiveLocale = locale == null ? Locale.KOREAN : locale;
        return (key, args) -> {
            ResourceBundle bundle = ResourceBundle.getBundle(
                    "i18n.messages",
                    effectiveLocale,
                    ResourceBundle.Control.getNoFallbackControl(ResourceBundle.Control.FORMAT_DEFAULT));
            String pattern = bundle.getString(key);
            return new MessageFormat(pattern, effectiveLocale)
                    .format(args == null ? new Object[0] : args);
        };
    }
}