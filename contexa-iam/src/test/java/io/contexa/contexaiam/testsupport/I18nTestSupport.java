package io.contexa.contexaiam.testsupport;

import org.junit.jupiter.api.extension.AfterAllCallback;
import org.junit.jupiter.api.extension.BeforeAllCallback;
import org.junit.jupiter.api.extension.ExtensionContext;
import org.springframework.context.MessageSource;
import org.springframework.context.i18n.LocaleContextHolder;
import org.springframework.context.support.ResourceBundleMessageSource;

import java.util.Locale;

/**
 * Shared i18n test support for service-impl unit tests.
 *
 * <p>Two responsibilities:
 *
 * <ol>
 *   <li>{@link #englishMessageSource()} returns a real {@link ResourceBundleMessageSource}
 *       wired against the production {@code i18n/messages} bundle, with
 *       {@code fallbackToSystemLocale=false} so an English message is returned
 *       even when the JVM default locale is ko_KR (typical CI host).</li>
 *   <li>{@link EnglishLocale} pins {@link LocaleContextHolder} to
 *       {@link Locale#ENGLISH} for the duration of the annotated test class so
 *       service code that calls {@code messageSource.getMessage(key, args,
 *       LocaleContextHolder.getLocale())} resolves the English bundle.</li>
 * </ol>
 *
 * <p>Use the spy + extension together:
 *
 * <pre>{@code
 * @ExtendWith({MockitoExtension.class, I18nTestSupport.EnglishLocale.class})
 * class FooServiceImplTest {
 *     @Spy
 *     private MessageSource messageSource = I18nTestSupport.englishMessageSource();
 *     @InjectMocks
 *     private FooServiceImpl service;
 * }
 * }</pre>
 */
public final class I18nTestSupport {

    private I18nTestSupport() {}

    public static MessageSource englishMessageSource() {
        ResourceBundleMessageSource ms = new ResourceBundleMessageSource();
        ms.setBasename("i18n/messages");
        ms.setDefaultEncoding("UTF-8");
        ms.setUseCodeAsDefaultMessage(true);
        ms.setFallbackToSystemLocale(false);
        return ms;
    }

    public static final class EnglishLocale implements BeforeAllCallback, AfterAllCallback {

        private static final ExtensionContext.Namespace NAMESPACE =
                ExtensionContext.Namespace.create(EnglishLocale.class);
        private static final String ORIGINAL_KEY = "originalLocale";

        @Override
        public void beforeAll(ExtensionContext context) {
            context.getStore(NAMESPACE).put(ORIGINAL_KEY, LocaleContextHolder.getLocale());
            LocaleContextHolder.setLocale(Locale.ENGLISH);
        }

        @Override
        public void afterAll(ExtensionContext context) {
            Locale original = (Locale) context.getStore(NAMESPACE).remove(ORIGINAL_KEY);
            LocaleContextHolder.setLocale(original);
        }
    }
}
