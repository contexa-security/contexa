/*
 * Copyright 2026 The Contexa Project
 *
 * The Contexa Project licenses this file to you under the Apache License,
 * version 2.0 (the "License"); you may not use this file except in compliance
 * with the License. You may obtain a copy of the License at:
 *
 *   https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
 * License for the specific language governing permissions and limitations
 * under the License.
 */
package io.contexa.contexaidentity.security.filter;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpSession;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.ApplicationContext;
import org.springframework.lang.Nullable;
import org.springframework.web.servlet.DispatcherServlet;
import org.springframework.web.servlet.LocaleResolver;
import org.springframework.web.servlet.i18n.SessionLocaleResolver;

import java.util.Locale;

/**
 * The language of the sign-in pages Contexa writes. They are written by filters, before Spring MVC asks the application's
 * {@link LocaleResolver}, so they ask it themselves: the sign-in page and the screens after it then speak the language the
 * person chose or the application gives, not two different ones. The resolver is looked up at the first page, not while
 * the security chain is built, which would make Spring MVC's configuration early.
 */
@Slf4j
public final class SignInPageLocale {

    @Nullable
    private final ApplicationContext context;
    @Nullable
    private volatile LocaleResolver resolver;
    private volatile boolean lookedUp;

    public SignInPageLocale(@Nullable ApplicationContext context) {
        this.context = context;
    }

    Locale resolve(HttpServletRequest request) {
        LocaleResolver application = applicationResolver();
        if (application != null) {
            try {
                Locale locale = application.resolveLocale(request);
                if (locale != null) {
                    return locale;
                }
            } catch (RuntimeException e) {
                log.debug("The locale resolver of the application failed; the sign-in page follows the browser", e);
            }
        }
        HttpSession session = request.getSession(false);
        if (session != null && session.getAttribute(SessionLocaleResolver.LOCALE_SESSION_ATTRIBUTE_NAME) instanceof Locale chosen) {
            return chosen;
        }
        Locale requestLocale = request.getLocale();
        return requestLocale != null ? requestLocale : Locale.KOREAN;
    }

    @Nullable
    private LocaleResolver applicationResolver() {
        if (!lookedUp) {
            if (context != null && context.containsBean(DispatcherServlet.LOCALE_RESOLVER_BEAN_NAME)) {
                try {
                    resolver = context.getBean(DispatcherServlet.LOCALE_RESOLVER_BEAN_NAME, LocaleResolver.class);
                } catch (RuntimeException e) {
                    log.debug("The locale resolver of the application could not be read; the sign-in pages follow the "
                            + "browser", e);
                }
            }
            lookedUp = true;
        }
        return resolver;
    }

    /** The value of the page's {@code lang} attribute: a language code, letters only. */
    static String htmlLang(Locale locale) {
        String language = locale.getLanguage();
        return language.matches("[a-z]{2,8}") ? language : "en";
    }
}
