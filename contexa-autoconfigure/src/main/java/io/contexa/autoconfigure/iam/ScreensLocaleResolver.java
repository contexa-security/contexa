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
package io.contexa.autoconfigure.iam;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.context.i18n.LocaleContext;
import org.springframework.lang.Nullable;
import org.springframework.web.servlet.LocaleContextResolver;
import org.springframework.web.servlet.LocaleResolver;

import java.util.Locale;

/**
 * The language resolver of an application that owns its sign-in (HOST_OWNED): Contexa's own screens, which live under
 * {@code /contexa/}, resolve their language the way they always did (a session resolver, Korean by default, switched
 * by {@code ?lang=}); every other request of the application is resolved by what the application would have without
 * Contexa. Contexa must not change the language of the application's own pages.
 */
final class ScreensLocaleResolver implements LocaleContextResolver {

    static final String SCREENS = "/contexa/";

    private final LocaleResolver screens;
    private final LocaleResolver application;

    ScreensLocaleResolver(LocaleResolver screens, LocaleResolver application) {
        this.screens = screens;
        this.application = application;
    }

    private LocaleResolver of(HttpServletRequest request) {
        String path = request.getRequestURI();
        String context = request.getContextPath();
        if (path != null && context != null && !context.isEmpty() && path.startsWith(context)) {
            path = path.substring(context.length());
        }
        return path != null && path.startsWith(SCREENS) ? screens : application;
    }

    @Override
    public Locale resolveLocale(HttpServletRequest request) {
        return of(request).resolveLocale(request);
    }

    @Override
    public LocaleContext resolveLocaleContext(HttpServletRequest request) {
        LocaleResolver resolver = of(request);
        return resolver instanceof LocaleContextResolver contextual ? contextual.resolveLocaleContext(request)
                : () -> resolver.resolveLocale(request);
    }

    @Override
    public void setLocale(HttpServletRequest request, @Nullable HttpServletResponse response, @Nullable Locale locale) {
        of(request).setLocale(request, response, locale);
    }

    @Override
    public void setLocaleContext(HttpServletRequest request, @Nullable HttpServletResponse response,
                                 @Nullable LocaleContext localeContext) {
        LocaleResolver resolver = of(request);
        if (resolver instanceof LocaleContextResolver contextual) {
            contextual.setLocaleContext(request, response, localeContext);
        } else {
            resolver.setLocale(request, response, localeContext != null ? localeContext.getLocale() : null);
        }
    }
}
