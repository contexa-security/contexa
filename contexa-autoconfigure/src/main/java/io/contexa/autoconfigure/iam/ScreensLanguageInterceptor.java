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
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.BeanFactoryUtils;
import org.springframework.beans.factory.ListableBeanFactory;
import org.springframework.context.i18n.LocaleContextHolder;
import org.springframework.core.annotation.AnnotationAwareOrderComparator;
import org.springframework.lang.Nullable;
import org.springframework.web.servlet.DispatcherServlet;
import org.springframework.web.servlet.HandlerInterceptor;
import org.springframework.web.servlet.LocaleContextResolver;
import org.springframework.web.servlet.ModelAndView;
import org.springframework.web.servlet.View;
import org.springframework.web.servlet.ViewResolver;
import org.springframework.web.servlet.view.UrlBasedViewResolver;

import java.util.ArrayList;
import java.util.List;
import java.util.Locale;

/**
 * The language of Contexa's screens in an application that owns its sign-in (HOST_OWNED). Contexa adds no language
 * resolver there: the application keeps the one it has (Spring Boot's, by default), under Spring MVC's name, for every
 * request. A request for one of Contexa's screens, which live under {@code /contexa/}, is given the screens' resolver
 * for its own duration instead (the language a person chose with {@code ?lang=} for the session; before a choice, the
 * browser's when the screens have it, Korean otherwise). The application's own requests are not touched.
 * <p>
 * Spring MVC takes the language of a request from three places, and a screen's request is given the screens' resolver
 * in each:
 * <ul>
 *   <li>the resolver the dispatcher puts in the request ({@link DispatcherServlet#LOCALE_RESOLVER_ATTRIBUTE}), which the
 *       {@code ?lang=} switch, {@code RequestContextUtils.getLocale}, a {@code Locale} argument of a handler and the
 *       {@code RequestContext} of a view (form errors) ask;</li>
 *   <li>{@link LocaleContextHolder}, which the messages of the handlers ask; the dispatcher sets it back when the
 *       request ends;</li>
 *   <li>the dispatcher's own resolver, which it asks when it looks up the view by name: a Thymeleaf page is written in
 *       the language its view was looked up with. The view of a screen is therefore looked up here, after the handler, in
 *       the screens' language, with the view resolvers the dispatcher finds (every one in the context, in their order).
 *       A view that cannot be looked up here is left to the dispatcher, which looks it up as it would without Contexa.</li>
 * </ul>
 * Registered as a mapped interceptor, it runs before the interceptors registered through Spring MVC's configuration in
 * every handler mapping, so the {@code ?lang=} switch after it changes the screens' language.
 */
@Slf4j
final class ScreensLanguageInterceptor implements HandlerInterceptor {

    /** Where Contexa's screens live, below the application's context path. */
    static final String SCREENS = "/contexa/";

    private final LocaleContextResolver screens;
    private final ListableBeanFactory beans;
    @Nullable
    private volatile List<ViewResolver> viewResolvers;

    ScreensLanguageInterceptor(LocaleContextResolver screens, ListableBeanFactory beans) {
        this.screens = screens;
        this.beans = beans;
    }

    /** Whether the request is one of Contexa's screens: its path below the context path starts with {@link #SCREENS}. */
    static boolean isScreen(HttpServletRequest request) {
        String path = request.getRequestURI();
        String context = request.getContextPath();
        if (path != null && context != null && !context.isEmpty() && path.startsWith(context)) {
            path = path.substring(context.length());
        }
        return path != null && path.startsWith(SCREENS);
    }

    @Override
    public boolean preHandle(HttpServletRequest request, HttpServletResponse response, Object handler) {
        if (isScreen(request)) {
            request.setAttribute(DispatcherServlet.LOCALE_RESOLVER_ATTRIBUTE, screens);
            LocaleContextHolder.setLocaleContext(screens.resolveLocaleContext(request));
        }
        return true;
    }

    /** The view of a screen, looked up in the screens' language; a redirect or a forward carries no language. */
    @Override
    public void postHandle(HttpServletRequest request, HttpServletResponse response, Object handler,
                           @Nullable ModelAndView modelAndView) {
        if (modelAndView == null || request.getAttribute(DispatcherServlet.LOCALE_RESOLVER_ATTRIBUTE) != screens) {
            return;
        }
        String name = modelAndView.getViewName();
        if (name == null || name.startsWith(UrlBasedViewResolver.REDIRECT_URL_PREFIX)
                || name.startsWith(UrlBasedViewResolver.FORWARD_URL_PREFIX)) {
            return;
        }
        Locale locale = screens.resolveLocale(request);
        try {
            for (ViewResolver resolver : viewResolvers()) {
                View view = resolver.resolveViewName(name, locale);
                if (view != null) {
                    modelAndView.setView(view);
                    return;
                }
            }
        } catch (Exception e) {
            log.debug("The view {} of a Contexa screen was not looked up in the screens' language; the dispatcher looks "
                    + "it up", name, e);
        }
    }

    /** The view resolvers the dispatcher finds: every one in the context and its parents, in their order. */
    private List<ViewResolver> viewResolvers() {
        List<ViewResolver> resolvers = viewResolvers;
        if (resolvers == null) {
            List<ViewResolver> found = new ArrayList<>(
                    BeanFactoryUtils.beansOfTypeIncludingAncestors(beans, ViewResolver.class, true, false).values());
            AnnotationAwareOrderComparator.sort(found);
            resolvers = List.copyOf(found);
            viewResolvers = resolvers;
        }
        return resolvers;
    }
}
