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

import io.contexa.contexacommon.security.bridge.SecurityOwnershipMode;
import io.contexa.contexacommon.operating.ConditionalOnOwnership;
import java.util.Locale;
import java.util.Set;
import org.springframework.beans.factory.BeanFactory;
import org.springframework.beans.factory.BeanFactoryAware;
import org.springframework.beans.factory.config.BeanPostProcessor;
import org.springframework.beans.factory.config.SingletonBeanRegistry;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.web.servlet.WebMvcAutoConfiguration;
import org.springframework.context.ApplicationContext;
import org.springframework.context.HierarchicalMessageSource;
import org.springframework.context.MessageSource;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.support.AbstractApplicationContext;
import org.springframework.context.support.DelegatingMessageSource;
import org.springframework.context.support.ResourceBundleMessageSource;
import org.springframework.web.servlet.LocaleResolver;
import org.springframework.web.servlet.config.annotation.InterceptorRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;
import org.springframework.web.servlet.handler.MappedInterceptor;
import org.springframework.web.servlet.i18n.SessionLocaleResolver;

/**
 * The language of Contexa's screens and their texts.
 * <p>
 * When Contexa owns sign-in (CONTEXA_OWNED) it resolves the language of the whole application. When the application
 * owns sign-in (HOST_OWNED) Contexa adds no language resolver: the application keeps the one it has (Spring Boot's, by
 * default) for all its requests, and only the requests of the screens under {@code /contexa/} are given the screens'
 * resolver and its {@code ?lang=} switch, one request at a time. In both, the texts of Contexa's screens are found even
 * when the application has a message bundle of its own (the application's source keeps its texts first, Contexa's
 * bundle stands behind it).
 */
@AutoConfiguration(before = WebMvcAutoConfiguration.class)
public class IamI18nAutoConfiguration {

    static final String BUNDLE = "contexa/i18n/messages";

    /** The message source Contexa creates when the application has none: its own bundle only. */
    static final class ContexaMessageSource extends ResourceBundleMessageSource {

        ContexaMessageSource() {
            setBasenames(BUNDLE);
            setDefaultEncoding("UTF-8");
            setFallbackToSystemLocale(false);
            setUseCodeAsDefaultMessage(true);
            setCacheSeconds(3600);
        }
    }

    @Bean
    @ConditionalOnMissingBean
    public MessageSource messageSource() {
        return new ContexaMessageSource();
    }

    /**
     * Puts Contexa's bundle behind the message source of an application that has one of its own (Spring Boot makes
     * one as soon as the application has a {@code messages.properties}, and Contexa's then stands aside), so that the
     * texts of Contexa's screens do not show as missing keys. An application whose only message source goes by another
     * name has none named {@code messageSource}: the context then puts an empty one of its own there, and Contexa's
     * bundle stands behind that one. The application's source under its own name is not touched.
     */
    @Bean
    static BeanPostProcessor contexaMessagesBehindTheApplications() {
        return new ContexaMessagesBehindTheApplications();
    }

    static final class ContexaMessagesBehindTheApplications implements BeanPostProcessor, BeanFactoryAware {

        private static final String NAME = AbstractApplicationContext.MESSAGE_SOURCE_BEAN_NAME;

        private final MessageSource contexa = new ContexaMessageSource();
        private SingletonBeanRegistry singletons;
        private volatile boolean contextsOwnSeen;

        @Override
        public void setBeanFactory(BeanFactory beanFactory) {
            if (beanFactory instanceof SingletonBeanRegistry registry) {
                singletons = registry;
            }
        }

        /** The context's own empty source is registered as it is, shown to no post-processor: it is looked up here. */
        @Override
        public Object postProcessBeforeInitialization(Object bean, String beanName) {
            if (!contextsOwnSeen && singletons != null && singletons.containsSingleton(NAME)) {
                contextsOwnSeen = true;
                if (singletons.getSingleton(NAME) instanceof DelegatingMessageSource own) {
                    behind(own);
                }
            }
            return bean;
        }

        @Override
        public Object postProcessAfterInitialization(Object bean, String beanName) {
            if (NAME.equals(beanName) && bean instanceof HierarchicalMessageSource source) {
                behind(source);
            }
            return bean;
        }

        private void behind(HierarchicalMessageSource source) {
            HierarchicalMessageSource last = source;
            for (MessageSource next = source; next instanceof HierarchicalMessageSource hierarchical; ) {
                if (next instanceof ContexaMessageSource) {
                    return;
                }
                last = hierarchical;
                next = hierarchical.getParentMessageSource();
                if (next != null && !(next instanceof HierarchicalMessageSource)) {
                    return;
                }
            }
            last.setParentMessageSource(contexa);
        }
    }

    /** CONTEXA_OWNED: Contexa resolves the language of the whole application, as it always did. */
    @Configuration(proxyBeanMethods = false)
    @ConditionalOnOwnership(value = SecurityOwnershipMode.CONTEXA_OWNED, matchIfUndeclared = true)
    static class ContexaOwned {

        @Bean
        @ConditionalOnMissingBean
        LocaleResolver localeResolver() {
            return screensResolver();
        }

        @Bean
        WebMvcConfigurer contexaLanguageSwitch() {
            return new WebMvcConfigurer() {
                @Override
                public void addInterceptors(InterceptorRegistry registry) {
                    registry.addInterceptor(new ScreensLocaleChangeInterceptor());
                }
            };
        }
    }

    /**
     * HOST_OWNED: the application's language resolver stays the application's, under Spring MVC's name and of the class
     * the application gave it (Spring Boot's, made after this configuration, when the application defines none); Contexa
     * serves its screens only.
     */
    @Configuration(proxyBeanMethods = false)
    @ConditionalOnOwnership(SecurityOwnershipMode.HOST_OWNED)
    static class HostOwned {

        /**
         * The screens' own language, for their requests only, when the application defines no language resolver of its
         * own. A resolver the application defines serves the screens as well, as it always did.
         */
        @Bean
        @ConditionalOnMissingBean(LocaleResolver.class)
        MappedInterceptor contexaScreensLanguage(ApplicationContext context) {
            return new MappedInterceptor(new String[]{ScreensLanguageInterceptor.SCREENS + "**"},
                    new ScreensLanguageInterceptor(screensResolver(), context));
        }

        @Bean
        WebMvcConfigurer contexaScreensLanguageSwitch() {
            return new WebMvcConfigurer() {
                @Override
                public void addInterceptors(InterceptorRegistry registry) {
                    registry.addInterceptor(new ScreensLocaleChangeInterceptor())
                            .addPathPatterns(ScreensLanguageInterceptor.SCREENS + "**");
                }
            };
        }
    }

    /**
     * The language a person chose (?lang=) for the rest of the session; before a choice, the browser's when the screens
     * have it (Korean, English), Korean otherwise. The sign-in pages ask the same resolver, so the two do not differ.
     */
    private static SessionLocaleResolver screensResolver() {
        SessionLocaleResolver resolver = new SessionLocaleResolver();
        resolver.setDefaultLocaleFunction(request -> {
            Locale browser = request.getLocale();
            return browser != null && SCREEN_LANGUAGES.contains(browser.getLanguage())
                    ? Locale.forLanguageTag(browser.getLanguage()) : Locale.KOREAN;
        });
        return resolver;
    }

    /** The languages the screens are written in. */
    private static final Set<String> SCREEN_LANGUAGES = Set.of("ko", "en");
}
