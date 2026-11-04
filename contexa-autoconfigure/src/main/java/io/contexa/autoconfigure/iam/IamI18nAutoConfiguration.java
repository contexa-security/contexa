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
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.beans.factory.config.BeanPostProcessor;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.web.WebProperties;
import org.springframework.boot.autoconfigure.web.servlet.WebMvcAutoConfiguration;
import org.springframework.context.HierarchicalMessageSource;
import org.springframework.context.MessageSource;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.support.ResourceBundleMessageSource;
import org.springframework.web.servlet.LocaleResolver;
import org.springframework.web.servlet.config.annotation.InterceptorRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;
import org.springframework.web.servlet.i18n.AcceptHeaderLocaleResolver;
import org.springframework.web.servlet.i18n.FixedLocaleResolver;
import org.springframework.web.servlet.i18n.SessionLocaleResolver;

/**
 * The language of Contexa's screens and their texts.
 * <p>
 * When Contexa owns sign-in (CONTEXA_OWNED) it resolves the language of the whole application. When the application
 * owns sign-in (HOST_OWNED) it does not touch how the application resolves its own language: Contexa's resolver and
 * its {@code ?lang=} switch serve only the screens under {@code /contexa/}. In both, the texts of Contexa's screens
 * are found even when the application has a message bundle of its own (the application's source keeps its texts first,
 * Contexa's bundle stands behind it).
 */
@AutoConfiguration(before = WebMvcAutoConfiguration.class)
public class IamI18nAutoConfiguration {

    static final String BUNDLE = "i18n/messages";

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
     * texts of Contexa's screens do not show as missing keys.
     */
    @Bean
    static BeanPostProcessor contexaMessagesBehindTheApplications() {
        return new ContexaMessagesBehindTheApplications();
    }

    static final class ContexaMessagesBehindTheApplications implements BeanPostProcessor {

        private final MessageSource contexa = new ContexaMessageSource();

        @Override
        public Object postProcessAfterInitialization(Object bean, String beanName) {
            if (!"messageSource".equals(beanName) || !(bean instanceof HierarchicalMessageSource source)) {
                return bean;
            }
            HierarchicalMessageSource last = source;
            for (MessageSource next = source; next instanceof HierarchicalMessageSource hierarchical; ) {
                if (next instanceof ContexaMessageSource) {
                    return bean;
                }
                last = hierarchical;
                next = hierarchical.getParentMessageSource();
                if (next != null && !(next instanceof HierarchicalMessageSource)) {
                    return bean;
                }
            }
            last.setParentMessageSource(contexa);
            return bean;
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

    /** HOST_OWNED: the application's own language resolution stays; Contexa serves its screens only. */
    @Configuration(proxyBeanMethods = false)
    @ConditionalOnOwnership(SecurityOwnershipMode.HOST_OWNED)
    static class HostOwned {

        @Bean
        @ConditionalOnMissingBean
        LocaleResolver localeResolver(ObjectProvider<WebProperties> web) {
            return new ScreensLocaleResolver(screensResolver(), applicationResolver(web.getIfAvailable(WebProperties::new)));
        }

        @Bean
        WebMvcConfigurer contexaScreensLanguageSwitch() {
            return new WebMvcConfigurer() {
                @Override
                public void addInterceptors(InterceptorRegistry registry) {
                    registry.addInterceptor(new ScreensLocaleChangeInterceptor())
                            .addPathPatterns(ScreensLocaleResolver.SCREENS + "**");
                }
            };
        }

        /** What Spring Boot gives the application when nothing else is defined (spring.web.locale and its resolver). */
        private static LocaleResolver applicationResolver(WebProperties web) {
            if (web.getLocaleResolver() == WebProperties.LocaleResolver.FIXED) {
                return new FixedLocaleResolver(web.getLocale());
            }
            AcceptHeaderLocaleResolver resolver = new AcceptHeaderLocaleResolver();
            resolver.setDefaultLocale(web.getLocale());
            return resolver;
        }
    }

    private static LocaleResolver screensResolver() {
        SessionLocaleResolver resolver = new SessionLocaleResolver();
        resolver.setDefaultLocale(Locale.KOREAN);
        return resolver;
    }
}
