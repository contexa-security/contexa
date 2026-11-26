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

import io.contexa.contexaiam.admin.web.i18n.SeedTextDialect;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.BeanUtils;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnClass;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnWebApplication;
import org.springframework.context.ApplicationContext;
import org.springframework.context.annotation.Bean;
import org.springframework.core.Ordered;
import org.springframework.util.ClassUtils;
import org.thymeleaf.dialect.IDialect;
import org.thymeleaf.spring6.SpringTemplateEngine;
import org.thymeleaf.spring6.templateresolver.SpringResourceTemplateResolver;
import org.thymeleaf.spring6.view.ThymeleafViewResolver;
import org.thymeleaf.templatemode.TemplateMode;

import java.nio.charset.StandardCharsets;
import java.util.Set;

/**
 * R-9 (F-04): Contexa's screens are written by a template engine of their own, which reads Contexa's views only
 * ({@code contexa/...} under {@code classpath:/templates/}) with the dialects they are written in: Spring's standard
 * dialect, the seed texts of the console (IAM-D31) and Spring Security's, as the starter brings it. Neither the engine,
 * its template resolver nor its dialects are beans, so an application's own Thymeleaf, which Spring Boot builds from the
 * beans of those types, is configured as without Contexa; an application that does not use Thymeleaf gets none of
 * Spring Boot's ({@code StandaloneAutoConfigurationFilter}), and its JSP views stay its own.
 * <p>
 * The view resolver takes the names of Contexa's views only, before the application's resolvers, and is no candidate for
 * the application's injection of a view resolver. The engine's messages are the context's, as an engine bean gets them.
 */
@Slf4j
@AutoConfiguration
@ConditionalOnWebApplication(type = ConditionalOnWebApplication.Type.SERVLET)
@ConditionalOnClass(name = {"org.thymeleaf.spring6.view.ThymeleafViewResolver",
        "io.contexa.contexaiam.admin.web.i18n.SeedTextDialect"})
public class IamScreenTemplatesAutoConfiguration {

    /** The names of Contexa's views, which its view resolver and its template resolver take. */
    static final String CONTEXA_VIEWS = "contexa/*";

    private static final String TEMPLATES = "classpath:/templates/";
    private static final String HTML = ".html";
    private static final String SECURITY_DIALECT = "org.thymeleaf.extras.springsecurity6.dialect.SpringSecurityDialect";
    private static final String CSRF_TOKEN = "org.springframework.security.web.csrf.CsrfToken";

    @Bean(name = "contexaScreensViewResolver", defaultCandidate = false)
    @ConditionalOnMissingBean(name = "contexaScreensViewResolver")
    public ThymeleafViewResolver contexaScreensViewResolver(ApplicationContext applicationContext) {
        ThymeleafViewResolver resolver = new ThymeleafViewResolver();
        resolver.setTemplateEngine(screensEngine(applicationContext));
        resolver.setCharacterEncoding(StandardCharsets.UTF_8.name());
        resolver.setContentType("text/html;charset=" + StandardCharsets.UTF_8.name());
        resolver.setViewNames(new String[]{CONTEXA_VIEWS});
        // a redirect or a forward is the application's view resolvers' to make, as without Contexa: Thymeleaf makes them before it
        // reads the view names unless told not to
        resolver.setAlwaysProcessRedirectAndForward(false);
        resolver.setOrder(Ordered.HIGHEST_PRECEDENCE + 10);
        return resolver;
    }

    static SpringTemplateEngine screensEngine(ApplicationContext applicationContext) {
        SpringResourceTemplateResolver templates = new SpringResourceTemplateResolver();
        templates.setApplicationContext(applicationContext);
        templates.setPrefix(TEMPLATES);
        templates.setSuffix(HTML);
        templates.setTemplateMode(TemplateMode.HTML);
        templates.setCharacterEncoding(StandardCharsets.UTF_8.name());
        templates.setResolvablePatterns(Set.of(CONTEXA_VIEWS));
        templates.setCacheable(true);
        templates.setCheckExistence(true);

        SpringTemplateEngine engine = new SpringTemplateEngine();
        engine.setTemplateResolver(templates);
        engine.setMessageSource(applicationContext);
        engine.addDialect(new SeedTextDialect());
        IDialect security = securityDialect(applicationContext.getClassLoader());
        if (security != null) {
            engine.addDialect(security);
        }
        return engine;
    }

    /** Spring Security's dialect, where it and Spring Security's web support are on the class path. */
    private static IDialect securityDialect(ClassLoader classLoader) {
        if (!ClassUtils.isPresent(SECURITY_DIALECT, classLoader) || !ClassUtils.isPresent(CSRF_TOKEN, classLoader)) {
            return null;
        }
        try {
            return (IDialect) BeanUtils.instantiateClass(ClassUtils.forName(SECURITY_DIALECT, classLoader));
        } catch (ClassNotFoundException | LinkageError ex) {
            log.error("Spring Security's Thymeleaf dialect could not be loaded: Contexa's screens are written without it", ex);
            return null;
        }
    }
}
