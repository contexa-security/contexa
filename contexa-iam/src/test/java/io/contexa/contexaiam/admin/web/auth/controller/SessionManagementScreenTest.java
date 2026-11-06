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
package io.contexa.contexaiam.admin.web.auth.controller;

import io.contexa.contexacore.autonomous.utils.RequestFactRedaction;
import io.contexa.contexaiam.domain.entity.ActiveSession;
import org.junit.jupiter.api.Test;
import org.springframework.context.support.ResourceBundleMessageSource;
import org.springframework.data.domain.PageImpl;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.mock.web.MockServletContext;
import org.thymeleaf.context.WebContext;
import org.thymeleaf.spring6.SpringTemplateEngine;
import org.thymeleaf.templatemode.TemplateMode;
import org.thymeleaf.templateresolver.ClassLoaderTemplateResolver;
import org.thymeleaf.web.servlet.JakartaServletWebApplication;

import java.time.LocalDateTime;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * The console's session list shows and acts on a session by its reference, as the audit names it: an administrator
 * never reads the value a session's cookie carries, so no administrator can take another person's session from it.
 */
class SessionManagementScreenTest {

    private static final String RAW = "6F1C2A9B8E7D4C3B2A1908F7E6D5C4B3";

    @Test
    void theListShowsAndInvalidatesBySessionReference() {
        String reference = RequestFactRedaction.sessionReference(RAW);
        // One row kept by its reference, one kept before the references under the raw value.
        ActiveSession tracked = ActiveSession.builder().sessionId(reference).userId("alice").username("alice")
                .clientIp("10.0.0.7").createdAt(LocalDateTime.now()).lastAccessedAt(LocalDateTime.now()).build();
        ActiveSession legacy = ActiveSession.builder().sessionId("LEGACY-RAW-VALUE").userId("bob").username("bob")
                .createdAt(LocalDateTime.now()).build();

        String page = render(Map.of("activePage", "session-management", "activeCount", 2L,
                "sessionPage", new PageImpl<>(List.of(tracked, legacy))));

        assertThat(page).doesNotContain(RAW).doesNotContain("LEGACY-RAW-VALUE")
                .contains("title=\"" + reference + "\"",
                        "/contexa/admin/session-management/" + reference + "/invalidate",
                        "/contexa/admin/session-management/"
                                + RequestFactRedaction.sessionReference("LEGACY-RAW-VALUE") + "/invalidate");
    }

    private static String render(Map<String, Object> variables) {
        MockServletContext servletContext = new MockServletContext();
        MockHttpServletRequest request = new MockHttpServletRequest(servletContext, "GET",
                "/contexa/admin/session-management");
        WebContext context = new WebContext(JakartaServletWebApplication.buildApplication(servletContext)
                .buildExchange(request, new MockHttpServletResponse()), Locale.ENGLISH, variables);
        return engine().process("contexa/admin/session-management", context);
    }

    private static SpringTemplateEngine engine() {
        ClassLoaderTemplateResolver fragments = resolver("test-templates/", 1);
        fragments.setResolvablePatterns(Set.of("contexa/fragments/*"));
        ClassLoaderTemplateResolver templates = resolver("templates/", 2);
        SpringTemplateEngine engine = new SpringTemplateEngine();
        engine.setTemplateResolvers(Set.of(fragments, templates));
        ResourceBundleMessageSource messages = new ResourceBundleMessageSource();
        messages.setBasename("contexa/i18n/messages");
        messages.setFallbackToSystemLocale(false);
        engine.setTemplateEngineMessageSource(messages);
        return engine;
    }

    private static ClassLoaderTemplateResolver resolver(String prefix, int order) {
        ClassLoaderTemplateResolver resolver = new ClassLoaderTemplateResolver();
        resolver.setPrefix(prefix);
        resolver.setSuffix(".html");
        resolver.setTemplateMode(TemplateMode.HTML);
        resolver.setCharacterEncoding("UTF-8");
        resolver.setCheckExistence(true);
        resolver.setOrder(order);
        return resolver;
    }
}
