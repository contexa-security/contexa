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
package io.contexa.contexaiam.admin.web.menu;

import io.contexa.contexaiam.admin.web.menu.service.AdminMenuService.MenuNode;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.mock.web.MockServletContext;
import org.thymeleaf.context.WebContext;
import org.thymeleaf.spring6.SpringTemplateEngine;
import org.thymeleaf.templatemode.TemplateMode;
import org.thymeleaf.templateresolver.ClassLoaderTemplateResolver;
import org.thymeleaf.web.servlet.JakartaServletWebApplication;

import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;

/** The side menu drawn from the real fragment: a drawing as a drawing, and a stored value of no known form not at all. */
class AdminMenuFragmentTemplateTest {

    private static final String SEEDED_DRAWING = "<svg fill=\"none\" stroke=\"currentColor\" viewBox=\"0 0 24 24\" width=\"24\" "
            + "height=\"24\"><path stroke-linecap=\"round\" stroke-linejoin=\"round\" stroke-width=\"1.5\" d=\"M3.75 21h16.5\"/></svg>";

    private final SpringTemplateEngine engine = engine();

    @Test
    @DisplayName("a seeded drawing is drawn as it is")
    void aSeededDrawingIsDrawn() {
        assertThat(render(link(SEEDED_DRAWING))).contains(SEEDED_DRAWING);
        assertThat(render(group(SEEDED_DRAWING))).contains(SEEDED_DRAWING);
    }

    @Test
    @DisplayName("a class is written as a class")
    void aClassIsWrittenAsAClass() {
        assertThat(render(link("fas fa-home"))).contains("<i class=\"fas fa-home\"></i>");
    }

    @Test
    @DisplayName("a stored value of no known form reaches the page in no form")
    void aStoredValueOfNoKnownFormIsNotWritten() {
        assertThat(render(link("<b>Sales & Ops</b>"))).doesNotContain("Sales", "<b>", "&lt;b");
        assertThat(render(group("<b>Sales & Ops</b>"))).doesNotContain("Sales", "<b>", "&lt;b");
    }

    private static MenuNode link(String icon) {
        return new MenuNode(1L, "menu.dashboard", "/contexa/admin/dashboard", icon, "dashboard", "CORE", true, Set.of(),
                List.of());
    }

    private static MenuNode group(String icon) {
        return new MenuNode(2L, "menu.nav.iam", null, icon, "iam", "CORE", true, Set.of(), List.of(link("")));
    }

    private String render(MenuNode node) {
        MockServletContext servletContext = new MockServletContext();
        MockHttpServletRequest request = new MockHttpServletRequest(servletContext);
        var exchange = JakartaServletWebApplication.buildApplication(servletContext)
                .buildExchange(request, new MockHttpServletResponse());
        WebContext context = new WebContext(exchange, Locale.ENGLISH, Map.of("menuTree", List.of(node)));
        return engine.process("contexa/fragments/admin-menu", Set.of("menu"), context);
    }

    private static SpringTemplateEngine engine() {
        ClassLoaderTemplateResolver resolver = new ClassLoaderTemplateResolver();
        resolver.setPrefix("templates/");
        resolver.setSuffix(".html");
        resolver.setTemplateMode(TemplateMode.HTML);
        resolver.setCharacterEncoding("UTF-8");
        SpringTemplateEngine engine = new SpringTemplateEngine();
        engine.setTemplateResolver(resolver);
        return engine;
    }
}
