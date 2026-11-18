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

import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.springframework.context.support.ResourceBundleMessageSource;
import org.springframework.data.domain.PageImpl;
import org.springframework.data.domain.PageRequest;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.mock.web.MockServletContext;
import org.thymeleaf.context.WebContext;
import org.thymeleaf.web.servlet.IServletWebExchange;
import org.thymeleaf.web.servlet.JakartaServletWebApplication;
import org.thymeleaf.spring6.SpringTemplateEngine;
import org.thymeleaf.templatemode.TemplateMode;
import org.thymeleaf.templateresolver.ClassLoaderTemplateResolver;

import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * K142 on the drawn list screens of groups, address rules, permissions, role hierarchies, roles and sessions: with
 * millions of rows each draws the policy list's pagination (the first, the previous, the pages near the current one,
 * the next and the last), never a link per page, every link inside the list and keeping the screen's filters.
 */
class ListPaginationScreenTest {

    private static final Pattern PAGE_LINK = Pattern.compile("class=\"page-link\"[^>]*href=\"([^\"]*)\"");

    @ParameterizedTest
    @CsvSource({"groups,page,/contexa/admin/groups", "ip-management,rules,/contexa/admin/ip-management",
            "permissions,page,/contexa/admin/permissions", "role-hierarchies,hierarchyPage,/contexa/admin/role-hierarchies",
            "roles,page,/contexa/admin/roles", "session-management,sessionPage,/contexa/admin/session-management"})
    void millionsOfRowsDrawTheNearPagesOnly(String screen, String pageVariable, String address) {
        MockServletContext servletContext = new MockServletContext();
        IServletWebExchange exchange = JakartaServletWebApplication.buildApplication(servletContext)
                .buildExchange(new MockHttpServletRequest(servletContext), new MockHttpServletResponse());
        WebContext context = new WebContext(exchange, Locale.KOREAN);
        // page 5001 of 500,000, the screen's word and (for the address rules) its type
        context.setVariables(Map.of(pageVariable, new PageImpl<>(List.of(), PageRequest.of(5000, 20), 9_999_999L),
                "keyword", "ops team", "currentType", "DENY"));

        String html = engine().process("contexa/admin/" + screen, context);

        List<String> links = new ArrayList<>();
        Matcher matcher = PAGE_LINK.matcher(html);
        while (matcher.find()) {
            links.add(URLDecoder.decode(matcher.group(1).replace("&amp;", "&"), StandardCharsets.UTF_8));
        }
        // the first, the previous, page 1, pages 4999 to 5003, the last page, the next and the last
        assertThat(links).as(screen).hasSize(11).allMatch(link -> link.startsWith(address + "?")
                && link.contains("keyword=ops team") && (!screen.equals("ip-management") || link.contains("type=DENY")));
        assertThat(links).extracting(link -> Integer.parseInt(link.replaceAll(".*[?&]page=(\\d+).*", "$1")))
                .containsExactly(0, 4999, 0, 4998, 4999, 5000, 5001, 5002, 499999, 5001, 499999);
        assertThat(html).as(screen).contains(">500000<", "modern-pagination flex-wrap justify-center")
                .doesNotContain("numbers.sequence");
        assertThat(html.length()).as(screen).isLessThan(200_000);
    }

    private static SpringTemplateEngine engine() {
        ResourceBundleMessageSource messages = new ResourceBundleMessageSource();
        messages.setBasename("contexa/i18n/messages");
        messages.setDefaultEncoding("UTF-8");
        messages.setFallbackToSystemLocale(false);
        ClassLoaderTemplateResolver fragments = resolver("test-templates/", 1);
        fragments.setResolvablePatterns(Set.of("contexa/fragments/*"));
        SpringTemplateEngine engine = new SpringTemplateEngine();
        engine.setTemplateResolvers(Set.of(fragments, resolver("templates/", 2)));
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
