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
package io.contexa.contexaiam.admin.promptquality.screen;

import io.contexa.contexaiam.admin.promptquality.screen.PromptQualityScreens.Count;
import org.junit.jupiter.api.Test;
import org.springframework.context.support.ResourceBundleMessageSource;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.mock.web.MockServletContext;
import org.thymeleaf.context.WebContext;
import org.thymeleaf.spring6.SpringTemplateEngine;
import org.thymeleaf.templatemode.TemplateMode;
import org.thymeleaf.templateresolver.ClassLoaderTemplateResolver;
import org.thymeleaf.web.servlet.JakartaServletWebApplication;

import java.util.ArrayList;
import java.util.EnumMap;
import java.util.HashMap;
import java.util.List;
import java.util.Locale;
import java.util.Set;
import java.util.function.BiFunction;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Quality plan 3.8: the two new screens draw their title, their question and the menu bar of the group, the bar as the
 * mockups draw it: the policy center's tab bar with an icon, a name and a count badge for each menu in the order of
 * PromptQualityScreens, the screen's own menu lit up, the count in full in the badge's tooltip, the scope kept on the
 * links; in Korean and in English.
 */
class PromptQualityNavTemplateTest {

    private static final Pattern TAB = Pattern.compile("(?s)<a\\s([^>]*data-pqa-tab=\"[^\"]*\"[^>]*)>(.*?)</a>");
    private static final Pattern ATTRIBUTE = Pattern.compile("([a-z-]+)=\"([^\"]*)\"");
    private static final Pattern TEXT = Pattern.compile("<span>([^<]*)</span>");
    private static final Pattern BADGE = Pattern.compile("<span\\s+class=\"tab-count\"\\s+title=\"([^\"]*)\">([^<]*)</span>");

    private final SpringTemplateEngine engine = engine();
    private final EnumMap<Count, Long> counts = new EnumMap<>(Count.class);

    PromptQualityNavTemplateTest() {
        counts.put(Count.CASES, 76L);
        counts.put(Count.MEASUREMENTS, 6L);
        counts.put(Count.VERSIONS, 2L);
        counts.put(Count.SEALED, 12_345L);
    }

    private record Drawn(String key, String classes, String href, String current, String icon, String name,
                         String badge, String tooltip) {
    }

    @Test
    void theCasesScreenDrawsItsTitleAndTheBarWithItsOwnMenuLitInKorean() {
        String page = render("cases", Locale.KOREAN, nav(null, Locale.KOREAN));
        List<Drawn> tabs = tabs(page);

        assertThat(page).contains("id=\"pv-title\">정답 사례</h1>")
                .contains("판정을 채점하는 기준입니다.")
                .contains("class=\"pc-tab-nav zt-tab-nav mb-6\"")
                .contains("aria-label=\"프롬프트 품질 보증\"");
        assertThat(tabs).extracting(Drawn::key).containsExactly("status", "cases", "measure", "versions", "evidence");
        assertThat(tabs).extracting(Drawn::name).containsExactly("품질 현황", "정답 사례",
                "측정과 비교", "프롬프트 버전",
                "봉인 증거");
        assertThat(tabs).extracting(Drawn::icon).containsExactly("fas fa-heartbeat", "fas fa-clipboard-check",
                "fas fa-balance-scale", "fas fa-code-branch", "fas fa-stamp");
        assertThat(tabs).extracting(Drawn::href).containsExactly("/contexa/admin/prompt-quality/status",
                "/contexa/admin/prompt-quality/cases", "/contexa/admin/prompt-quality/measure",
                "/contexa/admin/prompt-quality/versions", "/contexa/admin/prompt-quality/evidence");
        assertThat(tabs).extracting(Drawn::classes).containsExactly("pc-tab-btn", "pc-tab-btn active", "pc-tab-btn",
                "pc-tab-btn", "pc-tab-btn");
        assertThat(tabs).extracting(Drawn::current).containsExactly(null, "page", null, null, null);
        assertThat(tabs).extracting(Drawn::badge).containsExactly(null, "76", "6", "2", "1.2만");
        assertThat(tabs).extracting(Drawn::tooltip).containsExactly(null,
                "사례 76건 (Contexa 기본 묶음과 확인 대기 사례 포함)",
                "측정 6건 (정답 사례 측정과 봉인 판정 측정)",
                "버전 2개 (숨긴 버전 제외)",
                "최근 7일 봉인 12,345건");
    }

    @Test
    void theMeasureScreenLightsItsOwnMenuAndKeepsTheScopeInEnglish() {
        String page = render("measure", Locale.ENGLISH, nav("tenant-a", Locale.ENGLISH));
        List<Drawn> tabs = tabs(page);

        assertThat(page).contains("id=\"pv-title\">Measure &amp; compare</h1>")
                .contains("Measure a version on the labelled cases and see whether it beats the one in use.")
                .contains("aria-label=\"Prompt quality assurance\"");
        assertThat(tabs).extracting(Drawn::name).containsExactly("Quality", "Labelled cases", "Measure &amp; compare",
                "Prompt versions", "Sealed evidence");
        assertThat(tabs).extracting(Drawn::current).containsExactly(null, null, "page", null, null);
        assertThat(tabs).extracting(Drawn::classes).containsExactly("pc-tab-btn", "pc-tab-btn", "pc-tab-btn active",
                "pc-tab-btn", "pc-tab-btn");
        assertThat(tabs).extracting(Drawn::href).allSatisfy(href -> assertThat(href).endsWith("?scope=tenant-a"));
        assertThat(tabs).extracting(Drawn::badge).containsExactly(null, "76", "6", "2", "12.3K");
        assertThat(tabs).extracting(Drawn::tooltip).containsExactly(null,
                "76 cases, the Contexa default set and the cases waiting for confirmation included",
                "6 measurements, on the labelled cases and on sealed decisions",
                "2 versions, the hidden ones left out", "12,345 sealed in the last 7 days");
    }

    @Test
    void aCountNotReadHasNoBadgeAndAPageWithoutTheBarDrawsNone() {
        counts.remove(Count.MEASUREMENTS);
        List<Drawn> tabs = tabs(render("cases", Locale.ENGLISH, nav(null, Locale.ENGLISH)));

        assertThat(tabs).extracting(Drawn::badge).containsExactly(null, "76", null, "2", "12.3K");
        assertThat(render("cases", Locale.ENGLISH, null)).doesNotContain("pc-tab-nav", "data-pqa-tab")
                .contains("id=\"pv-title\">Labelled cases</h1>");
    }

    private PromptQualityNav nav(String scope, Locale locale) {
        BiFunction<Count, String, Long> read = (count, given) -> {
            assertThat(given).isEqualTo(scope);
            return counts.get(count);
        };
        return new PromptQualityNav(PromptQualityScreens.MENUS, read, scope, locale);
    }

    private static List<Drawn> tabs(String page) {
        List<Drawn> tabs = new ArrayList<>();
        Matcher tab = TAB.matcher(page);
        while (tab.find()) {
            HashMap<String, String> attributes = new HashMap<>();
            Matcher attribute = ATTRIBUTE.matcher(tab.group(1));
            while (attribute.find()) {
                attributes.put(attribute.group(1), attribute.group(2));
            }
            String body = tab.group(2);
            Matcher icon = Pattern.compile("<i\\s+class=\"([^\"]*)\"\\s+aria-hidden=\"true\"></i>").matcher(body);
            Matcher name = TEXT.matcher(body);
            Matcher badge = BADGE.matcher(body);
            boolean badged = badge.find();
            tabs.add(new Drawn(attributes.get("data-pqa-tab"), attributes.get("class"), attributes.get("href"),
                    attributes.get("aria-current"), icon.find() ? icon.group(1) : null,
                    name.find() ? name.group(1) : null, badged ? badge.group(2) : null, badged ? badge.group(1) : null));
        }
        return tabs;
    }

    private String render(String screen, Locale locale, PromptQualityNav nav) {
        MockServletContext servletContext = new MockServletContext();
        MockHttpServletRequest request = new MockHttpServletRequest(servletContext);
        var exchange = JakartaServletWebApplication.buildApplication(servletContext)
                .buildExchange(request, new MockHttpServletResponse());
        HashMap<String, Object> variables = new HashMap<>();
        variables.put("screen", screen);
        if (nav != null) {
            variables.put(PromptQualityNavAdvice.ATTRIBUTE, nav);
        }
        WebContext context = new WebContext(exchange, locale, variables);
        return engine.process(PromptQualityScreens.TEMPLATES + screen, Set.of("main"), context);
    }

    private static SpringTemplateEngine engine() {
        ClassLoaderTemplateResolver resolver = new ClassLoaderTemplateResolver();
        resolver.setPrefix("templates/");
        resolver.setSuffix(".html");
        resolver.setTemplateMode(TemplateMode.HTML);
        resolver.setCharacterEncoding("UTF-8");
        ResourceBundleMessageSource messages = new ResourceBundleMessageSource();
        messages.setBasename("contexa/i18n/messages");
        messages.setDefaultEncoding("UTF-8");
        messages.setFallbackToSystemLocale(false);
        SpringTemplateEngine engine = new SpringTemplateEngine();
        engine.setTemplateResolver(resolver);
        engine.setTemplateEngineMessageSource(messages);
        return engine;
    }
}
