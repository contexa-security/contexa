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

import com.fasterxml.jackson.databind.ObjectMapper;
import io.contexa.contexaiam.admin.promptquality.screen.PromptQualityMeasureViews.Tab;
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

import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.EnumMap;
import java.util.HashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Quality plan 3.8: the screens of the labelled cases and of measure and compare draw their frame in both languages:
 * the title, the bar with their own menu lit, the addresses their scripts read, the views of measure and compare as
 * one tab bar from the screen's one list (the trial's result under "two versions"), the counts beside the tabs as the
 * bar counts them, and a page with no bar nor data still drawn. Their scripts and styles carry a version mark.
 */
class PromptQualityScreenTemplateTest {

    private static final Pattern VIEW_TAB = Pattern.compile("(?s)<button\\s([^>]*role=\"tab\"[^>]*)>([^<]*)</button>");
    private static final Pattern ATTRIBUTE = Pattern.compile("([a-z-]+)=\"([^\"]*)\"");

    private final ResourceBundleMessageSource messages = messages();
    private final SpringTemplateEngine engine = engine(messages);
    private final PromptQualityPageController controller = new PromptQualityPageController(messages, new ObjectMapper());
    private final EnumMap<Count, Long> counts = new EnumMap<>(Count.class);

    PromptQualityScreenTemplateTest() {
        counts.put(Count.CASES, 76L);
        counts.put(Count.MEASUREMENTS, 6L);
        counts.put(Count.VERSIONS, 2L);
        counts.put(Count.SEALED, 1_284L);
    }

    private record Drawn(String view, String href, String selected, String text) {
    }

    @Test
    void theCasesScreenDrawsItsFrameForTheListAndForACaseInKorean() {
        HashMap<String, Object> list = variables("cases", "list", Locale.KOREAN, null);
        list.put("apiBase", "/contexa/admin/api/prompt-quality/cases");
        String page = render("cases", Locale.KOREAN, list);

        assertThat(page).contains("id=\"pv-title\">정답 사례</h1>")
                .contains("data-pqa-api=\"/contexa/admin/api/prompt-quality/cases\"")
                .contains("data-api-base=\"/contexa/admin/api/prompt-quality/versions\"")
                .contains("data-measure-base=\"/contexa/admin/prompt-quality/measure\"")
                .contains("data-view=\"list\"").doesNotContain("data-case-key=")
                .contains("class=\"pc-tab-btn active\"").contains("data-pqa-tab=\"cases\"")
                .contains("id=\"zt-band\"").contains("id=\"pv-notice\"").contains("id=\"pv-confirm-overlay\"")
                .contains("id=\"zt-messages\"").doesNotContain("id=\"pqa-views\"");
        HashMap<String, Object> detail = variables("cases", "detail", Locale.KOREAN, null);
        detail.put("caseKey", "VER-A1T");
        assertThat(render("cases", Locale.KOREAN, detail)).contains("data-case-key=\"VER-A1T\"")
                .contains("data-view=\"detail\"").contains("id=\"pv-crumbs\"");
    }

    @Test
    void theViewsOfMeasureAndCompareAreOneTabBarWithTheBarsCountInBothLanguages() {
        HashMap<String, Object> runs = variables("measure", "runs", Locale.KOREAN, null);
        List<Drawn> korean = tabs(render("measure", Locale.KOREAN, runs));
        assertThat(korean).extracting(Drawn::view).containsExactly("runs", "run", "compare", "causes");
        assertThat(korean).extracting(Drawn::text).containsExactly("측정 목록 6", "한 판의 결과", "두 판의 비교",
                "틀린 사례와 원인");
        assertThat(korean).extracting(Drawn::selected).containsExactly("true", "false", "false", "false");
        assertThat(korean).extracting(Drawn::href).containsExactly("/contexa/admin/prompt-quality/measure",
                "/contexa/admin/prompt-quality/measure/run", "/contexa/admin/prompt-quality/measure/compare",
                "/contexa/admin/prompt-quality/measure/run?view=causes");

        HashMap<String, Object> trial = variables("measure", "trial", Locale.ENGLISH, "tenant-a");
        trial.put("trialId", 7L);
        String page = render("measure", Locale.ENGLISH, trial);
        List<Drawn> english = tabs(page);
        assertThat(page).contains("id=\"pv-title\">Measure &amp; compare</h1>").contains("data-trial-id=\"7\"")
                .contains("data-view=\"trial\"").contains("class=\"pc-tab-btn active\"")
                .contains("data-api-base=\"/contexa/admin/api/prompt-quality/versions\"")
                .contains("aria-label=\"Views of measure and compare\"");
        assertThat(english).extracting(Drawn::text).containsExactly("Measurements 6", "One version", "Two versions",
                "Wrong cases and causes");
        // The result of a trial stands under "two versions".
        assertThat(english).extracting(Drawn::selected).containsExactly("false", "false", "true", "false");
        assertThat(english).extracting(Drawn::href).allSatisfy(href -> assertThat(href).endsWith("scope=tenant-a"));

        HashMap<String, Object> compare = variables("measure", "compare", Locale.KOREAN, null);
        compare.put("candidate", 3);
        compare.put("reference", 1);
        compare.put("candidateMeasure", 9L);
        compare.put("referenceMeasure", 8L);
        assertThat(render("measure", Locale.KOREAN, compare)).contains("data-candidate=\"3\"")
                .contains("data-reference=\"1\"").contains("data-candidate-measure=\"9\"")
                .contains("data-reference-measure=\"8\"");
        // On the page of one measurement the views of a measurement open on it.
        HashMap<String, Object> run = variables("measure", "run", Locale.KOREAN, null, 41L);
        List<Drawn> onRun = tabs(render("measure", Locale.KOREAN, run));
        assertThat(onRun).extracting(Drawn::selected).containsExactly("false", "true", "false", "false");
        assertThat(onRun).extracting(Drawn::href).containsExactly("/contexa/admin/prompt-quality/measure",
                "/contexa/admin/prompt-quality/measure/41", "/contexa/admin/prompt-quality/measure/compare",
                "/contexa/admin/prompt-quality/measure/41?view=causes");
    }

    /** With no bar (no count read) and no data the frame is still drawn, the tabs without counts. */
    @Test
    void aPageWithoutTheBarOrDataIsStillDrawn() {
        HashMap<String, Object> variables = new HashMap<>();
        variables.put("screen", "measure");
        variables.put("view", "runs");
        variables.put("measureTabs", controller.tabs("runs", null, Locale.ENGLISH, null));
        String page = render("measure", Locale.ENGLISH, variables);

        assertThat(page).doesNotContain("pc-tab-nav").contains("id=\"zt-content\"");
        assertThat(tabs(page)).extracting(Drawn::text).containsExactly("Measurements", "One version", "Two versions",
                "Wrong cases and causes");
        assertThat(render("cases", Locale.ENGLISH, new HashMap<>())).contains("id=\"pv-title\">Labelled cases</h1>");
    }

    /** The scripts and styles of the two screens carry a version mark, so a browser never runs an older copy. */
    @Test
    void theScriptsAndStylesCarryAVersionMark() throws IOException {
        // K197: the script of the cases changed its words of a case's input and raised its mark; K200: it draws the
        // answer fields with the shared script, which raised its mark too; the supplement (P-6) draws the notice of
        // the person's data with the shared script in every window that makes a case.
        Map<String, String> marks = Map.of("cases", "20261123-sup3", "measure", "20261123-fb");
        for (String screen : List.of("cases", "measure")) {
            String template = read("templates/contexa/admin/prompt-quality/" + screen + ".html");
            Matcher assets = Pattern.compile("@\\{(/contexa/[^}]*\\.(?:js|css)[^}]*)}").matcher(template);
            List<String> found = new ArrayList<>();
            while (assets.find()) {
                found.add(assets.group(1));
            }
            assertThat(found).hasSizeGreaterThanOrEqualTo(5).allSatisfy(asset -> assertThat(asset).contains("?v="));
            assertThat(found).contains("/contexa/js/admin/prompt-version/pv-common.js?v=20261122-s2b",
                    "/contexa/js/admin/prompt-quality/pqa-common.js?v=20261122-s1",
                    "/contexa/js/admin/prompt-quality/" + screen + ".js?v=" + marks.get(screen));
        }
        assertThat(read("templates/contexa/admin/prompt-quality/measure.html"))
                .contains("/contexa/js/admin/prompt-quality/measure-trials.js?v=20261123-k225")
                .contains("/contexa/js/admin/prompt-quality/case-answer.js?v=20261123-sup3")
                .contains("th:each=\"extra : ${viewScripts}\"");
        String cases = read("templates/contexa/admin/prompt-quality/cases.html");
        assertThat(cases).contains("/contexa/js/admin/prompt-quality/case-answer.js?v=20261123-sup3");
        assertThat(cases.indexOf("case-answer.js")).isLessThan(cases.indexOf("prompt-quality/cases.js"));
        assertThat(read("templates/contexa/fragments/admin-menu.html")).contains("admin-menu.js?v=20261122-s1");
    }

    /** K191: the side menu's group of the prompt quality screens lights on every address of the group. */
    @Test
    void theSideMenuLightsTheGroupOnItsScreens() throws IOException {
        String menu = read("static/contexa/js/admin-menu.js");

        assertThat(menu).contains("'/contexa/admin/prompt-quality': 'prompt-quality'")
                .contains("'/contexa/admin/prompt-inspection': 'prompt-quality'");
    }

    private HashMap<String, Object> variables(String screen, String view, Locale locale, String scope) {
        return variables(screen, view, locale, scope, null);
    }

    private HashMap<String, Object> variables(String screen, String view, Locale locale, String scope, Long measureId) {
        HashMap<String, Object> variables = new HashMap<>();
        variables.put("measureId", measureId);
        variables.put("screen", screen);
        variables.put("view", view);
        variables.put("apiBase", "/contexa/admin/api/prompt-quality/" + screen);
        variables.put("versionsApi", "/contexa/admin/api/prompt-quality/versions");
        variables.put("versionsPages", PromptQualityScreens.VERSIONS);
        variables.put("measureBase", PromptQualityScreens.MEASURE);
        variables.put("scriptMessagesJson", "{}");
        PromptQualityNav nav = new PromptQualityNav(PromptQualityScreens.MENUS, (count, given) -> counts.get(count),
                scope, locale);
        variables.put(PromptQualityNavAdvice.ATTRIBUTE, nav);
        if ("measure".equals(screen)) {
            List<Tab> tabs = controller.tabs(view, nav, locale, (Long) variables.get("measureId"));
            variables.put("measureTabs", tabs);
            variables.put("viewScripts", List.of());
        }
        return variables;
    }

    private static List<Drawn> tabs(String page) {
        List<Drawn> tabs = new ArrayList<>();
        Matcher tab = VIEW_TAB.matcher(page);
        while (tab.find()) {
            HashMap<String, String> attributes = new HashMap<>();
            Matcher attribute = ATTRIBUTE.matcher(tab.group(1));
            while (attribute.find()) {
                attributes.put(attribute.group(1), attribute.group(2));
            }
            tabs.add(new Drawn(attributes.get("data-view"), attributes.get("data-href"),
                    attributes.get("aria-selected"), tab.group(2)));
        }
        return tabs;
    }

    private String render(String screen, Locale locale, HashMap<String, Object> variables) {
        MockServletContext servletContext = new MockServletContext();
        MockHttpServletRequest request = new MockHttpServletRequest(servletContext);
        var exchange = JakartaServletWebApplication.buildApplication(servletContext)
                .buildExchange(request, new MockHttpServletResponse());
        WebContext context = new WebContext(exchange, locale, variables);
        return engine.process(PromptQualityScreens.TEMPLATES + screen, Set.of("main"), context);
    }

    private static String read(String resource) throws IOException {
        try (InputStream input = PromptQualityScreenTemplateTest.class.getClassLoader().getResourceAsStream(resource)) {
            assertThat(input).as(resource).isNotNull();
            return new String(input.readAllBytes(), StandardCharsets.UTF_8);
        }
    }

    private static ResourceBundleMessageSource messages() {
        ResourceBundleMessageSource messages = new ResourceBundleMessageSource();
        messages.setBasename("contexa/i18n/messages");
        messages.setDefaultEncoding("UTF-8");
        messages.setFallbackToSystemLocale(false);
        return messages;
    }

    private static SpringTemplateEngine engine(ResourceBundleMessageSource messages) {
        ClassLoaderTemplateResolver resolver = new ClassLoaderTemplateResolver();
        resolver.setPrefix("templates/");
        resolver.setSuffix(".html");
        resolver.setTemplateMode(TemplateMode.HTML);
        resolver.setCharacterEncoding("UTF-8");
        SpringTemplateEngine engine = new SpringTemplateEngine();
        engine.setTemplateResolver(resolver);
        engine.setTemplateEngineMessageSource(messages);
        return engine;
    }
}
