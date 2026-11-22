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
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Locale;
import java.util.Properties;
import java.util.Set;
import java.util.TreeSet;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Quality plan 3.6 to 3.8: the state of quality and the sealed evidence draw their title, their question and the menu
 * bar of the group with their own menu lit up, in Korean and in English; the frame their scripts draw in (the band with
 * the period, the notices, the confirmation), the data their scripts read, and their scripts with the version of the
 * files; without the bar's data they draw no bar. Every word their scripts name is in both languages.
 */
class PromptQualityStatusEvidenceTemplateTest {

    private static final Pattern TAB = Pattern.compile("(?s)<a\\s([^>]*data-pqa-tab=\"([^\"]*)\"[^>]*)>");
    private static final Pattern SCRIPT = Pattern.compile("<script src=\"([^\"]*)\"></script>");

    private final SpringTemplateEngine engine = engine();

    @Test
    void theStateOfQualityDrawsItsFrameWithItsMenuLitInBothLanguages() {
        String korean = render("status", Locale.KOREAN, true, null);
        assertThat(korean).contains("id=\"pv-title\">품질 현황</h1>")
                .contains("지금 판정에 쓰는 프롬프트가 얼마나 맞히는지, 무엇을 확인해야 하는지 봅니다.")
                .contains("data-api-base=\"/contexa/admin/api/prompt-quality/status\"")
                .contains("id=\"zt-period\"", "id=\"zt-band\"", "id=\"pqa-notice\"", "id=\"pqa-confirm-overlay\"",
                        "id=\"zt-messages\"", "id=\"pqa-paths\"", "class=\"zt-toolbar\"");
        assertThat(tabs(korean)).containsExactly("status*", "cases", "measure", "versions", "evidence");
        assertThat(scripts(korean)).containsExactly("/contexa/js/admin/zero-trust/console-common.js?v=20261118-k119",
                "/contexa/js/admin/prompt-quality/pqa-parts.js?v=20261122-s3",
                "/contexa/js/admin/prompt-quality/status.js?v=20261122-s3");

        String english = render("status", Locale.ENGLISH, true, null);
        assertThat(english).contains("id=\"pv-title\">Quality</h1>")
                .contains("How right the prompt in use is, and what there is to check.");
        assertThat(tabs(english)).containsExactly("status*", "cases", "measure", "versions", "evidence");
    }

    @Test
    void theSealedEvidenceDrawsItsListAndADecisionWithItsMenuLitInBothLanguages() {
        String list = render("evidence", Locale.KOREAN, true, null);
        assertThat(list).contains("id=\"pv-title\">봉인 증거</h1>")
                .contains("판정에 들어간 프롬프트와 사실, 답을 봉인해 둔 기록입니다.")
                .contains("data-api-base=\"/contexa/admin/api/prompt-quality/evidence\"")
                .contains("data-pages-base=\"/contexa/admin/prompt-quality/evidence\"")
                .contains("data-inspection-api=\"/contexa/admin/api/prompt-inspection\"")
                .contains("data-replay-api=\"/contexa/admin/api/sealed-decisions\"")
                .contains("id=\"zt-period\"", "id=\"zt-band\"", "id=\"pqa-notice\"", "id=\"pqa-confirm-overlay\"")
                .doesNotContain("data-package-id=");
        assertThat(tabs(list)).containsExactly("status", "cases", "measure", "versions", "evidence*");
        assertThat(scripts(list)).containsExactly("/contexa/js/admin/zero-trust/console-common.js?v=20261118-k119",
                "/contexa/js/admin/prompt-quality/pqa-parts.js?v=20261122-s3",
                "/contexa/js/admin/prompt-quality/evidence.js?v=20261122-s3");

        String decision = render("evidence", Locale.ENGLISH, true, "3f2b-91c0");
        assertThat(decision).contains("id=\"pv-title\">Sealed evidence</h1>")
                .contains("The prompt, the facts and the answer of a decision, sealed as they were.")
                .contains("data-package-id=\"3f2b-91c0\"");
        assertThat(tabs(decision)).containsExactly("status", "cases", "measure", "versions", "evidence*");
    }

    @Test
    void withoutTheDataOfTheBarNoBarIsDrawn() {
        for (String screen : List.of("status", "evidence")) {
            assertThat(render(screen, Locale.ENGLISH, false, null)).doesNotContain("data-pqa-tab", "pc-tab-nav")
                    .contains("id=\"zt-content\"");
        }
    }

    /** Every word of the two screens, the report button and the two menus is in both bundles and translated. */
    @Test
    void everyWordOfTheScreensIsInBothLanguages() throws IOException {
        Properties english = properties("contexa/i18n/messages.properties");
        Properties korean = properties("contexa/i18n/messages_ko.properties");
        Set<String> englishKeys = keys(english);
        Set<String> koreanKeys = keys(korean);

        assertThat(englishKeys).hasSizeGreaterThan(250).isEqualTo(koreanKeys);
        assertThat(englishKeys).filteredOn(key -> english.getProperty(key).isBlank()).isEmpty();
        List<String> untranslated = new ArrayList<>();
        for (String key : englishKeys) {
            String text = english.getProperty(key);
            if (text.equals(korean.getProperty(key)) && text.matches(".*[A-Za-z]{3,}.*")) {
                untranslated.add(key);
            }
        }
        assertThat(untranslated).as("translated").isEmpty();
        for (String key : List.of("menu.pqa.status", "menu.pqa.evidence")) {
            assertThat(english.getProperty(key)).as(key).isNotBlank().isNotEqualTo(korean.getProperty(key));
        }
        // The glossary says what the daily sample holds now: stopped decisions at random, allowed ones by risk and
        // at random (quality plan 3.6).
        assertThat(korean.getProperty("zt.console.glossary.review.help")).doesNotContain("멈춘 판정에서 매일 무작위로 뽑음")
                .contains("허용 판정");
        assertThat(english.getProperty("zt.console.glossary.review.help"))
                .doesNotContain("a random sample of stopped decisions each day").contains("allowed decisions");
    }

    private static Set<String> keys(Properties bundle) {
        Set<String> keys = new TreeSet<>();
        for (String key : bundle.stringPropertyNames()) {
            if (key.startsWith("pqa.status.") || key.startsWith("pqa.evidence.") || key.startsWith("pqa.report.ui.")) {
                keys.add(key);
            }
        }
        return keys;
    }

    /** The menus of the bar in their order, the lit one marked with a star. */
    private static List<String> tabs(String page) {
        List<String> tabs = new ArrayList<>();
        Matcher tab = TAB.matcher(page);
        while (tab.find()) {
            tabs.add(tab.group(2) + (tab.group(1).contains("aria-current=\"page\"") ? "*" : ""));
        }
        return tabs;
    }

    private static List<String> scripts(String page) {
        List<String> scripts = new ArrayList<>();
        Matcher script = SCRIPT.matcher(page);
        while (script.find()) {
            scripts.add(script.group(1));
        }
        return scripts;
    }

    private String render(String screen, Locale locale, boolean bar, String packageId) {
        MockServletContext servletContext = new MockServletContext();
        MockHttpServletRequest request = new MockHttpServletRequest(servletContext);
        var exchange = JakartaServletWebApplication.buildApplication(servletContext)
                .buildExchange(request, new MockHttpServletResponse());
        HashMap<String, Object> variables = new HashMap<>();
        variables.put("screen", screen);
        if ("status".equals(screen)) {
            variables.put("apiBase", "/contexa/admin/api/prompt-quality/status");
            variables.put("pathsJson", "{}");
        }
        else {
            variables.put("apiBase", "/contexa/admin/api/prompt-quality/evidence");
            variables.put("pagesBase", PromptQualityScreens.EVIDENCE);
            variables.put("inspectionApi", "/contexa/admin/api/prompt-inspection");
            variables.put("replayApi", "/contexa/admin/api/sealed-decisions");
            variables.put("packageId", packageId);
        }
        variables.put("scriptMessagesJson", "{}");
        if (bar) {
            variables.put(PromptQualityNavAdvice.ATTRIBUTE, new PromptQualityNav(PromptQualityScreens.MENUS,
                    (count, scope) -> 3L, null, locale));
        }
        WebContext context = new WebContext(exchange, locale, variables);
        return engine.process(PromptQualityScreens.TEMPLATES + screen, Set.of("main"), context)
                + engine.process(PromptQualityScreens.TEMPLATES + screen, Set.of("script"), context);
    }

    private static Properties properties(String resource) throws IOException {
        Properties properties = new Properties();
        try (InputStream input = PromptQualityStatusEvidenceTemplateTest.class.getClassLoader()
                .getResourceAsStream(resource)) {
            assertThat(input).as(resource).isNotNull();
            properties.load(new InputStreamReader(input, StandardCharsets.UTF_8));
        }
        return properties;
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
