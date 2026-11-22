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
package io.contexa.contexaiam.admin.promptquality.version;

import io.contexa.contexaiam.admin.promptquality.screen.PromptQualityNav;
import io.contexa.contexaiam.admin.promptquality.screen.PromptQualityNavAdvice;
import io.contexa.contexaiam.admin.promptquality.screen.PromptQualityScreens;
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
import java.util.HashMap;
import java.util.List;
import java.util.Locale;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Quality plan 3.8 and the approved mockup (second round): the four prompt version screens (the list, a version, a new
 * version, the advanced screen) stand under the menu bar of the prompt quality assurance group with the versions lit
 * instead of the tabs they had; the trials are no tab any more; the list opens the advanced screen from a button in
 * its title row, and the advanced screen has the way back to the list above its title; in Korean and in English.
 */
class PromptVersionScreensTemplateTest {

    private static final Pattern TAB = Pattern.compile("(?s)<a\\s([^>]*data-pqa-tab=\"[^\"]*\"[^>]*)>");
    private static final Pattern KEY = Pattern.compile("data-pqa-tab=\"([^\"]*)\"");
    private static final Pattern ADVANCED = Pattern.compile("(?s)<a\\s[^>]*id=\"pv-advanced\"[^>]*>.*?</a>");
    private static final Pattern CRUMBS = Pattern.compile("(?s)<nav class=\"pv-crumbs\" id=\"pv-crumbs\"[^>]*>(.*?)</nav>");
    private static final List<String> SCREENS = List.of("list", "version", "new", "advanced");

    private final SpringTemplateEngine engine = engine();

    @Test
    void everyVersionScreenStandsUnderTheMenuBarWithTheVersionsLitAndNoTabsOfItsOwn() {
        for (Locale locale : List.of(Locale.KOREAN, Locale.ENGLISH)) {
            for (String screen : SCREENS) {
                String page = render(screen, locale);

                assertThat(tabs(page)).as(screen).containsExactly("cases", "measure", "versions", "evidence");
                assertThat(page).as(screen)
                        .containsPattern("<a\\s[^>]*class=\"pc-tab-btn active\"[^>]*data-pqa-tab=\"versions\""
                                + "[^>]*aria-current=\"page\"")
                        .doesNotContain("data-pv-tab", "/versions/trials")
                        .contains("data-measure-base=\"/contexa/admin/prompt-quality/measure\"")
                        .contains("id=\"pv-confirm-overlay\"");
            }
        }
    }

    @Test
    void theListOpensTheAdvancedScreenFromItsTitleRowInKoreanAndEnglish() {
        String korean = advancedButton(render("list", Locale.KOREAN));
        String english = advancedButton(render("list", Locale.ENGLISH));

        assertThat(korean).contains("class=\"modern-btn-secondary\"", "data-pv-action=\"advanced\"",
                "href=\"/contexa/admin/prompt-quality/versions/advanced\"",
                "title=\"먼저 적용, 함께 시험, 급히 되돌리기, 문서 폴더와 가져오기, 기록\"",
                "<i class=\"fas fa-sliders-h\" aria-hidden=\"true\"></i>", "<span>고급</span>");
        assertThat(english).contains("title=\"Canary, running alongside, emergency rollback, the document folder and"
                + " import, the history\"", "<span>Advanced</span>");
        for (String screen : List.of("version", "new", "advanced")) {
            assertThat(render(screen, Locale.KOREAN)).as(screen).doesNotContain("id=\"pv-advanced\"");
        }
    }

    @Test
    void theAdvancedScreenHasTheWayBackToTheListAboveItsTitle() {
        String korean = crumbs(render("advanced", Locale.KOREAN));
        String english = crumbs(render("advanced", Locale.ENGLISH));

        assertThat(korean).contains("<a class=\"zt-link\" href=\"/contexa/admin/prompt-quality/versions\""
                + " data-pv-crumb=\"list\">프롬프트 버전</a>", "<span class=\"zt-muted\"> › 고급</span>");
        assertThat(english).contains(">Prompt versions</a>", "<span class=\"zt-muted\"> › Advanced</span>");
        // The list has no way back; a version and the new version screen draw theirs with the version's name.
        assertThat(crumbs(render("list", Locale.KOREAN))).isBlank();
        assertThat(crumbs(render("version", Locale.KOREAN))).isBlank();
    }

    private static List<String> tabs(String page) {
        List<String> keys = new ArrayList<>();
        Matcher tab = TAB.matcher(page);
        while (tab.find()) {
            Matcher key = KEY.matcher(tab.group(1));
            keys.add(key.find() ? key.group(1) : null);
        }
        return keys;
    }

    private static String advancedButton(String page) {
        Matcher button = ADVANCED.matcher(page);
        assertThat(button.find()).as("the advanced button").isTrue();
        return button.group();
    }

    private static String crumbs(String page) {
        Matcher crumbs = CRUMBS.matcher(page);
        assertThat(crumbs.find()).as("the way back").isTrue();
        return crumbs.group(1);
    }

    private String render(String screen, Locale locale) {
        MockServletContext servletContext = new MockServletContext();
        MockHttpServletRequest request = new MockHttpServletRequest(servletContext);
        var exchange = JakartaServletWebApplication.buildApplication(servletContext)
                .buildExchange(request, new MockHttpServletResponse());
        HashMap<String, Object> variables = new HashMap<>();
        variables.put("screen", screen);
        variables.put("apiBase", "/contexa/admin/api/prompt-quality/versions");
        variables.put("pagesBase", PromptQualityScreens.VERSIONS);
        variables.put("measureBase", PromptQualityScreens.MEASURE);
        variables.put("scriptMessagesJson", "{}");
        variables.put(PromptQualityNavAdvice.ATTRIBUTE, new PromptQualityNav(PromptQualityScreens.MENUS,
                (count, scope) -> 2L, null, locale));
        WebContext context = new WebContext(exchange, locale, variables);
        // The template breaks long tags over lines; the page is read with its white space as one blank.
        return engine.process("contexa/admin/prompt-version/" + screen, Set.of("main"), context)
                .replaceAll("\\s+", " ").replace(" >", ">");
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
