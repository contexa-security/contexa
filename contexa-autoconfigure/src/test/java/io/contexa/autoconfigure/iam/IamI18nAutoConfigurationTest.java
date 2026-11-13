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

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.config.BeanDefinition;
import org.springframework.boot.autoconfigure.AutoConfigurations;
import org.springframework.boot.autoconfigure.context.MessageSourceAutoConfiguration;
import org.springframework.boot.autoconfigure.web.servlet.WebMvcAutoConfiguration;
import org.springframework.boot.test.context.assertj.AssertableWebApplicationContext;
import org.springframework.boot.test.context.runner.WebApplicationContextRunner;
import org.springframework.context.MessageSource;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.i18n.LocaleContextHolder;
import org.springframework.context.support.StaticMessageSource;
import org.springframework.core.Ordered;
import org.springframework.mock.web.MockHttpSession;
import org.springframework.stereotype.Controller;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.context.WebApplicationContext;
import org.springframework.web.servlet.LocaleResolver;
import org.springframework.web.servlet.View;
import org.springframework.web.servlet.ViewResolver;
import org.springframework.web.servlet.i18n.AcceptHeaderLocaleResolver;
import org.springframework.web.servlet.i18n.FixedLocaleResolver;
import org.springframework.web.servlet.i18n.SessionLocaleResolver;
import org.springframework.web.servlet.support.RequestContextUtils;

import java.util.Locale;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * Exception tests 2026-11-03 (ownership harness): with Contexa the host application resolved the language of its own
 * requests as Contexa's screens do (a session resolver, Korean by default), so a French request got Korean, the
 * host's own message bundle was not read, and ?lang= on any host URL switched the language of the session.
 * <p>
 * B-7 (2026-11-13): under HOST_OWNED Contexa still put a resolver of its own under Spring MVC's name
 * ({@code localeResolver}), so Spring Boot's stood aside; an application that cast the bean to the class Spring Boot
 * gives it, or counted on Spring Boot having made it, broke. Contexa now adds none there, and its screens are given
 * their language one request at a time.
 */
class IamI18nAutoConfigurationTest {

    private static final String SCREENS_LANGUAGE = "contexaScreensLanguage";

    private final WebApplicationContextRunner runner = new WebApplicationContextRunner()
            .withConfiguration(AutoConfigurations.of(MessageSourceAutoConfiguration.class,
                    IamI18nAutoConfiguration.class, WebMvcAutoConfiguration.class))
            .withUserConfiguration(Pages.class)
            .withPropertyValues("spring.messages.basename=host-messages");

    private MockMvc mvc(AssertableWebApplicationContext context) {
        return MockMvcBuilders.webAppContextSetup((WebApplicationContext) context.getSourceApplicationContext()).build();
    }

    private static BeanDefinition localeResolverDefinition(AssertableWebApplicationContext context) {
        return context.getBeanFactory().getBeanDefinition("localeResolver");
    }

    @Test
    @DisplayName("HOST_OWNED: Contexa makes no language resolver; Spring Boot's accept-header resolver is the application's")
    void hostOwnedLeavesSpringBootsResolver() {
        runner.withPropertyValues("contexa.bridge.ownership=HOST_OWNED").run(context -> {
            assertThat(context).hasNotFailed();
            assertThat(context.getBeansOfType(LocaleResolver.class)).as("the application's resolver only")
                    .containsOnlyKeys("localeResolver");
            assertThat(context.getBean("localeResolver")).isExactlyInstanceOf(AcceptHeaderLocaleResolver.class);
            assertThat(localeResolverDefinition(context).getFactoryBeanName()).as("made by Spring Boot")
                    .startsWith(WebMvcAutoConfiguration.class.getName());
            assertThat(context).hasBean(SCREENS_LANGUAGE);
        });
    }

    @Test
    @DisplayName("HOST_OWNED: the host's own requests keep the language the host would resolve without Contexa")
    void theHostKeepsItsLanguage() {
        runner.withPropertyValues("contexa.bridge.ownership=HOST_OWNED").run(context -> {
            MockMvc mvc = mvc(context);

            mvc.perform(get("/app/locale").header("Accept-Language", "fr-FR")).andExpect(content().string("fr"));
            mvc.perform(get("/app/locale").header("Accept-Language", "en-US")).andExpect(content().string("en"));
            mvc.perform(get("/app/holder").header("Accept-Language", "fr-FR")).andExpect(content().string("fr"));
            mvc.perform(get("/app/greeting").header("Accept-Language", "fr-FR"))
                    .andExpect(content().string("Bonjour de l application hote"));
        });
    }

    @Test
    @DisplayName("HOST_OWNED: ?lang= on a host URL switches nothing, and the host's request does not fail for it")
    void langOnAHostUrlSwitchesNothing() {
        runner.withPropertyValues("contexa.bridge.ownership=HOST_OWNED").run(context -> {
            MockMvc mvc = mvc(context);
            MockHttpSession session = new MockHttpSession();

            mvc.perform(get("/app/locale?lang=de").session(session).header("Accept-Language", "en-US"))
                    .andExpect(status().isOk()).andExpect(content().string("en"));
            mvc.perform(get("/app/locale").session(session).header("Accept-Language", "en-US"))
                    .andExpect(content().string("en"));
        });
    }

    @Test
    @DisplayName("HOST_OWNED: Contexa's own screens keep their Korean default and the ?lang= switch")
    void contexaScreensKeepTheirLanguage() {
        runner.withPropertyValues("contexa.bridge.ownership=HOST_OWNED").run(context -> {
            MockMvc mvc = mvc(context);
            MockHttpSession session = new MockHttpSession();

            mvc.perform(get("/contexa/locale").session(session).header("Accept-Language", "fr-FR"))
                    .andExpect(content().string("ko"));
            mvc.perform(get("/contexa/locale?lang=en").session(session)).andExpect(content().string("en"));
            mvc.perform(get("/contexa/locale").session(session)).andExpect(content().string("en"));
        });
    }

    @Test
    @DisplayName("HOST_OWNED: a screen speaks the browser's language when the screens have it, Korean otherwise, "
            + "in its handler, its messages and its page; the application's pages speak the browser's")
    void aScreenFollowsTheScreensRules() {
        runner.withUserConfiguration(ViewPages.class, LanguageViews.class)
                .withPropertyValues("contexa.bridge.ownership=HOST_OWNED").run(context -> {
                    MockMvc mvc = mvc(context);

                    mvc.perform(get("/contexa/locale").header("Accept-Language", "en-US")).andExpect(content().string("en"));
                    mvc.perform(get("/contexa/locale").header("Accept-Language", "fr-FR")).andExpect(content().string("ko"));
                    mvc.perform(get("/contexa/holder").header("Accept-Language", "fr-FR")).andExpect(content().string("ko"));
                    // the page is looked up in the screens' language, as a Thymeleaf page is written in it
                    mvc.perform(get("/contexa/page").header("Accept-Language", "fr-FR")).andExpect(content().string("ko"));
                    mvc.perform(get("/contexa/page").header("Accept-Language", "en-US")).andExpect(content().string("en"));
                    mvc.perform(get("/app/page").header("Accept-Language", "fr-FR")).andExpect(content().string("fr"));
                });
    }

    @Test
    @DisplayName("HOST_OWNED: the language chosen on a screen serves the screens' handlers, messages and pages, "
            + "and never the application's")
    void aChoiceOnAScreenStaysOnTheScreens() {
        runner.withUserConfiguration(ViewPages.class, LanguageViews.class)
                .withPropertyValues("contexa.bridge.ownership=HOST_OWNED").run(context -> {
                    MockMvc mvc = mvc(context);
                    MockHttpSession session = new MockHttpSession();

                    // the switch runs after the screens are given their resolver, and serves the same request
                    mvc.perform(get("/contexa/holder?lang=en").session(session).header("Accept-Language", "fr-FR"))
                            .andExpect(content().string("en"));
                    assertThat(session.getAttribute(SessionLocaleResolver.LOCALE_SESSION_ATTRIBUTE_NAME))
                            .as("the attribute the sign-in pages read").isEqualTo(Locale.ENGLISH);
                    mvc.perform(get("/contexa/page").session(session).header("Accept-Language", "fr-FR"))
                            .andExpect(content().string("en"));
                    mvc.perform(get("/contexa/locale").session(session).header("Accept-Language", "fr-FR"))
                            .andExpect(content().string("en"));
                    mvc.perform(get("/app/locale").session(session).header("Accept-Language", "fr-FR"))
                            .andExpect(content().string("fr"));
                    mvc.perform(get("/app/page").session(session).header("Accept-Language", "fr-FR"))
                            .andExpect(content().string("fr"));
                });
    }

    @Test
    @DisplayName("HOST_OWNED: under a context path the screens are the requests below it that start with /contexa/")
    void theScreensBelowAContextPath() {
        runner.withPropertyValues("contexa.bridge.ownership=HOST_OWNED").run(context -> {
            MockMvc mvc = mvc(context);

            mvc.perform(get("/shop/contexa/locale").contextPath("/shop").header("Accept-Language", "fr-FR"))
                    .andExpect(content().string("ko"));
            mvc.perform(get("/shop/app/locale").contextPath("/shop").header("Accept-Language", "fr-FR"))
                    .andExpect(content().string("fr"));
        });
    }

    @Test
    @DisplayName("HOST_OWNED: an application on spring.web.locale-resolver=fixed keeps its fixed language; the screens keep theirs")
    void aFixedApplicationLanguageStays() {
        runner.withPropertyValues("contexa.bridge.ownership=HOST_OWNED", "spring.web.locale-resolver=fixed",
                "spring.web.locale=de").run(context -> {
                    assertThat(context.getBean("localeResolver")).isExactlyInstanceOf(FixedLocaleResolver.class);
                    assertThat(localeResolverDefinition(context).getFactoryBeanName())
                            .startsWith(WebMvcAutoConfiguration.class.getName());
                    MockMvc mvc = mvc(context);
                    MockHttpSession session = new MockHttpSession();

                    mvc.perform(get("/app/locale").header("Accept-Language", "fr-FR")).andExpect(content().string("de"));
                    mvc.perform(get("/app/holder").header("Accept-Language", "en-US")).andExpect(content().string("de"));
                    mvc.perform(get("/contexa/locale").header("Accept-Language", "fr-FR")).andExpect(content().string("ko"));
                    mvc.perform(get("/contexa/locale?lang=en").session(session)).andExpect(content().string("en"));
                    mvc.perform(get("/app/locale").session(session).header("Accept-Language", "en-US"))
                            .andExpect(content().string("de"));
                });
    }

    @Test
    @DisplayName("the host's message bundle and Contexa's both resolve, whichever of them the host's source is")
    void bothBundlesResolve() {
        runner.withPropertyValues("contexa.bridge.ownership=HOST_OWNED").run(context -> {
            MessageSource messages = context.getBean(MessageSource.class);

            assertThat(messages.getMessage("host.greeting", null, Locale.ENGLISH)).isEqualTo("Hello from the host application");
            assertThat(messages.getMessage("zerotrust.stepup.back", null, "missing", Locale.ENGLISH))
                    .as("a text of Contexa's screens, not shown as a missing key").isNotEqualTo("missing");
            assertThat(messages.getMessage("zerotrust.stepup.back", null, "missing", Locale.KOREAN))
                    .isNotEqualTo(messages.getMessage("zerotrust.stepup.back", null, "missing", Locale.ENGLISH));
        });
        runner.withPropertyValues("contexa.bridge.ownership=CONTEXA_OWNED").run(context -> {
            MessageSource messages = context.getBean(MessageSource.class);

            assertThat(messages.getMessage("host.greeting", null, Locale.ENGLISH)).isEqualTo("Hello from the host application");
            assertThat(messages.getMessage("zerotrust.stepup.back", null, "missing", Locale.ENGLISH)).isNotEqualTo("missing");
        });
    }

    @Test
    @DisplayName("without a bundle of its own the host gets Contexa's source, as before")
    void withoutAHostBundle() {
        new WebApplicationContextRunner()
                .withConfiguration(AutoConfigurations.of(MessageSourceAutoConfiguration.class,
                        IamI18nAutoConfiguration.class, WebMvcAutoConfiguration.class))
                .withPropertyValues("contexa.bridge.ownership=HOST_OWNED", "spring.messages.basename=no-such-bundle")
                .run(context -> assertThat(context.getBean(MessageSource.class)
                        .getMessage("zerotrust.stepup.back", null, "missing", Locale.ENGLISH)).isNotEqualTo("missing"));
    }

    @Test
    @DisplayName("a host whose only message source goes by another name: Contexa's texts resolve, the host's is as it was")
    void aHostSourceUnderAnotherName() {
        new WebApplicationContextRunner()
                .withConfiguration(AutoConfigurations.of(MessageSourceAutoConfiguration.class,
                        IamI18nAutoConfiguration.class, WebMvcAutoConfiguration.class))
                .withBean("auditMessages", MessageSource.class, StaticMessageSource::new)
                .withPropertyValues("contexa.bridge.ownership=HOST_OWNED", "spring.messages.basename=no-such-bundle")
                .run(context -> {
                    assertThat(context).hasNotFailed();
                    assertThat(context.getMessage("zerotrust.stepup.back", null, Locale.ENGLISH))
                            .as("the context's own source is what Contexa's screens are given")
                            .isNotEqualTo("zerotrust.stepup.back");
                    assertThat(context.getBean("auditMessages", StaticMessageSource.class).getParentMessageSource())
                            .as("the host's own source is not touched").isNull();
                    assertThat(context.getBeansOfType(MessageSource.class).values())
                            .as("no message source is added to those the host can be given by type")
                            .noneMatch(source -> source instanceof IamI18nAutoConfiguration.ContexaMessageSource);
                });
    }

    @Test
    @DisplayName("HOST_OWNED: a language resolver of the host's own stays, for its pages and the screens, and ?lang= on a screen does not fail")
    void aHostResolverStays() {
        runner.withUserConfiguration(HostResolver.class).withPropertyValues("contexa.bridge.ownership=HOST_OWNED")
                .run(context -> {
                    assertThat(context.getBean("localeResolver")).isExactlyInstanceOf(FixedLocaleResolver.class);
                    assertThat(context).doesNotHaveBean(SCREENS_LANGUAGE);
                    MockMvc mvc = mvc(context);

                    mvc.perform(get("/app/locale").header("Accept-Language", "fr-FR")).andExpect(content().string("de"));
                    mvc.perform(get("/contexa/locale").header("Accept-Language", "fr-FR"))
                            .andExpect(content().string("de"));
                    mvc.perform(get("/contexa/locale?lang=en")).andExpect(status().isOk());
                });
    }

    @Test
    @DisplayName("CONTEXA_OWNED keeps what it did: Contexa's session resolver is the language of the whole application")
    void contexaOwnedIsUnchanged() {
        runner.withPropertyValues("contexa.bridge.ownership=CONTEXA_OWNED").run(context -> {
            assertThat(context.getBean("localeResolver")).isExactlyInstanceOf(SessionLocaleResolver.class);
            assertThat(localeResolverDefinition(context).getFactoryBeanName())
                    .startsWith(IamI18nAutoConfiguration.class.getName());
            assertThat(context).doesNotHaveBean(SCREENS_LANGUAGE);
            MockMvc mvc = mvc(context);

            mvc.perform(get("/app/locale").header("Accept-Language", "fr-FR")).andExpect(content().string("ko"));
            mvc.perform(get("/app/locale?lang=de")).andExpect(content().string("de"));
        });
    }

    @RestController
    static class Pages {

        private final MessageSource messages;

        Pages(MessageSource messages) {
            this.messages = messages;
        }

        @GetMapping({"/app/locale", "/contexa/locale"})
        String locale(HttpServletRequest request) {
            return RequestContextUtils.getLocale(request).getLanguage();
        }

        @GetMapping({"/app/holder", "/contexa/holder"})
        String holder() {
            return LocaleContextHolder.getLocale().getLanguage();
        }

        @GetMapping("/app/greeting")
        String greeting(HttpServletRequest request) {
            return messages.getMessage("host.greeting", null, RequestContextUtils.getLocale(request));
        }
    }

    /** Pages rendered by a view, as Contexa's Thymeleaf screens are. */
    @Controller
    static class ViewPages {

        @GetMapping({"/app/page", "/contexa/page"})
        String page() {
            return "page";
        }
    }

    @Configuration(proxyBeanMethods = false)
    static class LanguageViews {

        @Bean
        ViewResolver languageViewResolver() {
            return new LanguageViewResolver();
        }
    }

    /** Gives every view the language it is looked up with, as Thymeleaf's resolver does. */
    static final class LanguageViewResolver implements ViewResolver, Ordered {

        @Override
        public View resolveViewName(String viewName, Locale locale) {
            return "page".equals(viewName) ? new LanguageView(locale) : null;
        }

        @Override
        public int getOrder() {
            return Ordered.HIGHEST_PRECEDENCE;
        }
    }

    /** A page written in the language of its view, as a Thymeleaf page is: it shows that language. */
    record LanguageView(Locale locale) implements View {

        @Override
        public String getContentType() {
            return "text/plain;charset=UTF-8";
        }

        @Override
        public void render(Map<String, ?> model, HttpServletRequest request, HttpServletResponse response) throws Exception {
            response.setContentType(getContentType());
            response.getWriter().write(locale.getLanguage());
        }
    }

    @Configuration(proxyBeanMethods = false)
    static class HostResolver {

        @Bean
        LocaleResolver localeResolver() {
            return new FixedLocaleResolver(Locale.GERMAN);
        }
    }
}
