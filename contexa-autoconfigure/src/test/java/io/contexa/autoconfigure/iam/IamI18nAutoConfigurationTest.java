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
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.boot.autoconfigure.AutoConfigurations;
import org.springframework.boot.autoconfigure.context.MessageSourceAutoConfiguration;
import org.springframework.boot.autoconfigure.web.servlet.WebMvcAutoConfiguration;
import org.springframework.boot.test.context.assertj.AssertableWebApplicationContext;
import org.springframework.boot.test.context.runner.WebApplicationContextRunner;
import org.springframework.context.MessageSource;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.mock.web.MockHttpSession;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.context.WebApplicationContext;
import org.springframework.web.servlet.LocaleResolver;
import org.springframework.web.servlet.i18n.FixedLocaleResolver;
import org.springframework.web.servlet.support.RequestContextUtils;

import java.util.Locale;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * Exception tests 2026-11-03 (ownership harness): with Contexa the host application resolved the language of its own
 * requests as Contexa's screens do (a session resolver, Korean by default), so a French request got Korean, the
 * host's own message bundle was not read, and ?lang= on any host URL switched the language of the session.
 */
class IamI18nAutoConfigurationTest {

    private final WebApplicationContextRunner runner = new WebApplicationContextRunner()
            .withConfiguration(AutoConfigurations.of(MessageSourceAutoConfiguration.class,
                    IamI18nAutoConfiguration.class, WebMvcAutoConfiguration.class))
            .withUserConfiguration(Pages.class)
            .withPropertyValues("spring.messages.basename=host-messages");

    private MockMvc mvc(AssertableWebApplicationContext context) {
        return MockMvcBuilders.webAppContextSetup((WebApplicationContext) context.getSourceApplicationContext()).build();
    }

    @Test
    @DisplayName("HOST_OWNED: the host's own requests keep the language the host would resolve without Contexa")
    void theHostKeepsItsLanguage() {
        runner.withPropertyValues("contexa.bridge.ownership=HOST_OWNED").run(context -> {
            MockMvc mvc = mvc(context);

            mvc.perform(get("/app/locale").header("Accept-Language", "fr-FR")).andExpect(content().string("fr"));
            mvc.perform(get("/app/locale").header("Accept-Language", "en-US")).andExpect(content().string("en"));
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
    @DisplayName("HOST_OWNED: a language resolver of the host's own stays, for its pages and the screens, and ?lang= on a screen does not fail")
    void aHostResolverStays() {
        runner.withUserConfiguration(HostResolver.class).withPropertyValues("contexa.bridge.ownership=HOST_OWNED")
                .run(context -> {
                    MockMvc mvc = mvc(context);

                    mvc.perform(get("/app/locale").header("Accept-Language", "fr-FR")).andExpect(content().string("de"));
                    mvc.perform(get("/contexa/locale").header("Accept-Language", "fr-FR"))
                            .andExpect(content().string("de"));
                    mvc.perform(get("/contexa/locale?lang=en")).andExpect(status().isOk());
                });
    }

    @Test
    @DisplayName("CONTEXA_OWNED keeps what it did: Contexa resolves the language of the whole application")
    void contexaOwnedIsUnchanged() {
        runner.withPropertyValues("contexa.bridge.ownership=CONTEXA_OWNED").run(context -> {
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

        @GetMapping("/app/greeting")
        String greeting(HttpServletRequest request) {
            return messages.getMessage("host.greeting", null, RequestContextUtils.getLocale(request));
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
