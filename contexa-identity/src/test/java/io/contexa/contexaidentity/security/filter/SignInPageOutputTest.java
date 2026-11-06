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
package io.contexa.contexaidentity.security.filter;

import io.contexa.contexacommon.enums.AuthType;
import io.contexa.contexacommon.properties.AuthContextProperties;
import io.contexa.contexaidentity.security.core.config.AuthenticationFlowConfig;
import io.contexa.contexaidentity.security.core.config.AuthenticationStepConfig;
import io.contexa.contexaidentity.security.core.dsl.option.AuthenticationProcessingOptions;
import io.contexa.contexaidentity.security.core.dsl.option.FormOptions;
import io.contexa.contexaidentity.security.core.dsl.option.RestOptions;
import io.contexa.contexaidentity.security.core.mfa.options.PrimaryAuthenticationOptions;
import io.contexa.contexaidentity.security.filter.handler.MfaStateMachineIntegrator;
import io.contexa.contexaidentity.security.service.AuthUrlProvider;
import jakarta.servlet.Filter;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.context.ApplicationContext;
import org.springframework.core.io.Resource;
import org.springframework.core.io.support.PathMatchingResourcePatternResolver;
import org.springframework.mock.web.MockFilterChain;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.web.csrf.CsrfToken;
import org.springframework.security.web.csrf.DefaultCsrfToken;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/**
 * The sign-in pages are open to anyone. What the server or the network answers (a message, a support contact, an
 * error) reaches them as text: no script of these pages builds markup out of a value.
 */
class SignInPageOutputTest {

    private static final Pattern INLINE_SCRIPT = Pattern.compile("<script>(.*?)</script>", Pattern.DOTALL);
    private static final Pattern MARKUP_WRITE = Pattern.compile("\\.(?:innerHTML|outerHTML)\\s*=|insertAdjacentHTML\\(|document\\.write\\(");
    /** The one value the SDK writes into its own page: wording bundled in the SDK itself. */
    private static final Pattern BUNDLED_WORDING = Pattern.compile("\\$\\{__ContexaMfaI18n\\.\\w+}");
    /** A string written once in the script: quoted, or a template with nothing left to fill. */
    private static final Pattern FIXED_MARKUP = Pattern.compile("'[^'\\\\]*'|\"[^\"\\\\]*\"|`[^`$\\\\]*`", Pattern.DOTALL);

    private final AuthContextProperties properties = new AuthContextProperties();
    private final AuthUrlProvider urls = new AuthUrlProvider(properties);

    @Test
    @DisplayName("the default form sign-in page writes every message as text, keeping the line before the contact")
    void theFormSignInPageWritesMessagesAsText() throws Exception {
        FormOptions form = FormOptions.builderForMfa(context()).build();
        PrimaryAuthenticationOptions primary = mock(PrimaryAuthenticationOptions.class);
        when(primary.isFormLogin()).thenReturn(true);
        when(primary.getFormOptions()).thenReturn(form);

        String page = render(mfaPages(primary), urls.getPrimaryLoginPage());

        assertThat(page).contains("id=\"loginButton\"");
        assertThat(markupBuiltFromValues("form sign-in page", inlineScripts(page))).isEmpty();
        assertThat(page).contains("error.message", "supportContact", "createElement('br')");
    }

    @Test
    @DisplayName("the default REST sign-in page of the MFA flow writes every message as text")
    void theMfaRestSignInPageWritesMessagesAsText() throws Exception {
        RestOptions rest = RestOptions.builderForMfa(context()).build();
        PrimaryAuthenticationOptions primary = mock(PrimaryAuthenticationOptions.class);
        when(primary.isRestLogin()).thenReturn(true);
        when(primary.getRestOptions()).thenReturn(rest);

        String page = render(mfaPages(primary), urls.getPrimaryLoginPage());

        assertThat(page).contains("id=\"loginButton\"");
        assertThat(markupBuiltFromValues("REST sign-in page", inlineScripts(page))).isEmpty();
        assertThat(page).contains("error.message", "supportContact", "createElement('br')");
    }

    @Test
    @DisplayName("the default REST sign-in page writes the server's message as text")
    void theRestSignInPageWritesMessagesAsText() throws Exception {
        String page = render(new DefaultRestLoginPageGeneratingFilter("/api/login"), "/api/login");

        assertThat(page).contains("id=\"loginButton\"");
        assertThat(markupBuiltFromValues("REST login page", inlineScripts(page))).isEmpty();
        assertThat(page).contains("error.message");
    }

    @Test
    @DisplayName("the shipped sign-in and MFA scripts build no markup out of a value")
    void theShippedScriptsBuildNoMarkupFromValues() throws IOException {
        Resource[] scripts = new PathMatchingResourcePatternResolver().getResources("classpath*:static/js/contexa-*.js");
        assertThat(scripts).extracting(Resource::getFilename)
                .contains("contexa-login-page.js", "contexa-mfa-sdk.js", "contexa-ott-verify-page.js", "contexa-passkey-page.js");

        List<String> offenders = new ArrayList<>();
        for (Resource script : scripts) {
            offenders.addAll(markupBuiltFromValues(script.getFilename(),
                    List.of(script.getContentAsString(StandardCharsets.UTF_8))));
        }

        assertThat(offenders).isEmpty();
    }

    /** Each write of markup whose value is anything but a fixed string or a template of bundled wording. */
    private static List<String> markupBuiltFromValues(String where, List<String> scripts) {
        List<String> found = new ArrayList<>();
        for (String code : scripts) {
            Matcher write = MARKUP_WRITE.matcher(code);
            while (write.find()) {
                Expression value = Expression.after(code, write.end());
                if (value.joins() || !FIXED_MARKUP.matcher(BUNDLED_WORDING.matcher(value.text().strip()).replaceAll("")).matches()) {
                    found.add(where + ": " + value.text().strip().lines().findFirst().orElse(""));
                }
            }
        }
        return found;
    }

    private static List<String> inlineScripts(String page) {
        List<String> scripts = new ArrayList<>();
        Matcher matcher = INLINE_SCRIPT.matcher(page);
        while (matcher.find()) {
            scripts.add(matcher.group(1));
        }
        assertThat(scripts).isNotEmpty();
        return scripts;
    }

    private DefaultMfaPageGeneratingFilter mfaPages(PrimaryAuthenticationOptions primary) {
        AuthenticationFlowConfig flow = AuthenticationFlowConfig.builder("mfa")
                .primaryAuthenticationOptions(primary)
                .stepConfigs(List.of(
                        new AuthenticationStepConfig("mfa", AuthType.MFA_FORM.name(), 0, true),
                        new AuthenticationStepConfig("mfa", AuthType.MFA_OTT.name(), 1, false)))
                .registeredFactorOptions(Map.of(AuthType.MFA_OTT, mock(AuthenticationProcessingOptions.class)))
                .build();
        return new DefaultMfaPageGeneratingFilter(flow, mock(MfaStateMachineIntegrator.class), urls,
                properties.getMfa(), "sessionStorage", true);
    }

    private ApplicationContext context() {
        ApplicationContext context = mock(ApplicationContext.class);
        when(context.getBean(AuthUrlProvider.class)).thenReturn(urls);
        return context;
    }

    private static String render(Filter filter, String path) throws Exception {
        MockHttpServletRequest request = new MockHttpServletRequest("GET", path);
        request.setAttribute(CsrfToken.class.getName(), new DefaultCsrfToken("X-CSRF-TOKEN", "_csrf", "csrf-token"));
        MockHttpServletResponse response = new MockHttpServletResponse();
        MockFilterChain chain = new MockFilterChain();

        filter.doFilter(request, response, chain);

        assertThat(chain.getRequest()).as("the page is drawn, not passed on").isNull();
        return response.getContentAsString();
    }

    /** The value assigned up to its closing semicolon, and whether it joins anything with {@code +} outside a quote. */
    private record Expression(String text, boolean joins) {

        static Expression after(String code, int from) {
            char quote = 0;
            boolean joins = false;
            int i = from;
            for (; i < code.length(); i++) {
                char c = code.charAt(i);
                if (quote != 0) {
                    if (c == '\\') {
                        i++;
                    } else if (c == quote) {
                        quote = 0;
                    }
                } else if (c == '\'' || c == '"' || c == '`') {
                    quote = c;
                } else if (c == '+') {
                    joins = true;
                } else if (c == ';') {
                    break;
                }
            }
            return new Expression(code.substring(from, i), joins);
        }
    }
}
