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
package io.contexa.contexaidentity.security.core.adapter.auth;

import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.web.authentication.ui.DefaultLoginPageGeneratingFilter;

import java.util.concurrent.atomic.AtomicBoolean;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/**
 * A form flow in the token state answers its failures with a Contexa handler, and Spring then leaves its generated
 * login page without an error address: a failed page sign-in was sent to /login?error and got a 404 (D-A2).
 */
class LoginPageErrorAddressTest {

    @Test
    void theGeneratedPageAnswersItsErrorAddressOnceItIsTold() throws Exception {
        DefaultLoginPageGeneratingFilter page = new DefaultLoginPageGeneratingFilter();
        page.setFormLoginEnabled(true);
        page.setLoginPageUrl("/login");
        page.setAuthenticationUrl("/login");
        page.setUsernameParameter("username");
        page.setPasswordParameter("password");
        HttpSecurity http = mock(HttpSecurity.class);
        when(http.getSharedObject(DefaultLoginPageGeneratingFilter.class)).thenReturn(page);

        assertThat(rendered(page, "/login", "error")).as("before: no page of it").isNull();

        new LoginPageErrorAddress("/login?error").configure(http);

        assertThat(rendered(page, "/login", "error")).contains("Invalid credentials");
        assertThat(rendered(page, "/login", null)).doesNotContain("Invalid credentials");
    }

    @Test
    void aChainWithoutAGeneratedPageIsLeftAsItIs() {
        HttpSecurity http = mock(HttpSecurity.class);

        new LoginPageErrorAddress("/login?error").configure(http);
    }

    /** The page the filter rendered, or null when it passed the request on. */
    private static String rendered(DefaultLoginPageGeneratingFilter page, String path, String query) throws Exception {
        MockHttpServletRequest request = new MockHttpServletRequest("GET", path);
        request.setServletPath(path);
        request.setQueryString(query);
        if (query != null) {
            request.setParameter(query, "");
        }
        MockHttpServletResponse response = new MockHttpServletResponse();
        AtomicBoolean passedOn = new AtomicBoolean();
        page.doFilter(request, response, (req, res) -> passedOn.set(true));
        return passedOn.get() ? null : response.getContentAsString();
    }
}
