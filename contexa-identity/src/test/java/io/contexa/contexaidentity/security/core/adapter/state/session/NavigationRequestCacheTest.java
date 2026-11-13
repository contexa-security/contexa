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
package io.contexa.contexaidentity.security.core.adapter.state.session;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.context.support.StaticApplicationContext;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.web.savedrequest.HttpSessionRequestCache;
import org.springframework.security.web.savedrequest.NullRequestCache;
import org.springframework.security.web.savedrequest.RequestCache;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

class NavigationRequestCacheTest {

    private static final String BROWSER = "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8";

    private final NavigationRequestCache cache = new NavigationRequestCache(new HttpSessionRequestCache());

    @Test
    @DisplayName("A client that keeps no cookie and asks for no page leaves no session behind")
    void aClientWithoutCookiesLeavesNoSession() {
        MockHttpServletRequest anything = anonymousGet("*/*");
        MockHttpServletRequest json = anonymousGet("application/json");
        MockHttpServletRequest silent = anonymousGet(null);

        cache.saveRequest(anything, new MockHttpServletResponse());
        cache.saveRequest(json, new MockHttpServletResponse());
        cache.saveRequest(silent, new MockHttpServletResponse());

        assertThat(anything.getSession(false)).isNull();
        assertThat(json.getSession(false)).isNull();
        assertThat(silent.getSession(false)).isNull();
    }

    @Test
    @DisplayName("A browser asking for a page is returned to it after sign-in")
    void aBrowserIsReturnedToItsPage() {
        MockHttpServletRequest request = anonymousGet(BROWSER);
        MockHttpServletResponse response = new MockHttpServletResponse();

        cache.saveRequest(request, response);

        assertThat(cache.getRequest(request, response)).isNotNull();
        assertThat(cache.getRequest(request, response).getRedirectUrl()).contains("/orders");
    }

    @Test
    @DisplayName("A client that already has a session is remembered whatever it accepts")
    void aClientWithASessionIsRemembered() {
        MockHttpServletRequest request = anonymousGet("*/*");
        request.getSession(true);
        MockHttpServletResponse response = new MockHttpServletResponse();

        cache.saveRequest(request, response);

        assertThat(cache.getRequest(request, response)).isNotNull();
    }

    @Test
    @DisplayName("The session state narrows the chain's default session cache and no other")
    void theSessionStateNarrowsOnlyTheDefaultCache() throws Exception {
        StaticApplicationContext plain = new StaticApplicationContext();
        plain.refresh();
        StaticApplicationContext declaring = new StaticApplicationContext();
        declaring.registerSingleton("hostRequestCache", HttpSessionRequestCache.class);
        declaring.refresh();

        HttpSecurity byDefault = chainWith(new HttpSessionRequestCache());
        new SessionStateConfigurer(plain).init(byDefault);
        verify(byDefault).setSharedObject(eq(RequestCache.class), any(NavigationRequestCache.class));

        HttpSecurity anotherKind = chainWith(new NullRequestCache());
        new SessionStateConfigurer(plain).init(anotherKind);
        verify(anotherKind, never()).setSharedObject(eq(RequestCache.class), any());

        HttpSecurity declared = chainWith(new HttpSessionRequestCache());
        new SessionStateConfigurer(declaring).init(declared);
        verify(declared, never()).setSharedObject(eq(RequestCache.class), any());
    }

    private static MockHttpServletRequest anonymousGet(String accept) {
        MockHttpServletRequest request = new MockHttpServletRequest("GET", "/orders");
        if (accept != null) {
            request.addHeader("Accept", accept);
        }
        return request;
    }

    private static HttpSecurity chainWith(RequestCache requestCache) {
        HttpSecurity http = mock(HttpSecurity.class);
        when(http.getSharedObject(RequestCache.class)).thenReturn(requestCache);
        return http;
    }
}
