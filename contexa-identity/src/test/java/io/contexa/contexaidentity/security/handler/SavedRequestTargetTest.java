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
package io.contexa.contexaidentity.security.handler;

import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.web.savedrequest.HttpSessionRequestCache;
import org.springframework.security.web.savedrequest.SavedRequest;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * After a sign-in the browser goes back to the page it asked for. Spring Security keeps that request with a full
 * address, and only its path and query are followed.
 */
class SavedRequestTargetTest {

    private static SavedRequest savedBySpringSecurity(String path, String query) {
        MockHttpServletRequest asked = new MockHttpServletRequest("GET", path);
        asked.setScheme("http");
        asked.setServerName("app.example");
        asked.setServerPort(8080);
        asked.setQueryString(query);
        HttpSessionRequestCache cache = new HttpSessionRequestCache();
        cache.saveRequest(asked, new MockHttpServletResponse());
        return cache.getRequest(asked, new MockHttpServletResponse());
    }

    @Test
    void theRequestSpringSecuritySavedIsFollowedByItsPathAndQuery() {
        SavedRequest saved = savedBySpringSecurity("/orders/42", "tab=items");

        assertThat(saved.getRedirectUrl()).startsWith("http://app.example:8080/orders/42");
        assertThat(SavedRequestTarget.of(saved)).startsWith("/orders/42?tab=items");
    }

    @Test
    void aSavedRequestWithoutAQueryIsFollowedToo() {
        assertThat(SavedRequestTarget.of(savedBySpringSecurity("/orders", null))).startsWith("/orders");
    }

    @Test
    void noSavedRequestIsNoPage() {
        assertThat(SavedRequestTarget.of(null)).isNull();
    }

    @Test
    void aPathIsKeptAsItIs() {
        assertThat(SavedRequestTarget.sameSite("/orders/42?tab=items")).isEqualTo("/orders/42?tab=items");
    }

    @Test
    void theHostOfAFullAddressIsNeverFollowed() {
        assertThat(SavedRequestTarget.sameSite("https://other.example/orders?x=1")).isEqualTo("/orders?x=1");
        assertThat(SavedRequestTarget.sameSite("https://other.example")).isNull();
        assertThat(SavedRequestTarget.sameSite("https://other.example?next=/orders")).isNull();
    }

    @Test
    void anAddressABrowserReadsAsAnotherSiteIsNoPage() {
        assertThat(SavedRequestTarget.sameSite("//other.example/orders")).isNull();
        assertThat(SavedRequestTarget.sameSite("http://app.example//other.example/orders")).isNull();
        assertThat(SavedRequestTarget.sameSite("/\\other.example/orders")).isNull();
        assertThat(SavedRequestTarget.sameSite("javascript:alert(1)")).isNull();
        assertThat(SavedRequestTarget.sameSite("orders")).isNull();
    }

    @Test
    void whatABrowserAsksForByItselfIsNoPage() {
        assertThat(SavedRequestTarget.sameSite("http://app.example/favicon.ico")).isNull();
        assertThat(SavedRequestTarget.sameSite("/.well-known/appspecific/com.chrome.devtools.json")).isNull();
        assertThat(SavedRequestTarget.sameSite(" ")).isNull();
        assertThat(SavedRequestTarget.sameSite(null)).isNull();
    }
}
