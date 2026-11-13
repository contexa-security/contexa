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

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.http.MediaType;
import org.springframework.security.web.savedrequest.RequestCache;
import org.springframework.security.web.savedrequest.SavedRequest;
import org.springframework.security.web.util.matcher.MediaTypeRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;

import java.util.Set;

/**
 * Remembers the request to return to after sign-in only for a client that comes back with it: one that
 * already has a session, or a browser asking for a page. A client that keeps no cookie would otherwise
 * leave a new session behind on every anonymous request, each of them living until it times out.
 */
final class NavigationRequestCache implements RequestCache {

    private final RequestCache delegate;
    private final RequestMatcher page;

    NavigationRequestCache(RequestCache delegate) {
        this.delegate = delegate;
        MediaTypeRequestMatcher html = new MediaTypeRequestMatcher(MediaType.TEXT_HTML);
        html.setIgnoredMediaTypes(Set.of(MediaType.ALL));
        this.page = html;
    }

    @Override
    public void saveRequest(HttpServletRequest request, HttpServletResponse response) {
        if (request.getSession(false) != null || page.matches(request)) {
            delegate.saveRequest(request, response);
        }
    }

    @Override
    public SavedRequest getRequest(HttpServletRequest request, HttpServletResponse response) {
        return delegate.getRequest(request, response);
    }

    @Override
    public HttpServletRequest getMatchingRequest(HttpServletRequest request, HttpServletResponse response) {
        return delegate.getMatchingRequest(request, response);
    }

    @Override
    public void removeRequest(HttpServletRequest request, HttpServletResponse response) {
        delegate.removeRequest(request, response);
    }
}
