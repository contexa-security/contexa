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
package io.contexa.contexacommon.security.bridge.identity;

import io.contexa.contexacommon.security.bridge.subject.ContexaRequestView;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpSession;

import java.security.Principal;
import java.util.ArrayList;
import java.util.Enumeration;
import java.util.List;
import java.util.Optional;

/**
 * The read-only view of a servlet request a resolver is given. It holds the request but never hands it out, so a
 * resolver cannot read the body or the parameters, create a session or change the request through it.
 */
final class ServletRequestView implements ContexaRequestView {

    private final HttpServletRequest request;

    ServletRequestView(HttpServletRequest request) {
        this.request = request;
    }

    @Override
    public String method() {
        return request.getMethod();
    }

    @Override
    public String path() {
        String uri = request.getRequestURI();
        return uri != null ? uri : "";
    }

    @Override
    public Optional<String> header(String name) {
        return name != null ? Optional.ofNullable(request.getHeader(name)) : Optional.empty();
    }

    @Override
    public List<String> headers(String name) {
        if (name == null) {
            return List.of();
        }
        Enumeration<String> values = request.getHeaders(name);
        if (values == null) {
            return List.of();
        }
        List<String> all = new ArrayList<>();
        while (values.hasMoreElements()) {
            all.add(values.nextElement());
        }
        return List.copyOf(all);
    }

    @Override
    public Optional<String> cookie(String name) {
        Cookie[] cookies = request.getCookies();
        if (name == null || cookies == null) {
            return Optional.empty();
        }
        for (Cookie cookie : cookies) {
            if (cookie != null && name.equals(cookie.getName())) {
                return Optional.ofNullable(cookie.getValue());
            }
        }
        return Optional.empty();
    }

    @Override
    public Optional<Object> attribute(String name) {
        return name != null ? Optional.ofNullable(request.getAttribute(name)) : Optional.empty();
    }

    @Override
    public <T> Optional<T> attribute(String name, Class<T> type) {
        return attribute(name).filter(type::isInstance).map(type::cast);
    }

    @Override
    public Optional<Object> sessionAttribute(String name) {
        HttpSession session = request.getSession(false);
        if (name == null || session == null) {
            return Optional.empty();
        }
        try {
            return Optional.ofNullable(session.getAttribute(name));
        } catch (IllegalStateException invalidated) {
            return Optional.empty();
        }
    }

    @Override
    public <T> Optional<T> sessionAttribute(String name, Class<T> type) {
        return sessionAttribute(name).filter(type::isInstance).map(type::cast);
    }

    @Override
    public Optional<String> sessionId() {
        HttpSession session = request.getSession(false);
        if (session == null) {
            return Optional.empty();
        }
        try {
            return Optional.ofNullable(session.getId());
        } catch (IllegalStateException invalidated) {
            return Optional.empty();
        }
    }

    @Override
    public Optional<String> remoteUser() {
        return Optional.ofNullable(request.getRemoteUser());
    }

    @Override
    public Optional<Principal> userPrincipal() {
        return Optional.ofNullable(request.getUserPrincipal());
    }
}
