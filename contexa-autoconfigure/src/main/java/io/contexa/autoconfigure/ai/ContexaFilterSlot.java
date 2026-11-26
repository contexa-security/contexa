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
package io.contexa.autoconfigure.ai;

import jakarta.servlet.DispatcherType;
import jakarta.servlet.Filter;
import jakarta.servlet.FilterChain;
import jakarta.servlet.FilterConfig;
import jakarta.servlet.RequestDispatcher;
import jakarta.servlet.ServletContext;
import jakarta.servlet.ServletException;
import jakarta.servlet.ServletRequest;
import jakarta.servlet.ServletResponse;
import jakarta.servlet.http.HttpServletRequest;
import lombok.extern.slf4j.Slf4j;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.Comparator;
import java.util.Enumeration;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.function.Supplier;

/**
 * Contexa's one place among the application's servlet filters (R-10 of docs/agent/운영모드-정상화-구현계획.md). The filters
 * of Contexa's that act on what the Spring Security filter chain established run here as one virtual chain, in the order
 * of their registrations ({@link ContexaSlotFilterRegistration}): no filter of the application's runs between two of them,
 * so the order the application gives its own filters changes nothing in what Contexa does.
 * <p>
 * Each member gets what the servlet container would have given it: the requests of its dispatcher types and URL patterns
 * (exact, path and extension patterns, matched on the path the container maps, the servlet path and the path info, or the
 * included path of an include), its own name and init parameters at its initialisation, and its destruction. A member that
 * answers the request itself ends it there: the members after it, the application's filters and its handler do not run.
 * The members are read from their registrations when the slot is first initialised or used. A slot called without its
 * initialisation (a filter called directly, outside a servlet container) initialises none of them: a once-per-request
 * member then keeps the name it had, and two such members of one class without a bean name would take each other's
 * request for their own.
 */
@Slf4j
public final class ContexaFilterSlot implements Filter {

    /** The name of the slot's registration with the servlet container. */
    public static final String NAME = "contexaFilterSlot";

    private final Supplier<? extends Collection<? extends ContexaSlotFilterRegistration<?>>> registrations;
    private volatile List<Member> members;

    public ContexaFilterSlot(Supplier<? extends Collection<? extends ContexaSlotFilterRegistration<?>>> registrations) {
        this.registrations = registrations;
    }

    @Override
    public void init(FilterConfig filterConfig) throws ServletException {
        ServletContext servletContext = filterConfig.getServletContext();
        for (Member member : members()) {
            member.filter().init(new MemberConfig(member.name(), servletContext, member.initParameters()));
        }
    }

    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
            throws IOException, ServletException {
        List<Filter> matching = matching(request);
        if (matching.isEmpty()) {
            chain.doFilter(request, response);
            return;
        }
        new VirtualChain(matching, chain).doFilter(request, response);
    }

    @Override
    public void destroy() {
        List<Member> resolved = this.members;
        if (resolved == null) {
            return;
        }
        for (Member member : resolved) {
            try {
                member.filter().destroy();
            } catch (RuntimeException failure) {
                log.error("Contexa's filter slot could not destroy the filter {}", member.name(), failure);
            }
        }
    }

    /** The filters the slot runs, in their order. */
    public List<Filter> filters() {
        return members().stream().map(Member::filter).toList();
    }

    private List<Filter> matching(ServletRequest request) {
        List<Member> resolved = members();
        DispatcherType dispatch = request.getDispatcherType();
        String path = request instanceof HttpServletRequest http ? mappedPath(http) : null;
        List<Filter> matching = new ArrayList<>(resolved.size());
        for (Member member : resolved) {
            if (member.accepts(dispatch, path)) {
                matching.add(member.filter());
            }
        }
        return matching;
    }

    private List<Member> members() {
        List<Member> resolved = this.members;
        if (resolved == null) {
            synchronized (this) {
                resolved = this.members;
                if (resolved == null) {
                    resolved = resolve(registrations.get());
                    this.members = resolved;
                }
            }
        }
        return resolved;
    }

    private static List<Member> resolve(Collection<? extends ContexaSlotFilterRegistration<?>> registrations) {
        List<ContexaSlotFilterRegistration<?>> running = new ArrayList<>();
        for (ContexaSlotFilterRegistration<?> registration : registrations) {
            if (registration.runsInSlot()) {
                running.add(registration);
            }
        }
        running.sort(Comparator.comparingInt(ContexaSlotFilterRegistration::getOrder));
        Set<String> names = new HashSet<>();
        List<Member> resolved = new ArrayList<>(running.size());
        for (ContexaSlotFilterRegistration<?> registration : running) {
            String name = registration.getFilterName();
            if (!registration.getServletNames().isEmpty() || !registration.getServletRegistrationBeans().isEmpty()) {
                throw new IllegalStateException("Contexa's filter slot maps its filters by URL pattern only, and the filter "
                        + name + " is mapped to servlets");
            }
            if (!names.add(name)) {
                throw new IllegalStateException("Contexa's filter slot has two filters named " + name);
            }
            List<String> patterns = registration.getUrlPatterns().isEmpty()
                    ? List.of("/*") : List.copyOf(registration.getUrlPatterns());
            resolved.add(new Member(registration.getFilter(), name, Map.copyOf(registration.getInitParameters()),
                    registration.determineDispatcherTypes(), patterns));
        }
        return List.copyOf(resolved);
    }

    /** The path the servlet container maps a dispatch by: the included one for an include, else the servlet path and the path info. */
    private static String mappedPath(HttpServletRequest request) {
        if (request.getDispatcherType() == DispatcherType.INCLUDE) {
            Object includedServletPath = request.getAttribute(RequestDispatcher.INCLUDE_SERVLET_PATH);
            if (includedServletPath != null) {
                Object includedPathInfo = request.getAttribute(RequestDispatcher.INCLUDE_PATH_INFO);
                return includedServletPath + (includedPathInfo != null ? includedPathInfo.toString() : "");
            }
        }
        String servletPath = request.getServletPath();
        String pathInfo = request.getPathInfo();
        return (servletPath != null ? servletPath : "") + (pathInfo != null ? pathInfo : "");
    }

    /** A URL pattern of the Servlet specification against a mapped path, as the servlet container matches a filter's. */
    static boolean matches(String pattern, String path) {
        if (pattern.equals(path) || pattern.equals("/*")) {
            return true;
        }
        if (pattern.endsWith("/*")) {
            int prefix = pattern.length() - 2;
            return path.regionMatches(0, pattern, 0, prefix)
                    && (path.length() == prefix || path.charAt(prefix) == '/');
        }
        if (pattern.startsWith("*.")) {
            int slash = path.lastIndexOf('/');
            int period = path.lastIndexOf('.');
            return slash >= 0 && period > slash && period != path.length() - 1
                    && path.length() - period == pattern.length() - 1
                    && pattern.regionMatches(2, path, period + 1, pattern.length() - 2);
        }
        return false;
    }

    private record Member(Filter filter, String name, Map<String, String> initParameters,
                          Set<DispatcherType> dispatcherTypes, List<String> urlPatterns) {

        boolean accepts(DispatcherType dispatch, String path) {
            if (path == null || !dispatcherTypes.contains(dispatch)) {
                return false;
            }
            for (String pattern : urlPatterns) {
                if (matches(pattern, path)) {
                    return true;
                }
            }
            return false;
        }
    }

    private record MemberConfig(String name, ServletContext servletContext, Map<String, String> parameters)
            implements FilterConfig {

        @Override
        public String getFilterName() {
            return name;
        }

        @Override
        public ServletContext getServletContext() {
            return servletContext;
        }

        @Override
        public String getInitParameter(String parameter) {
            return parameters.get(parameter);
        }

        @Override
        public Enumeration<String> getInitParameterNames() {
            return Collections.enumeration(parameters.keySet());
        }
    }

    private static final class VirtualChain implements FilterChain {

        private final List<Filter> filters;
        private final FilterChain chain;
        private int next;

        private VirtualChain(List<Filter> filters, FilterChain chain) {
            this.filters = filters;
            this.chain = chain;
        }

        @Override
        public void doFilter(ServletRequest request, ServletResponse response) throws IOException, ServletException {
            if (next == filters.size()) {
                chain.doFilter(request, response);
                return;
            }
            filters.get(next++).doFilter(request, response, this);
        }
    }
}
