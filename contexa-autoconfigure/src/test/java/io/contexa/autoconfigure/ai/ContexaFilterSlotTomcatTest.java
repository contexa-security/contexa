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

import io.contexa.contexaidentity.security.zerotrust.SandboxUserPathGuard;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServlet;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.boot.WebApplicationType;
import org.springframework.boot.autoconfigure.ImportAutoConfiguration;
import org.springframework.boot.autoconfigure.security.SecurityProperties;
import org.springframework.boot.autoconfigure.web.servlet.ServletWebServerFactoryAutoConfiguration;
import org.springframework.boot.builder.SpringApplicationBuilder;
import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.boot.web.servlet.ServletRegistrationBean;
import org.springframework.boot.web.servlet.context.ServletWebServerApplicationContext;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.Ordered;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.util.List;
import java.util.Set;
import java.util.concurrent.CopyOnWriteArrayList;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * R-10 of docs/agent/운영모드-정상화-구현계획.md on a real servlet container: Contexa's filters behind the Spring Security
 * filter chain run in one place, mapped after every filter of the application's, so a filter of the application's,
 * whatever its order, has run before all of them and never runs between two.
 */
@DisplayName("실제 Tomcat에서 Contexa 필터 슬롯: 고객 필터는 순서와 상관없이 모두 먼저 돌고, 사이에 끼어들지 못한다(R-10)")
class ContexaFilterSlotTomcatTest {

    private static final int CHAIN = SecurityProperties.DEFAULT_FILTER_ORDER;

    private static ServletWebServerApplicationContext context;
    private static Calls calls;

    @BeforeAll
    static void start() {
        context = (ServletWebServerApplicationContext) new SpringApplicationBuilder(Application.class,
                ContexaFilterSlotConfiguration.class)
                .web(WebApplicationType.SERVLET)
                .properties("server.port=0", "spring.main.banner-mode=off")
                .run();
        calls = context.getBean(Calls.class);
    }

    @AfterAll
    static void stop() {
        if (context != null) {
            context.close();
        }
    }

    @BeforeEach
    void clear() {
        calls.clear();
    }

    @Test
    @DisplayName("고객 필터를 옛 Contexa 필터 순서 사이나 맨 끝 순서에 두어도, 고객 필터가 모두 돈 뒤 Contexa 필터가 정해진 순서로 이어 돈다")
    void everyApplicationFilterRunsBeforeContexasFilters() throws Exception {
        HttpResponse<String> answer = get("/orders");

        assertThat(answer.statusCode()).isEqualTo(200);
        assertThat(calls.names()).containsExactly("application-between", "application-after", "application-last",
                "bridge", "challenge", "access", "url", "tracking", "servlet");
    }

    @Test
    @DisplayName("Contexa 필터가 응답을 끝내면 뒤의 Contexa 필터와 고객 필터·처리는 돌지 않는다")
    void aRefusalOfContexasEndsTheRequestThere() throws Exception {
        HttpResponse<String> answer = get("/contexa/step-up");

        assertThat(answer.statusCode()).isEqualTo(401);
        assertThat(answer.body()).contains("AUTHENTICATION_REQUIRED");
        assertThat(calls.names()).containsExactly("application-between", "application-after", "application-last",
                "bridge", "challenge", "access");
    }

    @Test
    @DisplayName("서블릿 컨테이너에는 Contexa의 체인 뒤 필터가 슬롯 하나로만 매핑된다")
    void theContainerMapsContexasFiltersAsTheOneSlot() {
        Set<String> registered = context.getServletContext().getFilterRegistrations().keySet();

        assertThat(registered).contains(ContexaFilterSlot.NAME, "applicationBetween", "applicationAfter", "applicationLast");
        assertThat(registered).doesNotContain("contexaProbeBridge", "contexaProbeChallenge", "contexaProbeAccess",
                "contexaSandboxUserPathGuard", "contexaProbeUrl", "contexaProbeTracking");
    }

    private static HttpResponse<String> get(String path) throws IOException, InterruptedException {
        HttpRequest request = HttpRequest.newBuilder(URI.create("http://127.0.0.1:" + context.getWebServer().getPort() + path))
                .GET().build();
        return HttpClient.newHttpClient().send(request, HttpResponse.BodyHandlers.ofString());
    }

    /**
     * The application, with the members of the slot. The slot's configuration is a source of its own: Contexa is not switched
     * on here, and Contexa's auto-configuration filter, which the auto-configuration import below brings to the classes
     * imported beside it, leaves out every class of Contexa's then.
     */
    @Configuration(proxyBeanMethods = false)
    @ImportAutoConfiguration(ServletWebServerFactoryAutoConfiguration.class)
    static class Application {

        @Bean
        Calls calls() {
            return new Calls();
        }

        @Bean
        ServletRegistrationBean<HttpServlet> applicationServlet(Calls calls) {
            HttpServlet servlet = new HttpServlet() {
                @Override
                protected void doGet(HttpServletRequest request, HttpServletResponse response) throws IOException {
                    calls.add("servlet");
                    response.getWriter().write("ok");
                }
            };
            return new ServletRegistrationBean<>(servlet, "/*");
        }

        @Bean
        ContexaSlotFilterRegistration<Recording> contexaProbeTracking(Calls calls) {
            return ContexaServletFilterOrder.member(new Recording(calls, "tracking"), "contexaProbeTracking", CHAIN,
                    ContexaServletFilterOrder.SESSION_TRACKING);
        }

        @Bean
        ContexaSlotFilterRegistration<Recording> contexaProbeBridge(Calls calls) {
            return ContexaServletFilterOrder.member(new Recording(calls, "bridge"), "contexaProbeBridge", CHAIN,
                    ContexaServletFilterOrder.BRIDGE);
        }

        @Bean
        ContexaSlotFilterRegistration<Recording> contexaProbeChallenge(Calls calls) {
            return ContexaServletFilterOrder.member(new Recording(calls, "challenge"), "contexaProbeChallenge", CHAIN,
                    ContexaServletFilterOrder.CHALLENGE);
        }

        @Bean
        ContexaSlotFilterRegistration<Recording> contexaProbeAccess(Calls calls) {
            return ContexaServletFilterOrder.member(new Recording(calls, "access"), "contexaProbeAccess", CHAIN,
                    ContexaServletFilterOrder.ACCESS_CONTROL);
        }

        @Bean
        ContexaSlotFilterRegistration<SandboxUserPathGuard> contexaProbeGuard() {
            ContexaSlotFilterRegistration<SandboxUserPathGuard> guard = ContexaServletFilterOrder.member(
                    new SandboxUserPathGuard(), "contexaSandboxUserPathGuard", CHAIN,
                    ContexaServletFilterOrder.USER_PATH_GUARD);
            guard.setUrlPatterns(SandboxUserPathGuard.URL_PATTERNS);
            return guard;
        }

        @Bean
        ContexaSlotFilterRegistration<Recording> contexaProbeUrl(Calls calls) {
            return ContexaServletFilterOrder.member(new Recording(calls, "url"), "contexaProbeUrl", CHAIN,
                    ContexaServletFilterOrder.URL_POLICY);
        }

        /** Where, before the slot, it ran between Contexa's URL policies and its session tracking. */
        @Bean
        FilterRegistrationBean<Recording> applicationBetween(Calls calls) {
            FilterRegistrationBean<Recording> registration = new FilterRegistrationBean<>(new Recording(calls, "application-between"));
            registration.setOrder(CHAIN + ContexaServletFilterOrder.URL_POLICY + 2);
            return registration;
        }

        @Bean
        FilterRegistrationBean<Recording> applicationAfter(Calls calls) {
            FilterRegistrationBean<Recording> registration = new FilterRegistrationBean<>(new Recording(calls, "application-after"));
            registration.setOrder(0);
            return registration;
        }

        /** The order a filter of the application's gets when it is given none, the same as the slot's. */
        @Bean
        FilterRegistrationBean<Recording> applicationLast(Calls calls) {
            FilterRegistrationBean<Recording> registration = new FilterRegistrationBean<>(new Recording(calls, "application-last"));
            registration.setOrder(Ordered.LOWEST_PRECEDENCE);
            return registration;
        }
    }

    static final class Calls {

        private final List<String> names = new CopyOnWriteArrayList<>();

        void add(String name) {
            names.add(name);
        }

        List<String> names() {
            return List.copyOf(names);
        }

        void clear() {
            names.clear();
        }
    }

    static final class Recording extends OncePerRequestFilter {

        private final Calls calls;
        private final String name;

        Recording(Calls calls, String name) {
            this.calls = calls;
            this.name = name;
        }

        @Override
        protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
                throws ServletException, IOException {
            calls.add(name);
            chain.doFilter(request, response);
        }
    }
}
