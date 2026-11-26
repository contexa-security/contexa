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

import jakarta.servlet.Filter;
import jakarta.servlet.http.HttpServlet;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletRequestWrapper;
import jakarta.servlet.http.HttpServletResponse;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.boot.WebApplicationType;
import org.springframework.boot.autoconfigure.ImportAutoConfiguration;
import org.springframework.boot.autoconfigure.security.servlet.SecurityAutoConfiguration;
import org.springframework.boot.autoconfigure.security.servlet.SecurityFilterAutoConfiguration;
import org.springframework.boot.autoconfigure.web.servlet.ServletWebServerFactoryAutoConfiguration;
import org.springframework.boot.builder.SpringApplicationBuilder;
import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.boot.web.servlet.ServletRegistrationBean;
import org.springframework.boot.web.servlet.context.ServletWebServerApplicationContext;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.Ordered;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.SecurityFilterChain;

import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.security.Principal;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * R-15 of docs/agent/운영모드-정상화-구현계획.md on a real servlet container: the isolation chain Contexa puts in place of
 * Spring Boot's default one leaves the application's requests as they were before Contexa came. Its own {@code /logout}
 * reaches it, the container's sign-in stays readable from the request, and the session is still rewritten into URLs.
 */
@DisplayName("실제 Tomcat에서 SANDBOX 격리 체인은 고객 앱의 로그아웃·컨테이너 인증·URL 세션을 바꾸지 않는다(R-15)")
class SandboxIsolationChainTomcatTest {

    private static ServletWebServerApplicationContext context;

    @BeforeAll
    static void start() {
        context = (ServletWebServerApplicationContext) new SpringApplicationBuilder(Application.class,
                SandboxIsolationAutoConfiguration.class)
                .web(WebApplicationType.SERVLET)
                .properties("server.port=0", "spring.main.banner-mode=off", "contexa.ai.security.mode=SANDBOX")
                .run();
    }

    @AfterAll
    static void stop() {
        if (context != null) {
            context.close();
        }
    }

    @Test
    @DisplayName("격리 체인이 선다")
    void theIsolationChainStands() {
        assertThat(context.containsBean(SandboxIsolationAutoConfiguration.ISOLATION_CHAIN)).isTrue();
    }

    /** docs/agent/bridge-v2-재감사.md R-3: none of Spring Security's default filters stays on the isolation chain. */
    @Test
    @DisplayName("격리 체인에는 Spring Security 필터가 하나도 없다")
    void theIsolationChainHoldsNoFilter() {
        SecurityFilterChain chain = context.getBean(SandboxIsolationAutoConfiguration.ISOLATION_CHAIN,
                SecurityFilterChain.class);

        assertThat(chain.getFilters()).isEmpty();
    }

    /**
     * docs/agent/bridge-v2-재감사.md R-3: an application that puts its user into the security context in a filter in front of
     * every chain reads that user in its servlet, as before Contexa came.
     */
    @Test
    @DisplayName("체인 앞 필터가 SecurityContextHolder에 넣은 사용자를 고객 앱이 그대로 읽는다")
    void theUserAFilterInFrontOfTheChainsPutsStaysTheApplications() throws Exception {
        HttpResponse<String> answer = send("GET", "/holder");

        assertThat(answer.statusCode()).isEqualTo(200);
        assertThat(answer.body()).isEqualTo("kim01");
    }

    @Test
    @DisplayName("고객 앱의 /logout은 Spring 로그아웃이 아니라 고객 앱이 받는다")
    void theApplicationsOwnLogoutReachesTheApplication() throws Exception {
        HttpResponse<String> answer = send("POST", "/logout");

        assertThat(answer.statusCode()).isEqualTo(200);
        assertThat(answer.body()).isEqualTo("the application's logout");
    }

    @Test
    @DisplayName("컨테이너가 인증한 사용자는 고객 앱의 getRemoteUser()·getUserPrincipal()에 그대로 보인다")
    void theContainersSignInStaysReadable() throws Exception {
        HttpResponse<String> answer = send("GET", "/whoami");

        assertThat(answer.statusCode()).isEqualTo(200);
        assertThat(answer.body()).isEqualTo("bob|bob|true");
    }

    @Test
    @DisplayName("쿠키 없는 요청의 세션은 고객 앱의 encodeURL로 주소에 실린다")
    void theSessionIsStillRewrittenIntoUrls() throws Exception {
        HttpResponse<String> answer = send("GET", "/rewrite");

        assertThat(answer.statusCode()).isEqualTo(200);
        assertThat(answer.body()).startsWith("/next;jsessionid=");
    }

    private static HttpResponse<String> send(String method, String path) throws IOException, InterruptedException {
        HttpRequest request = HttpRequest.newBuilder(URI.create("http://127.0.0.1:" + context.getWebServer().getPort() + path))
                .method(method, HttpRequest.BodyPublishers.noBody()).build();
        return HttpClient.newBuilder().followRedirects(HttpClient.Redirect.NEVER).build()
                .send(request, HttpResponse.BodyHandlers.ofString());
    }

    /**
     * An application without a chain or users of its own, signed in by its container: the filter in front of every chain
     * stands for the container's authentication (a realm, SPNEGO, a client certificate). Contexa is not switched on here;
     * the isolation chain's configuration is a source of its own, as Contexa's auto-configuration filter leaves out every
     * class of Contexa's from the auto-configuration import below.
     */
    @Configuration(proxyBeanMethods = false)
    @ImportAutoConfiguration({ServletWebServerFactoryAutoConfiguration.class, SecurityAutoConfiguration.class,
            SecurityFilterAutoConfiguration.class})
    static class Application {

        @Bean
        FilterRegistrationBean<Filter> containerSignIn() {
            FilterRegistrationBean<Filter> registration = new FilterRegistrationBean<>((request, response, chain) ->
                    chain.doFilter(new ContainerSignedIn((HttpServletRequest) request), response));
            registration.setOrder(Ordered.HIGHEST_PRECEDENCE);
            return registration;
        }

        /** The application's own sign-in in a filter in front of every chain, kept to its path. */
        @Bean
        FilterRegistrationBean<Filter> holderInFrontOfTheChains() {
            FilterRegistrationBean<Filter> registration = new FilterRegistrationBean<>((request, response, chain) -> {
                SecurityContextHolder.getContext().setAuthentication(
                        UsernamePasswordAuthenticationToken.authenticated("kim01", null, List.of()));
                try {
                    chain.doFilter(request, response);
                } finally {
                    SecurityContextHolder.clearContext();
                }
            });
            registration.addUrlPatterns("/holder");
            registration.setOrder(Ordered.HIGHEST_PRECEDENCE + 1);
            return registration;
        }

        @Bean
        ServletRegistrationBean<HttpServlet> applicationServlet() {
            HttpServlet servlet = new HttpServlet() {
                @Override
                protected void service(HttpServletRequest request, HttpServletResponse response) throws IOException {
                    String body = switch (request.getRequestURI()) {
                        case "/logout" -> "the application's logout";
                        case "/whoami" -> request.getRemoteUser() + "|"
                                + (request.getUserPrincipal() != null ? request.getUserPrincipal().getName() : null) + "|"
                                + request.isUserInRole("STAFF");
                        case "/rewrite" -> {
                            request.getSession(true);
                            yield response.encodeURL("/next");
                        }
                        case "/holder" -> {
                            Authentication user = SecurityContextHolder.getContext().getAuthentication();
                            yield user != null ? user.getName() : "nobody";
                        }
                        default -> "other";
                    };
                    response.getWriter().write(body);
                }
            };
            return new ServletRegistrationBean<>(servlet, "/*");
        }
    }

    static final class ContainerSignedIn extends HttpServletRequestWrapper {

        ContainerSignedIn(HttpServletRequest request) {
            super(request);
        }

        @Override
        public String getRemoteUser() {
            return "bob";
        }

        @Override
        public Principal getUserPrincipal() {
            return () -> "bob";
        }

        @Override
        public boolean isUserInRole(String role) {
            return "STAFF".equals(role);
        }
    }
}
