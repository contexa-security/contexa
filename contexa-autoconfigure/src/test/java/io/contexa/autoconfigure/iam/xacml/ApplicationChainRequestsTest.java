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
package io.contexa.autoconfigure.iam.xacml;

import io.contexa.autoconfigure.ai.SandboxIsolationAutoConfiguration;
import io.contexa.contexaidentity.security.core.context.OrderedSecurityFilterChain;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.support.DefaultListableBeanFactory;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.security.web.DefaultSecurityFilterChain;
import org.springframework.security.web.FilterChainProxy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.context.AbstractSecurityWebApplicationInitializer;
import org.springframework.security.web.debug.DebugFilter;
import org.springframework.security.web.util.matcher.AnyRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * R-7 and R-16 of docs/agent/운영모드-정상화-구현계획.md: which requests are the application's, so that the URL policies are
 * enforced on them behind the application's chain, and which are taken by one of Contexa's own chains.
 */
@DisplayName("고객 경로와 Contexa 자기 체인 경로의 구분(R-7, R-16)")
class ApplicationChainRequestsTest {

    private static final RequestMatcher ADMIN_REALM = request -> request.getRequestURI().startsWith("/contexa/admin");
    private static final RequestMatcher STATIC_FILES = request -> request.getRequestURI().startsWith("/css/");

    private final SecurityFilterChain adminRealm = new OrderedSecurityFilterChain(10, ADMIN_REALM, List.of());
    private final SecurityFilterChain ignoredStaticFiles = new DefaultSecurityFilterChain(STATIC_FILES);
    private final SecurityFilterChain applicationChain = new DefaultSecurityFilterChain(AnyRequestMatcher.INSTANCE);

    @Test
    @DisplayName("앱 체인이 맡는 요청은 고객 경로, Contexa 관리 영역 체인이 맡는 요청은 Contexa 몫이다")
    void theApplicationsChainAndContexasRealm() {
        DefaultListableBeanFactory beanFactory = beans(new FilterChainProxy(List.of(adminRealm, ignoredStaticFiles, applicationChain)));
        beanFactory.registerSingleton("contexamfa_contexa-adminSecurityFilterChain1", adminRealm);
        beanFactory.registerSingleton("hostChain", applicationChain);
        ApplicationChainRequests requests = new ApplicationChainRequests(beanFactory);

        assertThat(requests.matches(get("/h/open/staff/report"))).isTrue();
        assertThat(requests.matches(get("/contexa/admin/api/blacklist"))).isFalse();
        assertThat(requests.matches(get("/css/site.css"))).as("a path Contexa leaves outside security is not the application's chain's")
                .isFalse();
    }

    @Test
    @DisplayName("FULL의 Contexa 주 체인이 맡는 요청은 Contexa 몫이고, 앱의 좁힌 체인이 맡는 요청은 고객 경로다")
    void contexasMainChainAndTheApplicationsNarrowedChain() {
        SecurityFilterChain narrowed = new DefaultSecurityFilterChain(request -> request.getRequestURI().startsWith("/h/"));
        SecurityFilterChain mainChain = new OrderedSecurityFilterChain(Integer.MAX_VALUE, AnyRequestMatcher.INSTANCE, List.of());
        DefaultListableBeanFactory beanFactory = beans(new FilterChainProxy(List.of(narrowed, mainChain)));
        beanFactory.registerSingleton("hostChain", narrowed);
        beanFactory.registerSingleton("contexamfaSecurityFilterChain2", mainChain);
        ApplicationChainRequests requests = new ApplicationChainRequests(beanFactory);

        assertThat(requests.matches(get("/h/open/staff/report"))).isTrue();
        assertThat(requests.matches(get("/reports/1"))).isFalse();
    }

    @Test
    @DisplayName("SANDBOX 격리 체인은 보안 없는 앱을 대신하므로 그 요청은 고객 경로다")
    void theIsolationChainStandsInForTheApplication() {
        SecurityFilterChain isolation = new DefaultSecurityFilterChain(AnyRequestMatcher.INSTANCE);
        DefaultListableBeanFactory beanFactory = beans(new FilterChainProxy(List.of(adminRealm, isolation)));
        beanFactory.registerSingleton("contexamfa_contexa-adminSecurityFilterChain1", adminRealm);
        beanFactory.registerSingleton(SandboxIsolationAutoConfiguration.ISOLATION_CHAIN, isolation);
        ApplicationChainRequests requests = new ApplicationChainRequests(beanFactory);

        assertThat(requests.matches(get("/h/open/staff/report"))).isTrue();
        assertThat(requests.matches(get("/contexa/admin/api/blacklist"))).isFalse();
    }

    @Test
    @DisplayName("어느 체인도 맡지 않는 요청과 보안 필터가 없는 앱의 요청은 고객 경로다")
    void aRequestNoChainTakesIsTheApplications() {
        DefaultListableBeanFactory beanFactory = beans(new FilterChainProxy(List.of(adminRealm)));
        beanFactory.registerSingleton("contexamfa_contexa-adminSecurityFilterChain1", adminRealm);

        assertThat(new ApplicationChainRequests(beanFactory).matches(get("/h/open/staff/report"))).isTrue();
        assertThat(new ApplicationChainRequests(new DefaultListableBeanFactory()).matches(get("/h/open/staff/report"))).isTrue();
    }

    @Test
    @DisplayName("디버그 필터로 감싼 프록시의 체인도 같은 순서로 본다")
    void theChainsOfAProxyTheDebugFilterWraps() {
        DefaultListableBeanFactory beanFactory = beans(new DebugFilter(new FilterChainProxy(List.of(adminRealm, applicationChain))));
        beanFactory.registerSingleton("contexamfa_contexa-adminSecurityFilterChain1", adminRealm);
        beanFactory.registerSingleton("hostChain", applicationChain);
        ApplicationChainRequests requests = new ApplicationChainRequests(beanFactory);

        assertThat(requests.matches(get("/contexa/admin/api/blacklist"))).isFalse();
        assertThat(requests.matches(get("/h/open/staff/report"))).isTrue();
    }

    private static DefaultListableBeanFactory beans(Object springSecurityFilterChain) {
        DefaultListableBeanFactory beanFactory = new DefaultListableBeanFactory();
        beanFactory.registerSingleton(AbstractSecurityWebApplicationInitializer.DEFAULT_FILTER_NAME, springSecurityFilterChain);
        return beanFactory;
    }

    private static MockHttpServletRequest get(String path) {
        return new MockHttpServletRequest("GET", path);
    }
}
