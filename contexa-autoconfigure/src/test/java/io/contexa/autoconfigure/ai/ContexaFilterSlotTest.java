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
import jakarta.servlet.RequestDispatcher;
import jakarta.servlet.ServletException;
import jakarta.servlet.ServletRequest;
import jakarta.servlet.ServletResponse;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.support.DefaultListableBeanFactory;
import org.springframework.boot.autoconfigure.security.SecurityProperties;
import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.mock.web.MockFilterConfig;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.mock.web.MockServletContext;
import org.springframework.web.filter.OncePerRequestFilter;
import org.springframework.core.Ordered;

import java.io.IOException;
import java.util.ArrayList;
import java.util.EnumSet;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * R-10 of docs/agent/운영모드-정상화-구현계획.md: Contexa's filter slot runs its members as one virtual chain, each on the
 * requests the servlet container would have given it, under its own name.
 */
@DisplayName("Contexa 필터 슬롯의 가상 체인(R-10)")
class ContexaFilterSlotTest {

    private static final int CHAIN = SecurityProperties.DEFAULT_FILTER_ORDER;

    private final List<String> ran = new ArrayList<>();

    @Test
    @DisplayName("구성원을 순서 값대로 돌리고, 마지막 구성원 다음에 원래 체인을 잇는다")
    void runsItsMembersByTheirOrderThenTheOriginalChain() throws Exception {
        ContexaFilterSlot slot = slot(member("tracking", ContexaServletFilterOrder.SESSION_TRACKING),
                member("bridge", ContexaServletFilterOrder.BRIDGE), member("url", ContexaServletFilterOrder.URL_POLICY));

        slot.doFilter(request("/orders"), new MockHttpServletResponse(), application());

        assertThat(ran).containsExactly("bridge", "url", "tracking", "application");
    }

    @Test
    @DisplayName("구성원이 응답을 끝내면 뒤 구성원과 원래 체인은 돌지 않는다")
    void aMemberThatAnswersEndsTheRequest() throws Exception {
        ContexaFilterSlot slot = slot(member("bridge", ContexaServletFilterOrder.BRIDGE),
                answering("access", ContexaServletFilterOrder.ACCESS_CONTROL),
                member("tracking", ContexaServletFilterOrder.SESSION_TRACKING));
        MockHttpServletResponse response = new MockHttpServletResponse();

        slot.doFilter(request("/orders"), response, application());

        assertThat(ran).containsExactly("bridge", "access");
        assertThat(response.getStatus()).isEqualTo(HttpServletResponse.SC_FORBIDDEN);
    }

    @Test
    @DisplayName("끈 구성원은 돌지 않고 초기화도 받지 않는다")
    void aSwitchedOffMemberNeitherRunsNorIsInitialised() throws Exception {
        ContexaSlotFilterRegistration<Recording> off = member("challenge", ContexaServletFilterOrder.CHALLENGE);
        off.setEnabled(false);
        ContexaFilterSlot slot = slot(member("bridge", ContexaServletFilterOrder.BRIDGE), off);

        slot.doFilter(request("/orders"), new MockHttpServletResponse(), application());

        assertThat(ran).containsExactly("bridge", "application");
        assertThat(off.getFilter().filterConfigName()).isNull();
        assertThat(slot.filters()).containsExactly(filterOf(slot, "bridge"));
    }

    @Test
    @DisplayName("구성원마다 자기 URL 패턴(정확·경로·확장자)의 요청만 받는다")
    void eachMemberGetsTheRequestsOfItsOwnUrlPatterns() throws Exception {
        ContexaSlotFilterRegistration<Recording> guard = member("guard", ContexaServletFilterOrder.USER_PATH_GUARD);
        guard.setUrlPatterns(List.of("/contexa/step-up", "/contexa/step-up/*", "*.do"));
        ContexaFilterSlot slot = slot(guard);

        assertThat(runs(slot, request("/contexa/step-up"))).isTrue();
        assertThat(runs(slot, request("/contexa/step-up/code"))).isTrue();
        assertThat(runs(slot, request("/orders/list.do"))).isTrue();
        assertThat(runs(slot, request("/contexa/step-upx"))).isFalse();
        assertThat(runs(slot, request("/orders"))).isFalse();
        MockHttpServletRequest underAServletPath = new MockHttpServletRequest("GET", "/contexa/step-up/code");
        underAServletPath.setServletPath("/contexa");
        underAServletPath.setPathInfo("/step-up/code");
        assertThat(runs(slot, underAServletPath)).as("the servlet path and the path info together").isTrue();
    }

    @Test
    @DisplayName("구성원마다 자기 디스패치 유형만 받는다: 지정이 없으면 Spring Boot의 기본값")
    void eachMemberGetsTheDispatchesOfItsOwnTypes() throws Exception {
        List<String> plainRan = new ArrayList<>();
        Filter plain = (request, response, chain) -> {
            plainRan.add("plain");
            chain.doFilter(request, response);
        };
        ContexaSlotFilterRegistration<Filter> plainMember = ContexaServletFilterOrder.member(plain, "contexaPlain", CHAIN,
                ContexaServletFilterOrder.BRIDGE);
        ContexaSlotFilterRegistration<Recording> oncePerRequest = member("once", ContexaServletFilterOrder.CHALLENGE);
        ContexaSlotFilterRegistration<Recording> errorsOnly = member("errors", ContexaServletFilterOrder.ACCESS_CONTROL);
        errorsOnly.setDispatcherTypes(DispatcherType.ERROR);
        ContexaFilterSlot slot = initialised(new ContexaFilterSlot(() -> List.of(plainMember, oncePerRequest, errorsOnly)));
        MockHttpServletRequest forward = request("/orders");
        forward.setDispatcherType(DispatcherType.FORWARD);

        slot.doFilter(forward, new MockHttpServletResponse(), application());
        slot.doFilter(request("/orders"), new MockHttpServletResponse(), application());

        assertThat(plainRan).as("a filter that is not once per request takes requests only, as Spring Boot maps it")
                .containsExactly("plain");
        assertThat(ran).containsExactly("once", "application", "once", "application");
    }

    @Test
    @DisplayName("포함(INCLUDE) 디스패치는 포함하는 대상의 경로로 맞춘다")
    void anIncludeIsMatchedByThePathItIncludes() throws Exception {
        ContexaSlotFilterRegistration<Recording> guard = member("guard", ContexaServletFilterOrder.USER_PATH_GUARD);
        guard.setUrlPatterns(List.of("/contexa/step-up/*"));
        ContexaFilterSlot slot = slot(guard);
        MockHttpServletRequest include = request("/orders");
        include.setDispatcherType(DispatcherType.INCLUDE);
        include.setAttribute(RequestDispatcher.INCLUDE_SERVLET_PATH, "/contexa/step-up/code");

        assertThat(runs(slot, include)).isTrue();
    }

    @Test
    @DisplayName("구성원은 각자 자기 이름과 초기 매개변수로 초기화되어, 한 번만 도는 필터끼리 서로를 건너뛰지 않는다")
    void eachMemberIsInitialisedUnderItsOwnName() throws Exception {
        ContexaSlotFilterRegistration<Recording> first = member("first", ContexaServletFilterOrder.BRIDGE);
        ContexaSlotFilterRegistration<Recording> second = member("second", ContexaServletFilterOrder.CHALLENGE);
        first.addInitParameter("probe", "value");
        ContexaFilterSlot slot = slot(first, second);

        slot.doFilter(request("/orders"), new MockHttpServletResponse(), application());
        slot.destroy();

        assertThat(first.getFilter().filterConfigName()).isEqualTo("contexaFirst");
        assertThat(second.getFilter().filterConfigName()).isEqualTo("contexaSecond");
        assertThat(first.getFilter().getFilterConfig().getInitParameter("probe")).isEqualTo("value");
        assertThat(ran).containsExactly("first", "second", "application");
        assertThat(first.getFilter().destroyed).isTrue();
        assertThat(second.getFilter().destroyed).isTrue();
    }

    @Test
    @DisplayName("서블릿 이름으로 매핑한 구성원과 같은 이름의 두 구성원은 거부한다")
    void refusesWhatItCannotRunAsTheContainerWould() {
        ContexaSlotFilterRegistration<Recording> byServlet = member("servlet", ContexaServletFilterOrder.BRIDGE);
        byServlet.addServletNames("dispatcherServlet");
        ContexaSlotFilterRegistration<Recording> twin = member("twin", ContexaServletFilterOrder.CHALLENGE);
        ContexaSlotFilterRegistration<Recording> sameName = member("twin", ContexaServletFilterOrder.ACCESS_CONTROL);

        assertThatThrownBy(() -> slot(byServlet).filters())
                .isInstanceOf(IllegalStateException.class).hasMessageContaining("contexaServlet");
        assertThatThrownBy(() -> slot(twin, sameName).filters())
                .isInstanceOf(IllegalStateException.class).hasMessageContaining("contexaTwin");
    }

    @Test
    @DisplayName("슬롯 등록: 다른 모든 필터 매핑 뒤, 모든 경로와 디스패치 유형, 구성원은 빈 저장소에서 읽는다")
    void theSlotIsOneRegistrationAfterEveryOtherFilter() throws Exception {
        DefaultListableBeanFactory beanFactory = new DefaultListableBeanFactory();
        beanFactory.registerSingleton("contexaTracking", member("tracking", ContexaServletFilterOrder.SESSION_TRACKING));
        beanFactory.registerSingleton("contexaBridge", member("bridge", ContexaServletFilterOrder.BRIDGE));
        SecurityProperties moved = new SecurityProperties();
        moved.getFilter().setOrder(300);
        beanFactory.registerSingleton("securityProperties", moved);

        FilterRegistrationBean<ContexaFilterSlot> registration = new ContexaFilterSlotConfiguration()
                .filterSlotRegistration(beanFactory, beanFactory.getBeanProvider(SecurityProperties.class));
        initialised(registration.getFilter()).doFilter(request("/orders"), new MockHttpServletResponse(), application());

        assertThat(registration.isEnabled()).isTrue();
        assertThat(registration.getFilterName()).isEqualTo(ContexaFilterSlot.NAME);
        assertThat(registration.isMatchAfter()).isTrue();
        assertThat(registration.getOrder()).isEqualTo(Ordered.LOWEST_PRECEDENCE);
        assertThat(registration.getUrlPatterns()).containsExactly("/*");
        assertThat(registration.determineDispatcherTypes()).isEqualTo(EnumSet.allOf(DispatcherType.class));
        assertThat(ran).containsExactly("bridge", "tracking", "application");
    }

    private ContexaSlotFilterRegistration<Recording> member(String name, int position) {
        return ContexaServletFilterOrder.member(new Recording(name, false), contexaName(name), CHAIN, position);
    }

    private ContexaSlotFilterRegistration<Recording> answering(String name, int position) {
        return ContexaServletFilterOrder.member(new Recording(name, true), contexaName(name), CHAIN, position);
    }

    /** A slot over the given members, initialised as the servlet container initialises a filter before its first request. */
    @SafeVarargs
    private static ContexaFilterSlot slot(ContexaSlotFilterRegistration<Recording>... members) throws ServletException {
        return initialised(new ContexaFilterSlot(() -> List.of(members)));
    }

    private static ContexaFilterSlot initialised(ContexaFilterSlot slot) throws ServletException {
        slot.init(new MockFilterConfig(new MockServletContext(), ContexaFilterSlot.NAME));
        return slot;
    }

    private boolean runs(ContexaFilterSlot slot, HttpServletRequest request) throws IOException, ServletException {
        ran.clear();
        slot.doFilter(request, new MockHttpServletResponse(), application());
        return ran.size() > 1;
    }

    private FilterChain application() {
        return (ServletRequest request, ServletResponse response) -> ran.add("application");
    }

    private static Filter filterOf(ContexaFilterSlot slot, String name) {
        return slot.filters().stream()
                .filter(filter -> filter instanceof Recording recording && recording.name.equals(name))
                .findFirst()
                .orElseThrow();
    }

    private static MockHttpServletRequest request(String path) {
        MockHttpServletRequest request = new MockHttpServletRequest("GET", path);
        request.setServletPath(path);
        return request;
    }

    private static String contexaName(String name) {
        return "contexa" + Character.toUpperCase(name.charAt(0)) + name.substring(1);
    }

    /** A once-per-request filter that notes it ran, and answers 403 itself when told to. */
    private final class Recording extends OncePerRequestFilter {

        private final String name;
        private final boolean answers;
        private boolean destroyed;

        private Recording(String name, boolean answers) {
            this.name = name;
            this.answers = answers;
        }

        String filterConfigName() {
            return getFilterConfig() != null ? getFilterConfig().getFilterName() : null;
        }

        @Override
        protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
                throws ServletException, IOException {
            ran.add(name);
            if (answers) {
                response.setStatus(HttpServletResponse.SC_FORBIDDEN);
                return;
            }
            chain.doFilter(request, response);
        }

        @Override
        public void destroy() {
            destroyed = true;
        }
    }
}
