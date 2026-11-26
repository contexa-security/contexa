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
package io.contexa.contexacommon.bridge;

import io.contexa.contexacommon.security.bridge.BridgeProperties;
import io.contexa.contexacommon.security.bridge.BridgeRequestAttributes;
import io.contexa.contexacommon.security.bridge.coverage.BridgeCoverageEvaluator;
import io.contexa.contexacommon.security.bridge.resolver.SecurityContextAuthenticationStampResolver;
import io.contexa.contexacommon.security.bridge.resolver.SecurityContextAuthorizationStampResolver;
import io.contexa.contexacommon.security.bridge.sensor.RequestContextCollector;
import io.contexa.contexacommon.security.bridge.stamp.AuthenticationStamp;
import io.contexa.contexacommon.security.bridge.web.BridgeResolutionFilter;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockFilterChain;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.context.SecurityContextHolder;

import java.util.Collections;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * The request attributes an application keeps are its own, also those under names the bridge once read
 * ({@code ctxa.auth.*}, {@code ctxa.authz.*}, {@code ctxa.delegation.*}, bridge v1). What Contexa resolves goes to its own
 * names ({@code ctxa.bridge.*}) only: written back into the application's names, it replaced the application's values,
 * removed the ones the stamp had none for, changed their type, and a later resolution of the same request read
 * Contexa's own output as the application's evidence.
 */
class BridgeOutputNamespaceTest {

    @AfterEach
    void clear() {
        SecurityContextHolder.clearContext();
    }

    @Test
    @DisplayName("애플리케이션이 입력 이름에 넣은 값은 해석 뒤에도 넣은 그대로 남는다")
    void theApplicationsInputStaysAsItWroteIt() throws Exception {
        BridgeProperties properties = new BridgeProperties();
        signIn("alice");
        MockHttpServletRequest request = new MockHttpServletRequest("GET", "/reports");
        request.setAttribute("ctxa.authz.scopeTags", "finance,approval");
        request.setAttribute("ctxa.auth.time", "2026-03-23T09:00:00Z");
        request.setAttribute("ctxa.auth.displayName", "Alice of the application");

        filter(properties).doFilter(request, new MockHttpServletResponse(), new MockFilterChain());

        assertThat(request.getAttribute(BridgeRequestAttributes.AUTHENTICATION_STAMP)).isInstanceOf(AuthenticationStamp.class);
        assertThat(request.getAttribute("ctxa.authz.scopeTags")).isEqualTo("finance,approval");
        assertThat(request.getAttribute("ctxa.auth.time")).isEqualTo("2026-03-23T09:00:00Z");
        assertThat(request.getAttribute("ctxa.auth.displayName")).isEqualTo("Alice of the application");
    }

    @Test
    @DisplayName("Contexa는 해석 결과를 ctxa.bridge 이름에만 쓰고 애플리케이션 입력 이름에는 쓰지 않는다")
    void contexaWritesOnlyItsOwnNames() throws Exception {
        BridgeProperties properties = new BridgeProperties();
        signIn("alice");
        MockHttpServletRequest request = new MockHttpServletRequest("GET", "/reports");

        filter(properties).doFilter(request, new MockHttpServletResponse(), new MockFilterChain());

        List<String> names = Collections.list(request.getAttributeNames());
        assertThat(names).contains(BridgeRequestAttributes.RESOLUTION_RESULT, BridgeRequestAttributes.AUTHENTICATION_STAMP);
        assertThat(names).filteredOn(name -> name.startsWith("ctxa."))
                .allSatisfy(name -> assertThat(name).startsWith("ctxa.bridge."));
    }

    private static void signIn(String username) {
        SecurityContextHolder.getContext().setAuthentication(UsernamePasswordAuthenticationToken.authenticated(
                username, null, AuthorityUtils.createAuthorityList("ROLE_HOST")));
    }

    /** The stamp resolvers the auto-configuration registers for a signed-in Spring Security user (bridge v2). */
    private static BridgeResolutionFilter filter(BridgeProperties properties) {
        return new BridgeResolutionFilter(
                properties,
                new RequestContextCollector(),
                List.of(new SecurityContextAuthenticationStampResolver()),
                List.of(new SecurityContextAuthorizationStampResolver()),
                List.of(),
                new BridgeCoverageEvaluator());
    }
}
