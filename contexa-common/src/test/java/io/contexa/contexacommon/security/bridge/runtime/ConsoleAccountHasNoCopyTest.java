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
package io.contexa.contexacommon.security.bridge.runtime;

import io.contexa.contexacommon.operating.ContexaOperatingProfile;
import io.contexa.contexacommon.security.ConsoleSession;
import io.contexa.contexacommon.security.bridge.BridgeProperties;
import io.contexa.contexacommon.security.bridge.sensor.RequestContextSnapshot;
import io.contexa.contexacommon.security.bridge.stamp.AuthenticationStamp;
import io.contexa.contexacommon.security.bridge.sync.BridgeUserMirrorSyncResult;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.mock.env.MockEnvironment;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;

import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicInteger;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * R-12 and R-13 of docs/agent/운영모드-정상화-구현계획.md: the console's administrators sign in with Contexa's own accounts
 * on a chain of their own wherever the console is apart from the application (every way of running but FULL with
 * CONTEXA_OWNED), and the bridge reads the console's requests too. Such an account is the record of the person: the bridge
 * makes no copy of it, as it makes none of an account the main chain signs in.
 */
@DisplayName("콘솔 요청의 Contexa 계정은 사본을 만들지 않는다(R-12, R-13)")
class ConsoleAccountHasNoCopyTest {

    private final AtomicInteger copies = new AtomicInteger();
    private final Authentication administrator = UsernamePasswordAuthenticationToken.authenticated("admin", null,
            AuthorityUtils.createAuthorityList("ROLE_ADMIN"));

    @AfterEach
    void clear() {
        RequestContextHolder.resetRequestAttributes();
    }

    @Test
    @DisplayName("SANDBOX 콘솔 요청의 관리자 계정은 사본을 만들지 않는다")
    void anAdministratorOfTheConsoleHasNoCopy() {
        MockHttpServletRequest request = new MockHttpServletRequest("GET", "/contexa/admin/blacklist");
        ConsoleSession.mark(request);
        RequestContextHolder.setRequestAttributes(new ServletRequestAttributes(request));

        BridgeUserMirrorSyncResult result = support("SANDBOX").synchronizeUser(administrator, stamp("admin"), null,
                requestContext(), true);

        assertThat(result).isNull();
        assertThat(copies).hasValue(0);
    }

    @Test
    @DisplayName("SANDBOX 앱 요청의 사용자는 지금처럼 사본을 가진다")
    void anApplicationsUserKeepsItsCopy() {
        RequestContextHolder.setRequestAttributes(new ServletRequestAttributes(new MockHttpServletRequest("GET", "/orders")));

        support("SANDBOX").synchronizeUser(administrator, stamp("admin"), null, requestContext(), true);

        assertThat(copies).hasValue(1);
    }

    private BridgeRuntimeSupport support(String mode) {
        BridgeProperties properties = new BridgeProperties();
        properties.setEnvironment(new MockEnvironment().withProperty(ContexaOperatingProfile.PROP_MODE, mode));
        return new BridgeRuntimeSupport(properties, (authenticationStamp, authorizationStamp, requestContext) -> {
            copies.incrementAndGet();
            return new BridgeUserMirrorSyncResult(9L, "brg_copy", authenticationStamp.principalId(), "brg_copy", true,
                    true, true, false);
        });
    }

    private static AuthenticationStamp stamp(String subject) {
        return new AuthenticationStamp(subject, subject, "USER", true, "UsernamePasswordAuthenticationToken",
                "SECURITY_CONTEXT", null, null, null, "session-1", List.of("ROLE_ADMIN"), Map.of());
    }

    private static RequestContextSnapshot requestContext() {
        return new RequestContextSnapshot("/contexa/admin/blacklist", "GET", "10.0.0.10", "JUnit", "session-1",
                "request-1", "/contexa/admin/blacklist", null, false, Instant.now());
    }
}
