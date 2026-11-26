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
package io.contexa.contexaidentity.security.zerotrust;

import io.contexa.contexacommon.security.bridge.subject.ContexaBridge;
import io.contexa.contexacommon.security.bridge.subject.ContexaBridgeResult;
import io.contexa.contexacommon.security.bridge.subject.ContexaSubject;
import jakarta.servlet.http.HttpServletRequest;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.authentication.event.LogoutSuccessEvent;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;

import java.util.ArrayList;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

/** docs/agent/bridge-v2-B5-2-B5-3-설계안.md 2: a Spring Security sign-out is told to Contexa as ContexaBridge tells it. */
@DisplayName("bridge v2 갈래 S 로그아웃: 앱의 Spring Security 로그아웃이 로그아웃 알림과 같은 처리로 이어진다")
class SandboxSignOutListenerTest {

    private final List<String> signedOut = new ArrayList<>();

    @AfterEach
    void clear() {
        ContexaBridge.clearHandler();
        RequestContextHolder.resetRequestAttributes();
    }

    @Test
    @DisplayName("로그아웃 이벤트의 사용자가 그 요청으로 로그아웃 처리된다")
    void theSignedOutUserIsToldOnItsRequest() {
        ContexaBridge.registerHandler(recording());
        MockHttpServletRequest request = new MockHttpServletRequest("POST", "/logout");
        RequestContextHolder.setRequestAttributes(new ServletRequestAttributes(request));

        new SandboxSignOutListener().onApplicationEvent(new LogoutSuccessEvent(
                UsernamePasswordAuthenticationToken.authenticated("kim01", null, List.of())));

        assertThat(signedOut).containsExactly("kim01");
    }

    @Test
    @DisplayName("요청 밖의 로그아웃 이벤트는 아무것도 하지 않는다")
    void aSignOutOutsideARequestTellsNothing() {
        ContexaBridge.registerHandler(recording());

        new SandboxSignOutListener().onApplicationEvent(new LogoutSuccessEvent(
                UsernamePasswordAuthenticationToken.authenticated("kim01", null, List.of())));

        assertThat(signedOut).isEmpty();
    }

    private ContexaBridge.Handler recording() {
        return new ContexaBridge.Handler() {
            @Override
            public ContexaBridgeResult signedIn(HttpServletRequest request, ContexaSubject subject) {
                return ContexaBridgeResult.done();
            }

            @Override
            public ContexaBridgeResult signInFailed(HttpServletRequest request, String userId) {
                return ContexaBridgeResult.done();
            }

            @Override
            public ContexaBridgeResult signedOut(HttpServletRequest request, String userId) {
                signedOut.add(userId);
                return ContexaBridgeResult.done();
            }
        };
    }
}
