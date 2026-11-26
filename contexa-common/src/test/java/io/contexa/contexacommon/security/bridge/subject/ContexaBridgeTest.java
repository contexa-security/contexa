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
package io.contexa.contexacommon.security.bridge.subject;

import io.contexa.contexacommon.security.bridge.subject.ContexaBridgeResult.Outcome;
import jakarta.servlet.http.HttpServletRequest;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;

import java.util.ArrayList;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

/** docs/agent/bridge-v2-B5-2-B5-3-설계안.md 2: the optional calls of contract 6 never throw to the application. */
@DisplayName("bridge v2 선택 API: 레거시가 부르는 로그인·실패·로그아웃·삭제 알림은 예외를 던지지 않고 결과로 알린다")
class ContexaBridgeTest {

    private final MockHttpServletRequest request = new MockHttpServletRequest("POST", "/legacy/login");

    @AfterEach
    void clear() {
        ContexaBridge.clearHandler();
        ContexaUsers.clearHandler();
    }

    @Test
    @DisplayName("Contexa가 시작되지 않았으면 네 알림 모두 NOT_INITIALIZED로 답한다")
    void beforeContexaStartsEveryCallAnswersNotInitialized() {
        assertThat(ContexaBridge.isInitialized()).isFalse();
        assertThat(ContexaUsers.isInitialized()).isFalse();

        assertThat(ContexaBridge.signedIn(request, ContexaSubject.of("kim01", "kim01@seum.example").build()).outcome())
                .isEqualTo(Outcome.NOT_INITIALIZED);
        assertThat(ContexaBridge.signInFailed(request, "kim01").outcome()).isEqualTo(Outcome.NOT_INITIALIZED);
        assertThat(ContexaBridge.signedOut(request, "kim01").outcome()).isEqualTo(Outcome.NOT_INITIALIZED);
        assertThat(ContexaUsers.delete("kim01").outcome()).isEqualTo(Outcome.NOT_INITIALIZED);
    }

    @Test
    @DisplayName("요청이나 주체가 없거나 아이디가 규칙을 어기면 처리기를 부르지 않고 INVALID로 답한다")
    void whatBreaksTheContractIsInvalidAndReachesNoHandler() {
        Recording handler = new Recording();
        ContexaBridge.registerHandler(handler);
        ContexaUsers.registerHandler(handler);

        assertThat(ContexaBridge.signedIn(null, ContexaSubject.of("kim01", null).build()).outcome())
                .isEqualTo(Outcome.INVALID);
        assertThat(ContexaBridge.signedIn(request, null).outcome()).isEqualTo(Outcome.INVALID);
        assertThat(ContexaBridge.signedIn(request, ContexaSubject.of(" ", null).build()).outcome())
                .isEqualTo(Outcome.INVALID);
        assertThat(ContexaBridge.signInFailed(request, "").outcome()).isEqualTo(Outcome.INVALID);
        assertThat(ContexaBridge.signInFailed(request, "kim\u000001").outcome()).isEqualTo(Outcome.INVALID);
        assertThat(ContexaBridge.signedOut(null, "kim01").outcome()).isEqualTo(Outcome.INVALID);
        assertThat(ContexaUsers.delete(null).outcome()).isEqualTo(Outcome.INVALID);
        assertThat(ContexaUsers.delete("x".repeat(256)).outcome()).isEqualTo(Outcome.INVALID);

        assertThat(handler.calls).isEmpty();
    }

    @Test
    @DisplayName("규칙을 지킨 알림은 등록된 처리기에 아이디를 앞뒤 공백 없이 넘기고 그 결과를 돌려준다")
    void aCallThatKeepsTheContractReachesTheHandler() {
        Recording handler = new Recording();
        ContexaBridge.registerHandler(handler);
        ContexaUsers.registerHandler(handler);

        assertThat(ContexaBridge.signedIn(request, ContexaSubject.of("kim01", "kim01@seum.example").build()).isDone())
                .isTrue();
        assertThat(ContexaBridge.signInFailed(request, " kim01 ").isDone()).isTrue();
        assertThat(ContexaBridge.signedOut(request, "kim01").isDone()).isTrue();
        assertThat(ContexaUsers.delete("kim01").isDone()).isTrue();

        assertThat(handler.calls).containsExactly("signedIn kim01", "signInFailed kim01", "signedOut kim01",
                "delete kim01");
    }

    @Test
    @DisplayName("처리기가 예외를 던지거나 아무것도 돌려주지 않으면 레거시 요청에 번지지 않고 FAILED로 답한다")
    void aHandlerThatFailsIsAnsweredFailed() {
        ContexaBridge.registerHandler(new ContexaBridge.Handler() {
            @Override
            public ContexaBridgeResult signedIn(HttpServletRequest request, ContexaSubject subject) {
                throw new IllegalStateException("database down");
            }

            @Override
            public ContexaBridgeResult signInFailed(HttpServletRequest request, String userId) {
                return null;
            }

            @Override
            public ContexaBridgeResult signedOut(HttpServletRequest request, String userId) {
                throw new StackOverflowError();
            }
        });
        ContexaUsers.registerHandler(userId -> {
            throw new IllegalArgumentException("broken");
        });

        assertThat(ContexaBridge.signedIn(request, ContexaSubject.of("kim01", null).build()).outcome())
                .isEqualTo(Outcome.FAILED);
        assertThat(ContexaBridge.signInFailed(request, "kim01").outcome()).isEqualTo(Outcome.FAILED);
        assertThat(ContexaBridge.signedOut(request, "kim01").outcome()).isEqualTo(Outcome.FAILED);
        assertThat(ContexaUsers.delete("kim01").outcome()).isEqualTo(Outcome.FAILED);
    }

    private static final class Recording implements ContexaBridge.Handler, ContexaUsers.Handler {

        private final List<String> calls = new ArrayList<>();

        @Override
        public ContexaBridgeResult signedIn(HttpServletRequest request, ContexaSubject subject) {
            calls.add("signedIn " + subject.getUserId());
            return ContexaBridgeResult.done();
        }

        @Override
        public ContexaBridgeResult signInFailed(HttpServletRequest request, String userId) {
            calls.add("signInFailed " + userId);
            return ContexaBridgeResult.done();
        }

        @Override
        public ContexaBridgeResult signedOut(HttpServletRequest request, String userId) {
            calls.add("signedOut " + userId);
            return ContexaBridgeResult.done();
        }

        @Override
        public ContexaBridgeResult delete(String userId) {
            calls.add("delete " + userId);
            return ContexaBridgeResult.done();
        }
    }
}
