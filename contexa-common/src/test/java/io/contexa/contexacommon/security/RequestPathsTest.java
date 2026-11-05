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
package io.contexa.contexacommon.security;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.springframework.mock.web.MockHttpServletRequest;

import static org.assertj.core.api.Assertions.assertThat;

class RequestPathsTest {

    @Test
    @DisplayName("the path of a request leaves out the context path")
    void withoutTheContextPath() {
        MockHttpServletRequest request = new MockHttpServletRequest("GET", "/app/logout");
        request.setContextPath("/app");

        assertThat(RequestPaths.of(request)).isEqualTo("/logout");
    }

    @Test
    @DisplayName("exactly: the target with or without a closing slash, nothing else")
    void exactly() {
        assertThat(RequestPaths.isExactly("/logout", "/logout")).isTrue();
        assertThat(RequestPaths.isExactly("/logout/", "/logout")).isTrue();
        assertThat(RequestPaths.isExactly("/logout-report", "/logout")).isFalse();
        assertThat(RequestPaths.isExactly("/logout/report", "/logout")).isFalse();
        assertThat(RequestPaths.isExactly("/logout", null)).isFalse();
        assertThat(RequestPaths.isExactly(null, "/logout")).isFalse();
    }

    @Test
    @DisplayName("within: the folder and what is below it, not a name that starts the same")
    void within() {
        assertThat(RequestPaths.isWithin("/contexa/zero-trust", "/contexa/zero-trust")).isTrue();
        assertThat(RequestPaths.isWithin("/contexa/zero-trust/blocked", "/contexa/zero-trust")).isTrue();
        assertThat(RequestPaths.isWithin("/contexa/zero-trust-export", "/contexa/zero-trust")).isFalse();
        assertThat(RequestPaths.isWithin("/contexa/zero-trust", null)).isFalse();
    }

    @ParameterizedTest
    @ValueSource(strings = {"/logout;x=1", "/logout/..;/owners", "/logout/../owners", "/logout/%2e%2e/owners", "/logout//",
            "/logout\\..\\owners", "/logout/%2F", "/logout%00"})
    @DisplayName("a path the container may resolve to another one is never plain, and matches nothing")
    void notPlain(String path) {
        assertThat(RequestPaths.isPlain(path)).isFalse();
        assertThat(RequestPaths.isExactly(path, "/logout")).isFalse();
        assertThat(RequestPaths.isWithin(path, "/logout")).isFalse();
    }
}
