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
import org.junit.jupiter.params.provider.NullAndEmptySource;
import org.junit.jupiter.params.provider.ValueSource;

import static org.assertj.core.api.Assertions.assertThat;

class SameAppPathTest {

    @ParameterizedTest
    @ValueSource(strings = {"/", "/orders", "/orders/", "/orders/42?tab=open#top", "/a%20b", "/a b",
            "/orders?next=//elsewhere.example", "/orders#//elsewhere.example", "/...", "/.hidden", "/a.b/c"})
    @DisplayName("A path of the application is accepted")
    void acceptsPaths(String address) {
        assertThat(SameAppPath.isWithin(address, "")).isTrue();
    }

    @ParameterizedTest
    @NullAndEmptySource
    @ValueSource(strings = {" ", "orders", "./orders", "https://evil.example", "//evil.example", "/\\evil.example",
            "javascript:alert(1)", "/\tx", "/x\ny", "/\u007f", "/%", "/%zz", "/a//b", "/a/./b", "/a/../b", "/..", "/."})
    @DisplayName("Anything else is refused")
    void refusesEverythingElse(String address) {
        assertThat(SameAppPath.isWithin(address, "")).isFalse();
    }

    @ParameterizedTest
    @ValueSource(strings = {"/%2Fevil.example", "/%252Fevil.example", "/%25252Fevil.example", "/%5Cevil.example",
            "/%255cevil.example", "/%09/evil.example", "/%2e%2e/evil", "/%252e%252e/evil", "/%3Bx"})
    @DisplayName("An encoded form is refused at any depth that is read")
    void refusesEncodedForms(String address) {
        assertThat(SameAppPath.isWithin(address, "")).isFalse();
    }

    @Test
    @DisplayName("A value wrapped deeper than the layers read is refused rather than trusted")
    void refusesDeeperLayers() {
        assertThat(SameAppPath.isWithin("/%2525252525252Fevil.example", "")).isFalse();
    }

    @Test
    @DisplayName("Under a context path only that path and what lies below it are within the application")
    void respectsTheContextPath() {
        assertThat(SameAppPath.isWithin("/app", "/app")).isTrue();
        assertThat(SameAppPath.isWithin("/app/", "/app")).isTrue();
        assertThat(SameAppPath.isWithin("/app/orders?x=1", "/app")).isTrue();
        assertThat(SameAppPath.isWithin("/app?x=1", "/app")).isTrue();
        assertThat(SameAppPath.isWithin("/", "/app")).isFalse();
        assertThat(SameAppPath.isWithin("/application", "/app")).isFalse();
        assertThat(SameAppPath.isWithin("/app/../other", "/app")).isFalse();
    }

    @Test
    @DisplayName("Without a context path the root of the server is the application")
    void aMissingContextPathIsTheRoot() {
        assertThat(SameAppPath.isWithin("/orders", null)).isTrue();
    }

    @Test
    @DisplayName("orElse keeps a path and replaces anything else")
    void orElseReplacesWhatIsRefused() {
        assertThat(SameAppPath.orElse("/orders", "", "/")).isEqualTo("/orders");
        assertThat(SameAppPath.orElse("//evil.example", "", "/")).isEqualTo("/");
        assertThat(SameAppPath.orElse(null, "", "/")).isEqualTo("/");
    }
}
