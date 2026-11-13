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
package io.contexa.contexaidentity.security.utils;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class UrlPrefixesTest {

    /** A prefix that shares the first letters of an address is no prefix of it: /secure is not under /sec. */
    @Test
    void anAddressIsUnderAPrefixOnlyAtAPathBoundary() {
        assertThat(UrlPrefixes.isUnder("/secure", "/secure")).isTrue();
        assertThat(UrlPrefixes.isUnder("/secure/mfa/login", "/secure")).isTrue();
        assertThat(UrlPrefixes.isUnder("/secure?error", "/secure")).isTrue();
        assertThat(UrlPrefixes.isUnder("/secure#top", "/secure")).isTrue();
        assertThat(UrlPrefixes.isUnder("/securex/mfa/login", "/secure")).isFalse();
        assertThat(UrlPrefixes.isUnder("/mfa/login", "/m")).isFalse();
        assertThat(UrlPrefixes.isUnder(null, "/secure")).isFalse();
        assertThat(UrlPrefixes.isUnder("/secure", null)).isFalse();
    }

    @Test
    void theDefaultAddressGetsThePrefixEvenWhenItBeginsWithTheSameLetters() {
        assertThat(UrlPrefixes.apply("/m", "/mfa/login")).isEqualTo("/m/mfa/login");
        assertThat(UrlPrefixes.apply("/secure", "/mfa/login")).isEqualTo("/secure/mfa/login");
        assertThat(UrlPrefixes.apply("/secure", "/secure/mfa/login")).isEqualTo("/secure/mfa/login");
        assertThat(UrlPrefixes.apply(null, "/mfa/login")).isEqualTo("/mfa/login");
        assertThat(UrlPrefixes.apply("", "/mfa/login")).isEqualTo("/mfa/login");
        assertThat(UrlPrefixes.apply("/secure", null)).isNull();
    }

    @ParameterizedTest
    @ValueSource(strings = {"/admin", "/admin/area", "/a_b-c", "/A1"})
    void aPlainPathIsAPrefix(String prefix) {
        assertThatCode(() -> UrlPrefixes.validate(prefix)).doesNotThrowAnyException();
    }

    /** These left the flow's chain matching no request: its paths were outside every chain. */
    @ParameterizedTest
    @ValueSource(strings = {"/secure/", "//secure", "/", "secure", "/se cure", "/invalid#prefix", "/a//b", ""})
    void anyOtherValueStopsTheStartAndSaysWhatWasGiven(String prefix) {
        assertThatThrownBy(() -> UrlPrefixes.validate(prefix))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("urlPrefix must be a path such as")
                .hasMessageContaining("Given: \"" + prefix + "\"");
    }

    @Test
    void noPrefixIsNoPrefixToCheck() {
        assertThatCode(() -> UrlPrefixes.validate(null)).doesNotThrowAnyException();
    }
}
