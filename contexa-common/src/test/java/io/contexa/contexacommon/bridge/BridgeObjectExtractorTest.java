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

import io.contexa.contexacommon.security.bridge.BridgeObjectExtractor;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

class BridgeObjectExtractorTest {

    @Test
    void extractBooleanShouldNotPromoteAuthenticationMethodCollectionsIntoBooleanFacts() {
        Boolean extracted = BridgeObjectExtractor.extractBoolean(
                Map.of("amr", List.of("pwd", "mfa", "webauthn")),
                List.of("amr"));

        assertThat(extracted).isNull();
    }

    @Test
    void extractBooleanShouldParseOnlyExplicitBooleanRepresentations() {
        assertThat(BridgeObjectExtractor.extractBoolean(Map.of("flag", "true"), List.of("flag"))).isTrue();
        assertThat(BridgeObjectExtractor.extractBoolean(Map.of("flag", "no"), List.of("flag"))).isFalse();
        assertThat(BridgeObjectExtractor.extractBoolean(Map.of("flag", List.of("1")), List.of("flag"))).isTrue();
    }

    public static class HostPrincipal {
        private final String loginId = "kim";
        public String getDisplayName() {
            return "Kim";
        }
        public boolean isMfaDone() {
            return true;
        }
    }

    @Test
    void membersOfAHostObjectAreFoundByAccessorOrFieldAndTheAnswerDoesNotChangeOnTheNextCall() {
        HostPrincipal principal = new HostPrincipal();
        for (int round = 0; round < 3; round++) {
            assertThat(BridgeObjectExtractor.extractString(principal, List.of("displayName"))).isEqualTo("Kim");
            assertThat(BridgeObjectExtractor.extractString(principal, List.of("loginId"))).isEqualTo("kim");
            assertThat(BridgeObjectExtractor.extractBoolean(principal, List.of("mfaDone"))).isTrue();
            assertThat(BridgeObjectExtractor.extractString(principal, List.of("absent", "displayName"))).isEqualTo("Kim");
            assertThat(BridgeObjectExtractor.extractString(principal, List.of("absent"))).isNull();
        }
    }

    @Test
    void aKeyThatIsAbsentIsLookedUpOnceNotOnEveryRequest() {
        HostPrincipal principal = new HostPrincipal();
        BridgeObjectExtractor.extractString(principal, List.of("neverThere"));
        long began = System.nanoTime();
        for (int i = 0; i < 20_000; i++) {
            BridgeObjectExtractor.extractString(principal, List.of("neverThere"));
        }
        long millis = (System.nanoTime() - began) / 1_000_000;
        // a failed reflective lookup builds an exception each time: 20,000 of them take far longer than this bound
        assertThat(millis).isLessThan(500);
    }
}
