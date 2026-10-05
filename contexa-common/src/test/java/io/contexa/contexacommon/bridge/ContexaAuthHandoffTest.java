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

import io.contexa.contexacommon.security.bridge.handoff.ContexaAuthHandoff;
import org.junit.jupiter.api.Test;

import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.assertj.core.api.Assertions.entry;

class ContexaAuthHandoffTest {

    @Test
    void shouldDropNullAttributeKeysAndValuesAndKeepRemainingAttributesInOrder() {
        Map<String, Object> attributes = new LinkedHashMap<>();
        attributes.put("principalId", "customer-123");
        attributes.put("jwtAudience", null);
        attributes.put("displayName", "Customer");
        attributes.put(null, "orphan");
        attributes.put("organizationId", "org-a");

        ContexaAuthHandoff handoff = ContexaAuthHandoff.of("customer-123", List.of("ROLE_USER"), attributes);

        assertThat(handoff.attributes()).containsExactly(
                entry("principalId", "customer-123"),
                entry("displayName", "Customer"),
                entry("organizationId", "org-a"));
        assertThat(handoff.authorities()).isEqualTo(List.of("ROLE_USER"));
        assertThatThrownBy(() -> handoff.attributes().put("extra", "value"))
                .isInstanceOf(UnsupportedOperationException.class);
    }

    @Test
    void shouldDropNullAuthorityElementsAndKeepRemainingAuthoritiesInOrder() {
        List<String> authorities = Arrays.asList("ROLE_USER", null, "ROLE_ADMIN", "ROLE_USER");

        ContexaAuthHandoff handoff = ContexaAuthHandoff.of("customer-123", authorities);

        assertThat(handoff.authorities()).isEqualTo(List.of("ROLE_USER", "ROLE_ADMIN"));
        assertThatThrownBy(() -> handoff.authorities().clear())
                .isInstanceOf(UnsupportedOperationException.class);
    }
}
