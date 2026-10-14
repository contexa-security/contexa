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
package io.contexa.contexacore.autonomous.context.support;

import org.junit.jupiter.api.Test;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

class IdentityTokenNormalizerTest {

    @Test
    void anOAuth2ScopeAuthorityIsAPermissionNotARole() {
        // N-ID-1 (D7, G6-2): Spring's OAuth2 resource server grants each token scope as a SCOPE_ authority. It is a
        // permission the token carries; read as a role it became the requester's role SCOPE_READ.
        assertThat(IdentityTokenNormalizer.normalizeRoleStrings(List.of("ROLE_ANALYST", "SCOPE_read", "auditor")))
                .containsExactly("ANALYST", "AUDITOR");
        assertThat(IdentityTokenNormalizer.normalizeAuthorityStrings(List.of("ROLE_ANALYST", "SCOPE_read")))
                .containsExactly("SCOPE_read");
        assertThat(IdentityTokenNormalizer.normalizePermissionStrings(List.of("SCOPE_read", "report.read")))
                .containsExactly("SCOPE_read", "report.read");
    }
}
