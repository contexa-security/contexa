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
package io.contexa.contexacore.autonomous.saas.security;

import io.contexa.contexacore.properties.SaasForwardingProperties;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

class TenantScopedPseudonymizationServiceTest {

    @Test
    void hashUsesTenantScopeAndProducesStableDigest() {
        TenantScopedPseudonymizationService service = new TenantScopedPseudonymizationService(properties());

        String tenantAcme = service.hash("tenant-acme", "user-1");
        String tenantAcmeAgain = service.hash("tenant-acme", "user-1");
        String tenantGlobex = service.hash("tenant-globex", "user-1");

        assertThat(tenantAcme).isEqualTo(tenantAcmeAgain);
        assertThat(tenantAcme).isNotEqualTo(tenantGlobex);
    }

    @Test
    void hashGlobalProducesStableDigestAcrossTenants() {
        TenantScopedPseudonymizationService service = new TenantScopedPseudonymizationService(properties());

        String first = service.hashGlobal("10.10.10.10");
        String second = service.hashGlobal("10.10.10.10");
        String different = service.hashGlobal("10.10.10.11");

        assertThat(first).isEqualTo(second);
        assertThat(first).isNotEqualTo(different);
    }

    private SaasForwardingProperties properties() {
        return SaasForwardingProperties.builder()
                .enabled(true)
                .endpoint("https://saas.example.com")
                .pseudonymizationSecret("top-secret-key")
                .globalCorrelationSecret("global-correlation-secret")
                .oauth2(SaasForwardingProperties.OAuth2.builder()
                        .enabled(true)
                        .registrationId("reg")
                        .tokenUri("https://auth.example.com/oauth2/token")
                        .clientId("client")
                        .clientSecret("secret")
                        .scope("saas.xai.decision.ingest")
                        .expirySkewSeconds(30)
                        .build())
                .build();
    }
}
