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
