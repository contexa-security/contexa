package io.contexa.contexacore.autonomous.saas.client;

import io.contexa.contexacore.autonomous.saas.dto.ThreatIntelligenceSnapshot;
import io.contexa.contexacore.properties.SaasForwardingProperties;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.MediaType;
import org.springframework.test.web.client.MockRestServiceServer;
import org.springframework.web.client.RestClient;

import java.util.List;

import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.client.match.MockRestRequestMatchers.*;
import static org.springframework.test.web.client.response.MockRestResponseCreators.withSuccess;

class SaasThreatIntelligenceHttpClientTest {

    private SaasDecisionAccessTokenProvider accessTokenProvider;
    private MockRestServiceServer server;
    private SaasThreatIntelligenceHttpClient client;

    @BeforeEach
    void setUp() {
        accessTokenProvider = mock(SaasDecisionAccessTokenProvider.class);
        when(accessTokenProvider.getAccessToken()).thenReturn("saas-access-token");

        RestClient.Builder builder = RestClient.builder();
        server = MockRestServiceServer.bindTo(builder).build();
        client = new SaasThreatIntelligenceHttpClient(properties(), accessTokenProvider, builder.baseUrl("https://saas.example.com").build());
    }

    @Test
    void fetchSignalsUsesBearerTokenAndLimit() {
        server.expect(requestTo("https://saas.example.com/api/saas/runtime/ai-tuning/threat-signals?limit=4"))
                .andExpect(method(HttpMethod.GET))
                .andExpect(header(HttpHeaders.AUTHORIZATION, "Bearer saas-access-token"))
                .andRespond(withSuccess("""
                        {
                          "tenantId": "tenant-acme",
                          "featureEnabled": true,
                          "sharingEnabled": true,
                          "signals": [
                            {
                              "signalKey": "signal-001",
                              "status": "ACTIVE",
                              "canonicalThreatClass": "credential_abuse",
                              "geoCountry": "KR",
                              "mitreTacticHints": ["Initial Access"],
                              "affectedTenantCount": 3,
                              "observationCount": 4,
                              "summary": "Cross-tenant campaign detected."
                            }
                          ]
                        }
                        """, MediaType.APPLICATION_JSON));

        ThreatIntelligenceSnapshot snapshot = client.fetchSignals(4);

        assertThat(snapshot.tenantId()).isEqualTo("tenant-acme");
        assertThat(snapshot.signals()).hasSize(1);
        assertThat(snapshot.signals().getFirst().canonicalThreatClass()).isEqualTo("credential_abuse");
        server.verify();
    }

    private SaasForwardingProperties properties() {
        return SaasForwardingProperties.builder()
                .enabled(true)
                .endpoint("https://saas.example.com")
                .pseudonymizationSecret("top-secret-key")
                .globalCorrelationSecret("global-correlation-secret")
                .outboxBatchSize(50)
                .maxRetryAttempts(10)
                .retryInitialBackoffMs(1000L)
                .retryMaxBackoffMs(5000L)
                .dispatchIntervalMs(30000L)
                .oauth2(SaasForwardingProperties.OAuth2.builder()
                        .enabled(true)
                        .registrationId("reg")
                        .tokenUri("https://auth.example.com/oauth2/token")
                        .clientId("client")
                        .clientSecret("secret")
                        .scope(String.join(" ", List.of(
                                SaasForwardingProperties.XAI_DECISION_INGEST_SCOPE,
                                SaasForwardingProperties.THREAT_INTELLIGENCE_READ_SCOPE)))
                        .expirySkewSeconds(30)
                        .build())
                .threatIntelligence(SaasForwardingProperties.ThreatIntelligence.builder()
                        .enabled(true)
                        .endpointPath("/api/saas/runtime/ai-tuning/threat-signals")
                        .pullIntervalMs(3_600_000L)
                        .initialDelayMs(0L)
                        .signalLimit(5)
                        .promptLimit(3)
                        .cacheTtlMinutes(90)
                        .build())
                .build();
    }
}
