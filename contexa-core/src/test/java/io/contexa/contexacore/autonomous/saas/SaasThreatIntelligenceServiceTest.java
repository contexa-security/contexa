package io.contexa.contexacore.autonomous.saas;

import io.contexa.contexacore.autonomous.domain.SecurityEvent;
import io.contexa.contexacore.autonomous.saas.client.SaasThreatIntelligenceHttpClient;
import io.contexa.contexacore.autonomous.saas.dto.ThreatIntelligenceMatchContext;
import io.contexa.contexacore.autonomous.saas.dto.ThreatIntelligenceSnapshot;
import io.contexa.contexacore.autonomous.tiered.template.SecurityPromptTemplate;
import io.contexa.contexacore.properties.SaasForwardingProperties;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.time.LocalDateTime;
import java.util.List;
import java.util.Map;

import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class SaasThreatIntelligenceServiceTest {

    private SaasThreatIntelligenceHttpClient httpClient;
    private SaasThreatIntelligenceService service;

    @BeforeEach
    void setUp() {
        httpClient = mock(SaasThreatIntelligenceHttpClient.class);
        service = new SaasThreatIntelligenceService(properties(), httpClient);
    }

    @Test
    void refreshCachesSignalsAndReturnsPromptLimitedSignalsInPriorityOrder() {
        when(httpClient.fetchSignals(5)).thenReturn(new ThreatIntelligenceSnapshot(
                "tenant-acme",
                true,
                true,
                List.of(
                        signal("signal-low", 2, 3, LocalDateTime.of(2026, 3, 17, 8, 0)),
                        signal("signal-high", 5, 8, LocalDateTime.of(2026, 3, 17, 10, 0)),
                        signal("signal-mid", 4, 5, LocalDateTime.of(2026, 3, 17, 9, 0))),
                LocalDateTime.of(2026, 3, 17, 10, 5)));

        service.refresh();

        assertThat(service.currentSnapshot().tenantId()).isEqualTo("tenant-acme");
        assertThat(service.getPromptSignals())
                .extracting(ThreatIntelligenceSnapshot.ThreatSignalItem::signalKey)
                .containsExactly("signal-high", "signal-mid");
    }

    @Test
    void promptSignalsAreSuppressedWhenSharingIsDisabled() {
        when(httpClient.fetchSignals(5)).thenReturn(new ThreatIntelligenceSnapshot(
                "tenant-acme",
                true,
                false,
                List.of(signal("signal-hidden", 4, 6, LocalDateTime.of(2026, 3, 17, 10, 0))),
                LocalDateTime.of(2026, 3, 17, 10, 5)));

        service.refresh();

        assertThat(service.getPromptSignals()).isEmpty();
    }

    @Test
    void buildThreatContextReturnsMatchedSignalsForCurrentEvent() {
        when(httpClient.fetchSignals(5)).thenReturn(new ThreatIntelligenceSnapshot(
                "tenant-acme",
                true,
                true,
                List.of(signal("signal-auth", 4, 6, LocalDateTime.of(2026, 3, 17, 10, 0))),
                LocalDateTime.of(2026, 3, 17, 10, 5)));
        service.refresh();

        SecurityEvent event = SecurityEvent.builder()
                .eventId("evt-001")
                .timestamp(LocalDateTime.of(2026, 3, 17, 10, 10))
                .metadata(Map.of(
                        "requestPath", "/login",
                        "geoCountry", "KR",
                        "failedLoginAttempts", 4))
                .build();
        ThreatIntelligenceMatchContext context = service.buildThreatContext(event, new SecurityPromptTemplate.BehaviorAnalysis());

        assertThat(context.hasMatches()).isTrue();
        assertThat(context.matchedSignals()).extracting(match -> match.signal().signalKey()).containsExactly("signal-auth");
    }

    private ThreatIntelligenceSnapshot.ThreatSignalItem signal(String signalKey, int tenantCount, int observationCount, LocalDateTime lastObservedAt) {
        return new ThreatIntelligenceSnapshot.ThreatSignalItem(
                signalKey,
                "ACTIVE",
                "credential_abuse",
                "KR",
                List.of("Initial Access", "Credential Access"),
                List.of("authentication"),
                List.of("surface_authentication", "failed_login_burst"),
                tenantCount,
                observationCount,
                LocalDateTime.of(2026, 3, 17, 7, 0),
                lastObservedAt,
                LocalDateTime.of(2026, 3, 17, 22, 0),
                "Cross-tenant campaign detected.");
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
                        .promptLimit(2)
                        .cacheTtlMinutes(90)
                        .build())
                .build();
    }
}
