package io.contexa.contexacore.autonomous.saas;

import io.contexa.contexacore.autonomous.domain.SecurityEvent;
import io.contexa.contexacore.autonomous.saas.client.SaasThreatKnowledgePackHttpClient;
import io.contexa.contexacore.autonomous.saas.dto.ThreatKnowledgePackMatchContext;
import io.contexa.contexacore.autonomous.saas.dto.ThreatKnowledgePackSnapshot;
import io.contexa.contexacore.autonomous.tiered.template.SecurityPromptTemplate;
import io.contexa.contexacore.properties.SaasForwardingProperties;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.time.LocalDateTime;
import java.util.List;
import java.util.Map;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class SaasThreatKnowledgePackServiceTest {

    private SaasThreatKnowledgePackHttpClient httpClient;
    private SaasThreatKnowledgePackService service;

    @BeforeEach
    void setUp() {
        httpClient = mock(SaasThreatKnowledgePackHttpClient.class);
        service = new SaasThreatKnowledgePackService(properties(), httpClient);
    }

    @Test
    void refreshCachesKnowledgePackAndReturnsCurrentSnapshot() {
        when(httpClient.fetchKnowledgePack(5)).thenReturn(new ThreatKnowledgePackSnapshot(
                "tenant-acme",
                true,
                true,
                true,
                "PROMOTED_READY",
                1,
                0,
                0,
                List.of(knowledgeCase("knowledge-001")),
                LocalDateTime.of(2026, 3, 17, 10, 5)));

        service.refresh();

        assertThat(service.currentSnapshot().tenantId()).isEqualTo("tenant-acme");
        assertThat(service.currentSnapshot().runtimeReady()).isTrue();
        assertThat(service.currentSnapshot().cases()).extracting(ThreatKnowledgePackSnapshot.KnowledgeCaseItem::knowledgeKey)
                .containsExactly("knowledge-001");
    }

    @Test
    void buildThreatKnowledgeContextReturnsComparableCasesForCurrentEvent() {
        when(httpClient.fetchKnowledgePack(5)).thenReturn(new ThreatKnowledgePackSnapshot(
                "tenant-acme",
                true,
                true,
                true,
                "PROMOTED_READY",
                1,
                0,
                0,
                List.of(knowledgeCase("knowledge-001")),
                LocalDateTime.of(2026, 3, 17, 10, 5)));
        service.refresh();

        SecurityEvent event = SecurityEvent.builder()
                .eventId("evt-knowledge-001")
                .timestamp(LocalDateTime.of(2026, 3, 17, 10, 10))
                .metadata(Map.of(
                        "requestPath", "/login",
                        "geoCountry", "KR",
                        "failedLoginAttempts", 4))
                .build();

        ThreatKnowledgePackMatchContext context = service.buildThreatKnowledgeContext(
                event,
                new SecurityPromptTemplate.BehaviorAnalysis());

        assertThat(context.hasMatches()).isTrue();
        assertThat(context.matchedCases()).extracting(match -> match.knowledgeCase().knowledgeKey())
                .containsExactly("knowledge-001");
    }

    @Test
    void buildThreatKnowledgeContextFailsClosedWhenRuntimePolicyWithdrawsKnowledge() {
        SaasThreatKnowledgeRuntimePolicyService runtimePolicyService = mock(SaasThreatKnowledgeRuntimePolicyService.class);
        SaasThreatKnowledgePackService guardedService = new SaasThreatKnowledgePackService(properties(), httpClient, runtimePolicyService);
        when(httpClient.fetchKnowledgePack(5)).thenReturn(new ThreatKnowledgePackSnapshot(
                "tenant-acme",
                true,
                true,
                true,
                "PROMOTED_READY",
                1,
                0,
                0,
                List.of(knowledgeCase("knowledge-001")),
                LocalDateTime.of(2026, 3, 17, 10, 5)));
        when(runtimePolicyService.isEnabled()).thenReturn(true);
        when(runtimePolicyService.isRuntimeAllowed()).thenReturn(true);
        when(runtimePolicyService.approvedSignalKeys()).thenReturn(Set.of("signal-knowledge-001"));
        when(runtimePolicyService.withdrawnSignalKeys()).thenReturn(Set.of("signal-knowledge-001"));

        guardedService.refresh();

        SecurityEvent event = SecurityEvent.builder()
                .eventId("evt-knowledge-001")
                .timestamp(LocalDateTime.of(2026, 3, 17, 10, 10))
                .metadata(Map.of(
                        "requestPath", "/login",
                        "geoCountry", "KR",
                        "failedLoginAttempts", 4))
                .build();

        ThreatKnowledgePackMatchContext context = guardedService.buildThreatKnowledgeContext(
                event,
                new SecurityPromptTemplate.BehaviorAnalysis());

        assertThat(context.hasMatches()).isFalse();
    }


    @Test
    void buildThreatKnowledgeContextFailsClosedWhenRuntimePolicyDisablesRuntimeUsage() {
        SaasThreatKnowledgeRuntimePolicyService runtimePolicyService = mock(SaasThreatKnowledgeRuntimePolicyService.class);
        SaasThreatKnowledgePackService guardedService = new SaasThreatKnowledgePackService(properties(), httpClient, runtimePolicyService);
        when(httpClient.fetchKnowledgePack(5)).thenReturn(new ThreatKnowledgePackSnapshot(
                "tenant-acme",
                true,
                true,
                true,
                "PROMOTED_READY",
                1,
                0,
                0,
                List.of(knowledgeCase("knowledge-001")),
                LocalDateTime.of(2026, 3, 17, 10, 5)));
        when(runtimePolicyService.isEnabled()).thenReturn(true);
        when(runtimePolicyService.isRuntimeAllowed()).thenReturn(false);

        guardedService.refresh();

        SecurityEvent event = SecurityEvent.builder()
                .eventId("evt-knowledge-001")
                .timestamp(LocalDateTime.of(2026, 3, 17, 10, 10))
                .metadata(Map.of(
                        "requestPath", "/login",
                        "geoCountry", "KR",
                        "failedLoginAttempts", 4))
                .build();

        ThreatKnowledgePackMatchContext context = guardedService.buildThreatKnowledgeContext(
                event,
                new SecurityPromptTemplate.BehaviorAnalysis());

        assertThat(context.hasMatches()).isFalse();
    }
    private ThreatKnowledgePackSnapshot.KnowledgeCaseItem knowledgeCase(String knowledgeKey) {
        return new ThreatKnowledgePackSnapshot.KnowledgeCaseItem(
                "signal-" + knowledgeKey,
                knowledgeKey,
                "credential_abuse",
                "KR",
                List.of("authentication"),
                List.of("surface_authentication", "failed_login_burst"),
                List.of("Multiple tenants observed the same attack pattern."),
                List.of("Attackers reused a new device after burst failures."),
                List.of("Account takeover confirmed after investigation."),
                List.of("Ignore ordinary password reset bursts."),
                "REINFORCED",
                List.of("Confirmed attack outcomes are reusable memories for this case."),
                "Credential abuse campaign across finance tenants",
                "Prior cases converged on account takeover after burst failures.",
                LocalDateTime.of(2026, 3, 17, 10, 0),
                4,
                6,
                "MATURE",
                List.of("Tenant-local memory contains reinforced cases and hard negatives."),
                "POSITIVE_SHIFT",
                List.of("Protective review increased after knowledge promotion."),
                "REASONING_READY",
                List.of("Objective-bound reasoning memory is reusable at runtime."),
                "PROMOTED",
                "Promoted for runtime AI use because the case is validated and backed by reusable tenant evidence.",
                List.of("Promotion gate confirmed validated outcome evidence."));
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
                                SaasForwardingProperties.THREAT_KNOWLEDGE_READ_SCOPE)))
                        .expirySkewSeconds(30)
                        .build())
                .threatKnowledge(SaasForwardingProperties.ThreatKnowledge.builder()
                        .enabled(true)
                        .endpointPath("/api/saas/runtime/ai-tuning/threat-knowledge-pack")
                        .runtimePolicyEndpointPath("/api/saas/runtime/ai-tuning/threat-runtime-policy")
                        .pullIntervalMs(3_600_000L)
                        .initialDelayMs(0L)
                        .caseLimit(5)
                        .promptLimit(2)
                        .cacheTtlMinutes(90)
                        .build())
                .build();
    }
}
