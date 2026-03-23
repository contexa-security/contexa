package io.contexa.contexacore.autonomous.saas;

import io.contexa.contexacore.autonomous.saas.client.SaasThreatKnowledgeRuntimePolicyHttpClient;
import io.contexa.contexacore.autonomous.saas.dto.ThreatKnowledgeRuntimePolicySnapshot;
import io.contexa.contexacore.properties.SaasForwardingProperties;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.time.LocalDateTime;
import java.util.List;

import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class SaasThreatKnowledgeRuntimePolicyServiceTest {

    private SaasThreatKnowledgeRuntimePolicyHttpClient httpClient;
    private SaasThreatKnowledgeRuntimePolicyService service;

    @BeforeEach
    void setUp() {
        httpClient = mock(SaasThreatKnowledgeRuntimePolicyHttpClient.class);
        service = new SaasThreatKnowledgeRuntimePolicyService(properties(), httpClient);
    }

    @Test
    void refreshCachesRuntimePolicyAndIndexesApprovedArtifacts() {
        when(httpClient.fetchRuntimePolicy(5)).thenReturn(new ThreatKnowledgeRuntimePolicySnapshot(
                "tenant-acme",
                true,
                true,
                true,
                false,
                "READY",
                1,
                1,
                0,
                List.of(
                        new ThreatKnowledgeRuntimePolicySnapshot.ArtifactPolicyItem(
                                "signal-allow",
                                "knowledge-allow",
                                "tkp-2026.03.18",
                                "PROMOTED",
                                "READY_FOR_CANARY",
                                "NOT_ELIGIBLE",
                                true,
                                false,
                                "ALLOW_RUNTIME",
                                List.of("Runtime approved."),
                                "Allow this artifact."),
                        new ThreatKnowledgeRuntimePolicySnapshot.ArtifactPolicyItem(
                                "signal-withdraw",
                                "knowledge-withdraw",
                                "tkp-2026.03.17",
                                "PROMOTED",
                                "FAIL_REVIEW",
                                "ROLLBACK_REQUIRED",
                                true,
                                true,
                                "WITHDRAW",
                                List.of("Rollback required."),
                                "Withdraw this artifact.")),
                LocalDateTime.of(2026, 3, 18, 11, 0)));

        service.refresh();

        assertThat(service.currentSnapshot().tenantId()).isEqualTo("tenant-acme");
        assertThat(service.isRuntimeAllowed()).isTrue();
        assertThat(service.approvedSignalKeys()).containsExactly("signal-allow");
        assertThat(service.withdrawnSignalKeys()).containsExactly("signal-withdraw");
    }

    @Test
    void runtimeIsDeniedWhenKillSwitchIsActive() {
        when(httpClient.fetchRuntimePolicy(5)).thenReturn(new ThreatKnowledgeRuntimePolicySnapshot(
                "tenant-acme",
                true,
                true,
                false,
                true,
                "KILL_SWITCH_ACTIVE",
                0,
                2,
                0,
                List.of(),
                LocalDateTime.of(2026, 3, 18, 11, 5)));

        service.refresh();

        assertThat(service.isRuntimeAllowed()).isFalse();
        assertThat(service.approvedSignalKeys()).isEmpty();
        assertThat(service.withdrawnSignalKeys()).isEmpty();
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