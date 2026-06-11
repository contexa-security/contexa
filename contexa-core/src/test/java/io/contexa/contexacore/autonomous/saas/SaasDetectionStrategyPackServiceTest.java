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
package io.contexa.contexacore.autonomous.saas;

import io.contexa.contexacore.autonomous.saas.client.SaasDetectionStrategyPackHttpClient;
import io.contexa.contexacore.autonomous.saas.dto.DetectionStrategyPackSnapshot;
import io.contexa.contexacore.autonomous.saas.learning.strategy.DetectionStrategyRuntimePack;
import io.contexa.contexacore.properties.SaasForwardingProperties;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.time.LocalDateTime;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class SaasDetectionStrategyPackServiceTest {

    private SaasDetectionStrategyPackHttpClient httpClient;
    private SaasDetectionStrategyPackService service;

    @BeforeEach
    void setUp() {
        httpClient = mock(SaasDetectionStrategyPackHttpClient.class);
        service = new SaasDetectionStrategyPackService(properties(), httpClient);
    }

    @Test
    void refreshCachesSnapshotAndReturnsOnlyPromotedRuntimeEligibleStrategies() {
        when(httpClient.fetchPack(5)).thenReturn(new DetectionStrategyPackSnapshot(
                "tenant-acme",
                true,
                true,
                true,
                "PROMOTED",
                2L,
                1L,
                1L,
                List.of(
                        strategy("strategy-promoted-a", "PATH_SEQUENCE_DIVERGENCE", true, "PROMOTED", 0.31d),
                        strategy("strategy-shadow", "SESSION_ENTROPY_COLLAPSE", true, "SHADOW_READY", 0.24d),
                        strategy("strategy-disabled", "POST_MFA_SURFACE_JUMP", false, "PROMOTED", 0.40d),
                        strategy("strategy-promoted-b", "INITIAL_REQUEST_PROFILE_DELTA", true, "PROMOTED", 0.28d)),
                LocalDateTime.of(2026, 4, 8, 10, 0)));

        service.refresh();

        DetectionStrategyRuntimePack runtimePack = service.getPromptRuntimePack();

        assertThat(service.currentSnapshot().tenantId()).isEqualTo("tenant-acme");
        assertThat(runtimePack.runtimeReady()).isTrue();
        assertThat(runtimePack.strategies())
                .extracting(DetectionStrategyRuntimePack.RuntimeStrategyItem::strategyKey)
                .containsExactly("strategy-promoted-a", "strategy-promoted-b");
    }

    @Test
    void returnsEmptyRuntimePackWhenSharingIsDisabled() {
        when(httpClient.fetchPack(5)).thenReturn(new DetectionStrategyPackSnapshot(
                "tenant-acme",
                true,
                false,
                true,
                "PROMOTED",
                1L,
                0L,
                0L,
                List.of(strategy("strategy-hidden", "PATH_SEQUENCE_DIVERGENCE", true, "PROMOTED", 0.31d)),
                LocalDateTime.of(2026, 4, 8, 10, 0)));

        service.refresh();

        assertThat(service.getPromptRuntimePack()).isEqualTo(DetectionStrategyRuntimePack.empty());
    }

    private DetectionStrategyPackSnapshot.StrategyItem strategy(
            String strategyKey,
            String family,
            boolean runtimeEligible,
            String promotionState,
            double localLiftRate) {
        return new DetectionStrategyPackSnapshot.StrategyItem(
                strategyKey,
                "2026.04.08-v1",
                family,
                List.of("ACCOUNT_TAKEOVER"),
                List.of("failed_login_burst"),
                List.of("new_device", "admin_surface_jump"),
                List.of("NEW_DEVICE_POST_MFA_SENSITIVE"),
                12L,
                "HIGH",
                localLiftRate,
                0.04d,
                -0.11d,
                48L,
                0.81d,
                0.73d,
                runtimeEligible,
                promotionState,
                List.of("Runtime release requires promoted evidence."),
                List.of("Observed account takeover lift after strategy adoption."),
                List.of("Release gate cleared for runtime consumption."));
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
                                SaasForwardingProperties.DETECTION_STRATEGY_READ_SCOPE)))
                        .expirySkewSeconds(30)
                        .build())
                .detectionStrategy(SaasForwardingProperties.DetectionStrategy.builder()
                        .enabled(true)
                        .endpointPath("/api/saas/runtime/ai-tuning/detection-strategy-pack")
                        .pullIntervalMs(3_600_000L)
                        .initialDelayMs(0L)
                        .strategyLimit(5)
                        .promptLimit(2)
                        .cacheTtlMinutes(90)
                        .build())
                .build();
    }
}