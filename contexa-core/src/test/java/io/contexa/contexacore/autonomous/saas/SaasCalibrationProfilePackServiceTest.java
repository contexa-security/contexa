package io.contexa.contexacore.autonomous.saas;

import io.contexa.contexacore.autonomous.saas.client.SaasCalibrationProfilePackHttpClient;
import io.contexa.contexacore.autonomous.saas.dto.CalibrationProfilePackSnapshot;
import io.contexa.contexacore.autonomous.saas.learning.calibration.CalibrationProfileRuntimePack;
import io.contexa.contexacore.properties.SaasForwardingProperties;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.time.LocalDateTime;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class SaasCalibrationProfilePackServiceTest {

    private SaasCalibrationProfilePackHttpClient httpClient;
    private SaasCalibrationProfilePackService service;

    @BeforeEach
    void setUp() {
        httpClient = mock(SaasCalibrationProfilePackHttpClient.class);
        service = new SaasCalibrationProfilePackService(properties(), httpClient);
    }

    @Test
    void refreshCachesSnapshotAndReturnsOnlyPromotedRuntimeEligibleProfiles() {
        when(httpClient.fetchPack(4)).thenReturn(new CalibrationProfilePackSnapshot(
                "tenant-acme",
                true,
                true,
                true,
                "PROMOTED",
                2L,
                1L,
                1L,
                List.of(
                        profile("profile-promoted-b", "SESSION_PATH_SIMILARITY_BREAK", 28L, 6L, true, "PROMOTED"),
                        profile("profile-review-only", "SESSION_PATH_SIMILARITY_BREAK", 60L, 8L, true, "REVIEW_ONLY"),
                        profile("profile-disabled", "LOW_DIVERSITY_EXPORT_APPROACH", 80L, 12L, false, "PROMOTED"),
                        profile("profile-promoted-a", "NEW_DEVICE_POST_MFA_SENSITIVE", 42L, 12L, true, "PROMOTED")),
                LocalDateTime.of(2026, 4, 8, 12, 0)));

        service.refresh();

        CalibrationProfileRuntimePack runtimePack = service.getRuntimePack();

        assertThat(service.currentSnapshot().tenantId()).isEqualTo("tenant-acme");
        assertThat(runtimePack.runtimeReady()).isTrue();
        assertThat(runtimePack.profiles())
                .extracting(CalibrationProfileRuntimePack.RuntimeCalibrationItem::profileKey)
                .containsExactly("profile-promoted-a", "profile-promoted-b");
    }

    @Test
    void returnsEmptyRuntimePackWhenSharingIsDisabled() {
        when(httpClient.fetchPack(4)).thenReturn(new CalibrationProfilePackSnapshot(
                "tenant-acme",
                true,
                false,
                true,
                "PROMOTED",
                1L,
                0L,
                0L,
                List.of(profile("profile-hidden", "NEW_DEVICE_POST_MFA_SENSITIVE", 24L, 5L, true, "PROMOTED")),
                LocalDateTime.of(2026, 4, 8, 12, 0)));

        service.refresh();

        assertThat(service.getRuntimePack()).isEqualTo(CalibrationProfileRuntimePack.empty());
    }

    private CalibrationProfilePackSnapshot.ProfileItem profile(
            String profileKey,
            String scenarioClass,
            long sampleSize,
            long reviewedOutcomeCount,
            boolean runtimeEligible,
            String promotionState) {
        return new CalibrationProfilePackSnapshot.ProfileItem(
                profileKey,
                "2026.04.08-v1",
                scenarioClass,
                sampleSize,
                reviewedOutcomeCount,
                0.12d,
                0.08d,
                0.21d,
                0.07d,
                -0.09d,
                "DECREASE_CHALLENGE",
                runtimeEligible,
                promotionState,
                List.of("Bias risk reviewed"),
                List.of("Observed reviewed outcomes for calibration profile promotion."),
                List.of("Runtime release gate cleared for calibration consumption."));
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
                                SaasForwardingProperties.CALIBRATION_PROFILE_READ_SCOPE)))
                        .expirySkewSeconds(30)
                        .build())
                .calibrationProfile(SaasForwardingProperties.CalibrationProfile.builder()
                        .enabled(true)
                        .endpointPath("/api/saas/runtime/ai-tuning/calibration-profile-pack")
                        .pullIntervalMs(3_600_000L)
                        .initialDelayMs(0L)
                        .profileLimit(4)
                        .cacheTtlMinutes(90)
                        .build())
                .build();
    }
}
