package io.contexa.contexacore.autonomous.tiered.service.calibration;

import io.contexa.contexacommon.enums.ZeroTrustAction;
import io.contexa.contexacore.autonomous.domain.SecurityEvent;
import io.contexa.contexacore.autonomous.saas.SaasCalibrationProfilePackService;
import io.contexa.contexacore.autonomous.saas.learning.LearningArtifactMetadata;
import io.contexa.contexacore.autonomous.saas.learning.LearningArtifactMetrics;
import io.contexa.contexacore.autonomous.saas.learning.LearningArtifactReleaseState;
import io.contexa.contexacore.autonomous.saas.learning.calibration.CalibrationProfileRuntimePack;
import io.contexa.contexacore.autonomous.saas.learning.calibration.DefaultScenarioClassResolver;
import io.contexa.contexacore.autonomous.saas.threat.ThreatSignalNormalizationService;
import io.contexa.contexacore.autonomous.tiered.SecurityDecision;
import io.contexa.contexacore.autonomous.tiered.prompt.SecurityDecisionStandardPromptTemplate;
import org.junit.jupiter.api.Test;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class SecurityDecisionCalibrationServiceTest {

    private final SaasCalibrationProfilePackService calibrationProfilePackService = mock(SaasCalibrationProfilePackService.class);
    private final SecurityDecisionCalibrationService service = new SecurityDecisionCalibrationService(
            calibrationProfilePackService,
            new CalibrationRuntimeObservationFactory(new ThreatSignalNormalizationService()),
            new DefaultScenarioClassResolver(),
            new CalibrationProfileSelector(),
            new CalibrationDecisionApplier());

    @Test
    void appliesPostDecisionCalibrationForPromotedRuntimeProfile() {
        when(calibrationProfilePackService.isEnabled()).thenReturn(true);
        when(calibrationProfilePackService.getRuntimePack()).thenReturn(runtimePack(profile(
                "profile/new-device-post-mfa-sensitive",
                "NEW_DEVICE_POST_MFA_SENSITIVE",
                -0.10d,
                "DECREASE_CHALLENGE",
                48L,
                18L)));

        SecurityDecision decision = SecurityDecision.builder()
                .action(ZeroTrustAction.CHALLENGE)
                .autonomousAction(ZeroTrustAction.CHALLENGE)
                .confidence(0.82d)
                .llmAuditConfidence(0.82d)
                .reasoning("Layer2 expert decision")
                .build();

        SecurityDecision calibrated = service.apply(event(), decision, behaviorAnalysis(true, "/profile", 620L));

        assertThat(calibrated).isSameAs(decision);
        assertThat(calibrated.getCalibrationApplied()).isTrue();
        assertThat(calibrated.getCalibrationProfileKey()).isEqualTo("profile/new-device-post-mfa-sensitive");
        assertThat(calibrated.getCalibrationScenarioClass()).isEqualTo("NEW_DEVICE_POST_MFA_SENSITIVE");
        assertThat(calibrated.getConfidence()).isEqualTo(0.72d);
        assertThat(calibrated.resolveAutonomousAction()).isEqualTo(ZeroTrustAction.ALLOW);
        assertThat(calibrated.getCalibrationReasons()).isNotEmpty();
        assertThat(calibrated.getCalibrationSummary()).contains("post-decision adjustments");
    }

    @Test
    void preservesBlockAndLocalAutonomyConstraint() {
        when(calibrationProfilePackService.isEnabled()).thenReturn(true);
        when(calibrationProfilePackService.getRuntimePack()).thenReturn(runtimePack(profile(
                "profile/new-device-post-mfa-sensitive",
                "NEW_DEVICE_POST_MFA_SENSITIVE",
                -0.20d,
                "DECREASE_CHALLENGE",
                55L,
                20L)));

        SecurityDecision blockedDecision = SecurityDecision.builder()
                .action(ZeroTrustAction.BLOCK)
                .autonomousAction(ZeroTrustAction.BLOCK)
                .confidence(0.91d)
                .llmAuditConfidence(0.91d)
                .build();

        SecurityDecision constrainedDecision = SecurityDecision.builder()
                .action(ZeroTrustAction.CHALLENGE)
                .autonomousAction(ZeroTrustAction.CHALLENGE)
                .confidence(0.88d)
                .llmAuditConfidence(0.88d)
                .autonomyConstraintApplied(true)
                .autonomyConstraintSummary("Local policy locked challenge")
                .build();

        SecurityDecision blockedResult = service.apply(event(), blockedDecision, behaviorAnalysis(true, "/profile", 620L));
        SecurityDecision constrainedResult = service.apply(event(), constrainedDecision, behaviorAnalysis(true, "/profile", 620L));

        assertThat(blockedResult.resolveAutonomousAction()).isEqualTo(ZeroTrustAction.BLOCK);
        assertThat(blockedResult.getCalibrationApplied()).isTrue();
        assertThat(blockedResult.getConfidence()).isEqualTo(0.71d);
        assertThat(blockedResult.getCalibrationSummary()).contains("post-decision adjustments");

        assertThat(constrainedResult.resolveAutonomousAction()).isEqualTo(ZeroTrustAction.CHALLENGE);
        assertThat(constrainedResult.getConfidence()).isEqualTo(0.88d);
        assertThat(constrainedResult.getCalibrationApplied()).isFalse();
        assertThat(constrainedResult.getCalibrationSummary()).contains("local autonomy constraints preserved");
    }

    private CalibrationProfileRuntimePack runtimePack(CalibrationProfileRuntimePack.RuntimeCalibrationItem profile) {
        return new CalibrationProfileRuntimePack("tenant-a", true, List.of(profile), null);
    }

    private CalibrationProfileRuntimePack.RuntimeCalibrationItem profile(
            String profileKey,
            String scenarioClass,
            double confidenceAdjustment,
            String actionBias,
            long sampleSize,
            long reviewedOutcomeCount) {
        return new CalibrationProfileRuntimePack.RuntimeCalibrationItem(
                profileKey,
                "2026.04.08-v1",
                scenarioClass,
                new LearningArtifactMetadata(
                        LearningArtifactReleaseState.PROMOTED,
                        new LearningArtifactMetrics(sampleSize, 0.80d, 0.24d, 0.10d, -0.05d, -0.08d),
                        List.of()),
                sampleSize,
                reviewedOutcomeCount,
                0.12d,
                0.07d,
                0.18d,
                0.06d,
                confidenceAdjustment,
                actionBias,
                List.of("Reviewed operator outcomes retained this calibration profile."),
                List.of("Release gate cleared for runtime use."));
    }

    private SecurityEvent event() {
        return SecurityEvent.builder()
                .eventId("evt-1")
                .userId("user-1")
                .sessionId("session-1")
                .description("Security event")
                .metadata(new HashMap<>(Map.of(
                        "requestPath", "/admin/report/export",
                        "mfaVerified", true,
                        "isSensitiveResource", true,
                        "promptRuntimeTelemetryLinked", true,
                        "deniedDocumentCount", 2,
                        "failedLoginAttempts", 4,
                        "reasonCategory", "post_mfa_sensitive_access")))
                .build();
    }

    private SecurityDecisionStandardPromptTemplate.BehaviorAnalysis behaviorAnalysis(
            boolean isNewDevice,
            String previousPath,
            long lastRequestIntervalMs) {
        SecurityDecisionStandardPromptTemplate.BehaviorAnalysis behaviorAnalysis =
                new SecurityDecisionStandardPromptTemplate.BehaviorAnalysis();
        behaviorAnalysis.setIsNewDevice(isNewDevice);
        behaviorAnalysis.setPreviousPath(previousPath);
        behaviorAnalysis.setLastRequestIntervalMs(lastRequestIntervalMs);
        return behaviorAnalysis;
    }
}
