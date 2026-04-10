package io.contexa.contexacore.autonomous.saas;

import io.contexa.contexacore.autonomous.saas.client.SaasCalibrationProfilePackHttpClient;
import io.contexa.contexacore.autonomous.saas.dto.CalibrationProfilePackSnapshot;
import io.contexa.contexacore.autonomous.saas.learning.LearningArtifactReleaseState;
import io.contexa.contexacore.autonomous.saas.learning.LearningArtifactTypeNames;
import io.contexa.contexacore.autonomous.saas.learning.calibration.CalibrationProfileRuntimePack;
import io.contexa.contexacore.autonomous.saas.learning.release.LearningArtifactRuntimeConflictService;
import io.contexa.contexacore.properties.SaasForwardingProperties;

import java.util.Comparator;
import java.util.List;

public class SaasCalibrationProfilePackService extends AbstractSaasRuntimeArtifactPackService<CalibrationProfilePackSnapshot> {

    private final SaasCalibrationProfilePackHttpClient httpClient;

    public SaasCalibrationProfilePackService(
            SaasForwardingProperties properties,
            SaasCalibrationProfilePackHttpClient httpClient) {
        this(properties, httpClient, null);
    }

    public SaasCalibrationProfilePackService(
            SaasForwardingProperties properties,
            SaasCalibrationProfilePackHttpClient httpClient,
            LearningArtifactRuntimeConflictService runtimeConflictService) {
        super(properties, CalibrationProfilePackSnapshot.empty(), runtimeConflictService);
        this.httpClient = httpClient;
    }

    public boolean isEnabled() {
        return properties.isEnabled()
                && properties.getCalibrationProfile() != null
                && properties.getCalibrationProfile().isEnabled();
    }

    public CalibrationProfileRuntimePack getRuntimePack() {
        CalibrationProfilePackSnapshot snapshot = usableSnapshot();
        if (snapshot == null) {
            return CalibrationProfileRuntimePack.empty();
        }
        List<CalibrationProfileRuntimePack.RuntimeCalibrationItem> profiles = snapshot.profiles().stream()
                .filter(item -> isRuntimeEligible(snapshot.tenantId(), item))
                .sorted(Comparator.comparingLong(CalibrationProfilePackSnapshot.ProfileItem::sampleSize).reversed()
                        .thenComparing(Comparator.comparingLong(CalibrationProfilePackSnapshot.ProfileItem::operatorReviewedOutcomeCount).reversed()))
                .map(this::toRuntimeItem)
                .toList();
        if (profiles.isEmpty()) {
            return CalibrationProfileRuntimePack.empty();
        }
        return new CalibrationProfileRuntimePack(snapshot.tenantId(), true, profiles, snapshot.generatedAt());
    }

    @Override
    protected boolean isModuleEnabled() {
        return isEnabled();
    }

    @Override
    protected int resolveFetchLimit() {
        return properties.getCalibrationProfile().getProfileLimit();
    }

    @Override
    protected int resolveCacheTtlMinutes() {
        return properties.getCalibrationProfile().getCacheTtlMinutes();
    }

    @Override
    protected CalibrationProfilePackSnapshot fetchSnapshot(int limit) {
        return httpClient.fetchPack(limit);
    }

    @Override
    protected boolean isFeatureEnabled(CalibrationProfilePackSnapshot snapshot) {
        return snapshot.featureEnabled();
    }

    @Override
    protected boolean isSharingEnabled(CalibrationProfilePackSnapshot snapshot) {
        return snapshot.sharingEnabled();
    }

    @Override
    protected boolean isRuntimeReady(CalibrationProfilePackSnapshot snapshot) {
        return snapshot.runtimeReady();
    }

    @Override
    protected String artifactDisplayName() {
        return "SaaS calibration profile pack";
    }

    private boolean isRuntimeEligible(String tenantId, CalibrationProfilePackSnapshot.ProfileItem item) {
        return item != null
                && item.runtimeEligible()
                && resolveReleaseState(item.promotionState()) == LearningArtifactReleaseState.PROMOTED
                && !isRuntimeSuppressed(tenantId, LearningArtifactTypeNames.CALIBRATION_PROFILE, item.profileKey());
    }

    private CalibrationProfileRuntimePack.RuntimeCalibrationItem toRuntimeItem(
            CalibrationProfilePackSnapshot.ProfileItem item) {
        return new CalibrationProfileRuntimePack.RuntimeCalibrationItem(
                item.profileKey(),
                item.profileVersion(),
                item.scenarioClass(),
                toMetadata(
                        item.promotionState(),
                        item.sampleSize(),
                        0.0d,
                        0.0d,
                        0.0d,
                        item.falsePositiveRate(),
                        item.falseNegativeRate(),
                        item.guardrails()),
                item.sampleSize(),
                item.operatorReviewedOutcomeCount(),
                item.falsePositiveRate(),
                item.falseNegativeRate(),
                item.challengeOverfireRate(),
                item.allowUnderfireRate(),
                item.recommendedConfidenceAdjustment(),
                item.recommendedActionBias(),
                item.evidenceFacts(),
                item.policyFacts());
    }
}