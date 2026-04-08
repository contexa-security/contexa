package io.contexa.contexacore.autonomous.saas;

import io.contexa.contexacore.autonomous.saas.learning.LearningArtifactGuardrail;
import io.contexa.contexacore.autonomous.saas.learning.LearningArtifactMetadata;
import io.contexa.contexacore.autonomous.saas.learning.LearningArtifactMetrics;
import io.contexa.contexacore.autonomous.saas.learning.LearningArtifactReleaseState;
import io.contexa.contexacore.autonomous.saas.learning.release.LearningArtifactRuntimeConflictService;
import io.contexa.contexacore.properties.SaasForwardingProperties;
import lombok.extern.slf4j.Slf4j;
import org.springframework.util.StringUtils;

import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;

/**
 * Shared cache and metadata helpers for SaaS runtime learning artifacts.
 */
@Slf4j
public abstract class AbstractSaasRuntimeArtifactPackService<S> {

    protected final SaasForwardingProperties properties;
    private final S emptySnapshot;
    private final LearningArtifactRuntimeConflictService runtimeConflictService;
    private volatile CachedSnapshot<S> cachedSnapshot;

    protected AbstractSaasRuntimeArtifactPackService(SaasForwardingProperties properties, S emptySnapshot) {
        this(properties, emptySnapshot, null);
    }

    protected AbstractSaasRuntimeArtifactPackService(
            SaasForwardingProperties properties,
            S emptySnapshot,
            LearningArtifactRuntimeConflictService runtimeConflictService) {
        this.properties = properties;
        this.emptySnapshot = emptySnapshot;
        this.runtimeConflictService = runtimeConflictService;
        this.cachedSnapshot = new CachedSnapshot<>(emptySnapshot, null);
    }

    public void refresh() {
        if (!isModuleEnabled()) {
            return;
        }
        try {
            S snapshot = fetchSnapshot(resolveFetchLimit());
            cachedSnapshot = new CachedSnapshot<>(snapshot != null ? snapshot : emptySnapshot, LocalDateTime.now());
        } catch (Exception ex) {
            log.error("Failed to refresh {}", artifactDisplayName(), ex);
        }
    }

    public void invalidate() {
        cachedSnapshot = new CachedSnapshot<>(emptySnapshot, null);
    }

    public void invalidateAndRefresh() {
        invalidate();
        refresh();
    }

    public S currentSnapshot() {
        return cachedSnapshot.snapshot();
    }

    protected final S usableSnapshot() {
        if (!isModuleEnabled()) {
            return null;
        }
        CachedSnapshot<S> snapshot = cachedSnapshot;
        if (!snapshot.isUsable(resolveCacheTtlMinutes())) {
            return null;
        }
        S data = snapshot.snapshot();
        if (data == null || !isFeatureEnabled(data) || !isSharingEnabled(data) || !isRuntimeReady(data)) {
            return null;
        }
        return data;
    }

    protected final LearningArtifactMetadata toMetadata(
            String promotionState,
            long sampleSize,
            double outcomeCoverageRate,
            double hardNegativeCoverage,
            double localLiftRate,
            double fpDelta,
            double fnDelta,
            List<String> rawGuardrails) {
        return new LearningArtifactMetadata(
                resolveReleaseState(promotionState),
                new LearningArtifactMetrics(
                        sampleSize,
                        outcomeCoverageRate,
                        hardNegativeCoverage,
                        localLiftRate,
                        fpDelta,
                        fnDelta),
                toGuardrails(rawGuardrails));
    }

    protected final List<LearningArtifactGuardrail> toGuardrails(List<String> rawGuardrails) {
        if (rawGuardrails == null || rawGuardrails.isEmpty()) {
            return List.of();
        }
        ArrayList<LearningArtifactGuardrail> guardrails = new ArrayList<>();
        int index = 0;
        for (String rawGuardrail : rawGuardrails) {
            if (!StringUtils.hasText(rawGuardrail)) {
                continue;
            }
            index++;
            guardrails.add(new LearningArtifactGuardrail(
                    "runtime-guardrail-" + index,
                    rawGuardrail.trim(),
                    false));
        }
        return List.copyOf(guardrails);
    }

    protected final LearningArtifactReleaseState resolveReleaseState(String promotionState) {
        if (!StringUtils.hasText(promotionState)) {
            return LearningArtifactReleaseState.COLLECTING;
        }
        try {
            return LearningArtifactReleaseState.valueOf(promotionState.trim().toUpperCase(Locale.ROOT));
        } catch (IllegalArgumentException ex) {
            return LearningArtifactReleaseState.COLLECTING;
        }
    }

    protected final boolean isRuntimeSuppressed(String tenantId, String artifactType, String artifactKey) {
        if (runtimeConflictService == null
                || !StringUtils.hasText(tenantId)
                || !StringUtils.hasText(artifactType)
                || !StringUtils.hasText(artifactKey)) {
            return false;
        }
        return runtimeConflictService.isRuntimeSuppressed(tenantId, artifactType, artifactKey);
    }

    protected abstract boolean isModuleEnabled();

    protected abstract int resolveFetchLimit();

    protected abstract int resolveCacheTtlMinutes();

    protected abstract S fetchSnapshot(int limit);

    protected abstract boolean isFeatureEnabled(S snapshot);

    protected abstract boolean isSharingEnabled(S snapshot);

    protected abstract boolean isRuntimeReady(S snapshot);

    protected abstract String artifactDisplayName();

    private record CachedSnapshot<S>(S snapshot, LocalDateTime fetchedAt) {

        private boolean isUsable(int cacheTtlMinutes) {
            if (snapshot == null || fetchedAt == null) {
                return false;
            }
            return !fetchedAt.isBefore(LocalDateTime.now().minusMinutes(cacheTtlMinutes));
        }
    }
}