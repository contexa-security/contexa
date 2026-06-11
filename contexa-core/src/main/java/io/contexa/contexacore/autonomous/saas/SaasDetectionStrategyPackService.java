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
import io.contexa.contexacore.autonomous.saas.learning.LearningArtifactReleaseState;
import io.contexa.contexacore.autonomous.saas.learning.LearningArtifactTypeNames;
import io.contexa.contexacore.autonomous.saas.learning.release.LearningArtifactRuntimeConflictService;
import io.contexa.contexacore.autonomous.saas.learning.strategy.DetectionStrategyRuntimePack;
import io.contexa.contexacore.properties.SaasForwardingProperties;

import java.util.List;

public class SaasDetectionStrategyPackService extends AbstractSaasRuntimeArtifactPackService<DetectionStrategyPackSnapshot> {

    private final SaasDetectionStrategyPackHttpClient httpClient;

    public SaasDetectionStrategyPackService(
            SaasForwardingProperties properties,
            SaasDetectionStrategyPackHttpClient httpClient) {
        this(properties, httpClient, null);
    }

    public SaasDetectionStrategyPackService(
            SaasForwardingProperties properties,
            SaasDetectionStrategyPackHttpClient httpClient,
            LearningArtifactRuntimeConflictService runtimeConflictService) {
        super(properties, DetectionStrategyPackSnapshot.empty(), runtimeConflictService);
        this.httpClient = httpClient;
    }

    public boolean isEnabled() {
        return properties.isEnabled()
                && properties.getDetectionStrategy() != null
                && properties.getDetectionStrategy().isEnabled();
    }

    public DetectionStrategyRuntimePack getPromptRuntimePack() {
        DetectionStrategyPackSnapshot snapshot = usableSnapshot();
        if (snapshot == null) {
            return DetectionStrategyRuntimePack.empty();
        }
        List<DetectionStrategyRuntimePack.RuntimeStrategyItem> strategies = snapshot.strategies().stream()
                .filter(item -> isPromptRuntimeEligible(snapshot.tenantId(), item))
                .limit(properties.getDetectionStrategy().getPromptLimit())
                .map(this::toRuntimeStrategyItem)
                .toList();
        if (strategies.isEmpty()) {
            return DetectionStrategyRuntimePack.empty();
        }
        return new DetectionStrategyRuntimePack(snapshot.tenantId(), true, strategies, snapshot.generatedAt());
    }

    @Override
    protected boolean isModuleEnabled() {
        return isEnabled();
    }

    @Override
    protected int resolveFetchLimit() {
        return properties.getDetectionStrategy().getStrategyLimit();
    }

    @Override
    protected int resolveCacheTtlMinutes() {
        return properties.getDetectionStrategy().getCacheTtlMinutes();
    }

    @Override
    protected DetectionStrategyPackSnapshot fetchSnapshot(int limit) {
        return httpClient.fetchPack(limit);
    }

    @Override
    protected boolean isFeatureEnabled(DetectionStrategyPackSnapshot snapshot) {
        return snapshot.featureEnabled();
    }

    @Override
    protected boolean isSharingEnabled(DetectionStrategyPackSnapshot snapshot) {
        return snapshot.sharingEnabled();
    }

    @Override
    protected boolean isRuntimeReady(DetectionStrategyPackSnapshot snapshot) {
        return snapshot.runtimeReady();
    }

    @Override
    protected String artifactDisplayName() {
        return "SaaS detection strategy pack";
    }

    private boolean isPromptRuntimeEligible(String tenantId, DetectionStrategyPackSnapshot.StrategyItem item) {
        return item != null
                && item.runtimeEligible()
                && resolveReleaseState(item.promotionState()) == LearningArtifactReleaseState.PROMOTED
                && !isRuntimeSuppressed(tenantId, LearningArtifactTypeNames.DETECTION_STRATEGY, item.strategyKey());
    }

    private DetectionStrategyRuntimePack.RuntimeStrategyItem toRuntimeStrategyItem(
            DetectionStrategyPackSnapshot.StrategyItem item) {
        return new DetectionStrategyRuntimePack.RuntimeStrategyItem(
                item.strategyKey(),
                item.strategyVersion(),
                item.strategyFamily(),
                item.supportedThreatGoals(),
                item.requiredSignals(),
                item.recommendedSignals(),
                item.applicableContextClasses(),
                item.minimumEvidenceCount(),
                item.confidenceBand(),
                toMetadata(
                        item.promotionState(),
                        item.sampleSize(),
                        item.outcomeCoverageRate(),
                        item.hardNegativeCoverage(),
                        item.localLiftRate(),
                        item.fpDelta(),
                        item.fnDelta(),
                        item.guardrails()),
                item.evidenceFacts(),
                item.policyFacts());
    }
}