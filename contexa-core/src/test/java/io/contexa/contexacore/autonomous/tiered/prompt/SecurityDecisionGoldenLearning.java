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
package io.contexa.contexacore.autonomous.tiered.prompt;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.contexa.contexacommon.domain.SecurityEvent;
import io.contexa.contexacommon.security.baseline.BaselineVector;
import io.contexa.contexacore.ThreatAssessment;
import io.contexa.contexacore.autonomous.baseline.BaselineLearningService;
import io.contexa.contexacore.autonomous.baseline.store.BaselineDataStore;
import io.contexa.contexacore.autonomous.tiered.strategy.AbstractTieredStrategy;
import io.contexa.contexacore.properties.SecurityZeroTrustProperties;
import io.contexa.contexacore.properties.TieredStrategyProperties;

import java.util.List;

/**
 * The behaviour analysis of a golden case, built the way the decision layers build it (N-GOLD-1): the baseline service
 * reads the personal and organization baselines the source run held when its decision was sealed (the golden input's
 * learning evidence), and the layers' enrichment fills the analysis from them. The showcase engine the inputs were
 * sealed on runs no seed, threat intelligence, knowledge pack or detection strategy service (contexa.saas.enabled is
 * false), so none takes part here.
 */
final class SecurityDecisionGoldenLearning extends AbstractTieredStrategy {

    private SecurityDecisionGoldenLearning(BaselineLearningService baselineLearningService) {
        super(null, null, null, null, baselineLearningService, null, null, new TieredStrategyProperties());
    }

    /** The analysis of the case's learning evidence; null when the golden case carries none. */
    static SecurityDecisionStandardPromptTemplate.BehaviorAnalysis analysis(JsonNode goldenCase, SecurityEvent event,
                                                                         ObjectMapper objectMapper) {
        JsonNode evidence = goldenCase.path("learningEvidence");
        if (evidence.isMissingNode() || evidence.isNull()) {
            return null;
        }
        SealedBaselines baselines = new SealedBaselines(
                vector(evidence.path("personalBaseline"), objectMapper),
                vector(evidence.path("organizationBaseline"), objectMapper));
        return new SecurityDecisionGoldenLearning(
                new BaselineLearningService(baselines, new SecurityZeroTrustProperties())).analyse(event);
    }

    /** As the first layer converts its analysis for the prompt (Layer1ContextualStrategy). */
    private SecurityDecisionStandardPromptTemplate.BehaviorAnalysis analyse(SecurityEvent event) {
        SecurityDecisionStandardPromptTemplate.BehaviorAnalysis analysis =
                new SecurityDecisionStandardPromptTemplate.BehaviorAnalysis();
        analysis.setBaselineEstablished(
                analyzeBehaviorPatternsBase(event, baselineLearningService, List.of()).isBaselineEstablished());
        enrichBehaviorAnalysisWithRuntimeLearningSupport(analysis, event, null, null, null, null);
        return analysis;
    }

    private static BaselineVector vector(JsonNode node, ObjectMapper objectMapper) {
        return node.isMissingNode() || node.isNull() ? null : objectMapper.convertValue(node, BaselineVector.class);
    }

    @Override
    protected String getLayerName() {
        return "GoldenRender";
    }

    @Override
    public ThreatAssessment evaluate(SecurityEvent event) {
        throw new UnsupportedOperationException("The golden render builds the behaviour analysis only");
    }

    /** The baselines of the sealed decision; whichever user or organization the service asks for. */
    private record SealedBaselines(BaselineVector personal, BaselineVector organization) implements BaselineDataStore {

        @Override
        public BaselineVector getUserBaseline(String userId) {
            return personal;
        }

        @Override
        public void saveUserBaseline(String userId, BaselineVector baseline) {
            throw new UnsupportedOperationException("The sealed baselines are read only");
        }

        @Override
        public BaselineVector getOrganizationBaseline(String organizationId) {
            return organization;
        }

        @Override
        public void saveOrganizationBaseline(String organizationId, BaselineVector baseline) {
            throw new UnsupportedOperationException("The sealed baselines are read only");
        }

        @Override
        public Iterable<BaselineVector> listOrganizationBaselines() {
            return organization != null ? List.of(organization) : List.of();
        }

        @Override
        public long countUserBaselines() {
            return personal != null ? 1 : 0;
        }
    }
}
