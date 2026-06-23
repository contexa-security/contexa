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
package io.contexa.contexacore.hcad.semantic;

import io.contexa.contexacore.properties.HcadProperties;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

class HcadSemanticEvidenceKeyFactoryTest {

    @Test
    @DisplayName("user baseline evidence key should be stable and independent from path fan-out")
    void userBaselineKey_shouldBeStableWithoutRequestPath() {
        HcadSemanticEvidenceKey first = HcadSemanticEvidenceKey.userNormalBaseline(
                "tenant-1", "alice", "baseline-v1", "bge-small", 384, "ev-v1");
        HcadSemanticEvidenceKey second = HcadSemanticEvidenceKey.userNormalBaseline(
                "tenant-1", "alice", "baseline-v1", "bge-small", 384, "ev-v1");

        assertThat(HcadSemanticEvidenceKeyFactory.cacheKey(first))
                .isEqualTo(HcadSemanticEvidenceKeyFactory.cacheKey(second));
        assertThat(HcadSemanticEvidenceKeyFactory.cacheKey(first))
                .startsWith("hcad:semantic:evidence:user-normal-baseline:");
    }

    @Test
    @DisplayName("session flow evidence key should separate actor sessions but not individual paths")
    void sessionFlowKey_shouldIncludeSessionAndContextBindingHash() {
        HcadSemanticEvidenceKey first = HcadSemanticEvidenceKey.sessionRecentFlow(
                "tenant-1", "alice", "session-1", "ctx-1", "flow-v1", "bge-small", 384, "ev-v1");
        HcadSemanticEvidenceKey differentSession = HcadSemanticEvidenceKey.sessionRecentFlow(
                "tenant-1", "alice", "session-2", "ctx-1", "flow-v1", "bge-small", 384, "ev-v1");
        HcadSemanticEvidenceKey differentContext = HcadSemanticEvidenceKey.sessionRecentFlow(
                "tenant-1", "alice", "session-1", "ctx-2", "flow-v1", "bge-small", 384, "ev-v1");

        assertThat(HcadSemanticEvidenceKeyFactory.cacheKey(differentSession))
                .isNotEqualTo(HcadSemanticEvidenceKeyFactory.cacheKey(first));
        assertThat(HcadSemanticEvidenceKeyFactory.cacheKey(differentContext))
                .isNotEqualTo(HcadSemanticEvidenceKeyFactory.cacheKey(first));
    }

    @Test
    @DisplayName("resource semantic evidence key should include policy, prompt, model, and dimension")
    void resourceEvidenceKey_shouldChangeForPolicyPromptModelOrDimension() {
        HcadSemanticEvidenceKey baseline = HcadSemanticEvidenceKey.resourceDecisionSummary(
                "tenant-1", "orders.read", "policy-v1", "prompt-v1", "bge-small", 384, "ev-v1");

        assertThat(HcadSemanticEvidenceKeyFactory.cacheKey(HcadSemanticEvidenceKey.resourceDecisionSummary(
                "tenant-1", "orders.write", "policy-v1", "prompt-v1", "bge-small", 384, "ev-v1")))
                .isNotEqualTo(HcadSemanticEvidenceKeyFactory.cacheKey(baseline));
        assertThat(HcadSemanticEvidenceKeyFactory.cacheKey(HcadSemanticEvidenceKey.resourceDecisionSummary(
                "tenant-1", "orders.read", "policy-v2", "prompt-v1", "bge-small", 384, "ev-v1")))
                .isNotEqualTo(HcadSemanticEvidenceKeyFactory.cacheKey(baseline));
        assertThat(HcadSemanticEvidenceKeyFactory.cacheKey(HcadSemanticEvidenceKey.resourceDecisionSummary(
                "tenant-1", "orders.read", "policy-v1", "prompt-v2", "bge-small", 384, "ev-v1")))
                .isNotEqualTo(HcadSemanticEvidenceKeyFactory.cacheKey(baseline));
        assertThat(HcadSemanticEvidenceKeyFactory.cacheKey(HcadSemanticEvidenceKey.resourceDecisionSummary(
                "tenant-1", "orders.read", "policy-v1", "prompt-v1", "bge-large", 384, "ev-v1")))
                .isNotEqualTo(HcadSemanticEvidenceKeyFactory.cacheKey(baseline));
        assertThat(HcadSemanticEvidenceKeyFactory.cacheKey(HcadSemanticEvidenceKey.resourceDecisionSummary(
                "tenant-1", "orders.read", "policy-v1", "prompt-v1", "bge-small", 768, "ev-v1")))
                .isNotEqualTo(HcadSemanticEvidenceKeyFactory.cacheKey(baseline));
    }

    @Test
    @DisplayName("compatibility key should find stale evidence without treating it as a valid scoring hit")
    void compatibilityKey_shouldIgnoreVersionModelAndDimension() {
        HcadSemanticEvidenceKey baseline = HcadSemanticEvidenceKey.riskRequestSimilarity(
                "tenant-1", "alice", "orders.write", "policy-v1", "prompt-v1", "bge-small", 384, "ev-v1");
        HcadSemanticEvidenceKey changedContract = HcadSemanticEvidenceKey.riskRequestSimilarity(
                "tenant-1", "alice", "orders.write", "policy-v2", "prompt-v2", "bge-large", 768, "ev-v2");

        assertThat(HcadSemanticEvidenceKeyFactory.cacheKey(changedContract))
                .isNotEqualTo(HcadSemanticEvidenceKeyFactory.cacheKey(baseline));
        assertThat(HcadSemanticEvidenceKeyFactory.compatibilityKey(changedContract))
                .isEqualTo(HcadSemanticEvidenceKeyFactory.compatibilityKey(baseline));
    }

    @Test
    @DisplayName("negative cache key should use the same identity with a separate namespace")
    void negativeCacheKey_shouldUseSeparateNamespace() {
        HcadSemanticEvidenceKey key = HcadSemanticEvidenceKey.riskRequestSimilarity(
                "tenant-1", "alice", "orders.write", "policy-v1", "prompt-v1", "bge-small", 384, "ev-v1");

        assertThat(HcadSemanticEvidenceKeyFactory.negativeCacheKey(key))
                .startsWith("hcad:semantic:evidence:absent:risk-request-similarity:");
        assertThat(HcadSemanticEvidenceKeyFactory.negativeCacheKey(key))
                .isNotEqualTo(HcadSemanticEvidenceKeyFactory.cacheKey(key));
    }

    @Test
    @DisplayName("custom namespace should be normalized for Redis and Caffeine providers")
    void cacheKey_customNamespace_shouldNormalizeTrailingColon() {
        HcadSemanticEvidenceKey key = HcadSemanticEvidenceKey.policyPromptSnapshot(
                "tenant-1", "orders.read", "policy-v1", "prompt-v1", "ev-v1");

        assertThat(HcadSemanticEvidenceKeyFactory.cacheKey("custom:namespace:", key))
                .startsWith("custom:namespace:policy-prompt-version-snapshot:");
    }

    @Test
    @DisplayName("semantic evidence type should expose source and invalidation contract")
    void evidenceType_shouldExposeSourceAndInvalidationContract() {
        assertThat(HcadSemanticEvidenceType.USER_NORMAL_BASELINE.authoritativeSource())
                .isEqualTo("user-behavior-baseline-store");
        assertThat(HcadSemanticEvidenceType.RESOURCE_LLM_DECISION_SUMMARY.invalidationScope())
                .contains("policy")
                .contains("prompt template")
                .contains("dimension");
    }

    @Test
    @DisplayName("semantic evidence settings should separate provider role and per-evidence TTL")
    void semanticEvidenceSettings_shouldExposeProviderAndTtls() {
        HcadProperties.SemanticEvidenceSettings settings = new HcadProperties.SemanticEvidenceSettings();

        assertThat(settings.getProvider())
                .isEqualTo(HcadProperties.SemanticEvidenceSettings.EvidenceCacheProvider.AUTO);
        assertThat(settings.ttlSecondsFor(HcadSemanticEvidenceType.USER_NORMAL_BASELINE)).isEqualTo(86400L);
        assertThat(settings.ttlSecondsFor(HcadSemanticEvidenceType.SESSION_RECENT_FLOW)).isEqualTo(1800L);
        assertThat(settings.ttlSecondsFor(HcadSemanticEvidenceType.NORMAL_REQUEST_SIMILARITY)).isEqualTo(1800L);
        assertThat(HcadProperties.SemanticEvidenceSettings.EvidenceCacheProvider.REDIS).isNotNull();
        assertThat(HcadProperties.SemanticEvidenceSettings.EvidenceCacheProvider.CAFFEINE).isNotNull();
    }
}
