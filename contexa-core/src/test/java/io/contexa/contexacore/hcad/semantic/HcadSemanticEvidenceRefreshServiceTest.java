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

import io.contexa.contexacommon.domain.SecurityEvent;
import io.contexa.contexacore.properties.HcadProperties;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

class HcadSemanticEvidenceRefreshServiceTest {

    @Test
    @DisplayName("ALLOW decision refresh should target only normal semantic evidence key")
    void decisionEvidenceKeys_allow_shouldTargetOnlyNormalEvidence() {
        HcadSemanticEvidenceRefreshService service = service();
        SecurityEvent event = event();

        List<HcadSemanticEvidenceKey> keys = service.decisionEvidenceKeys(event, metadata(), "ALLOW");

        assertThat(keys).hasSize(1);
        HcadSemanticEvidenceKey key = keys.get(0);
        assertThat(key.type()).isEqualTo(HcadSemanticEvidenceType.NORMAL_REQUEST_SIMILARITY);
        assertThat(key.tenantId()).isEqualTo("tenant-a");
        assertThat(key.userId()).isEqualTo("admin");
        assertThat(key.resourceId()).isEqualTo("/contexa/admin/users/{id}");
        assertThat(key.embeddingModel()).isEqualTo("text-embedding-3-small");
        assertThat(key.dimension()).isEqualTo(1024);
    }

    @Test
    @DisplayName("CHALLENGE decision refresh should target only risk semantic evidence keys")
    void decisionEvidenceKeys_challenge_shouldTargetRiskEvidence() {
        HcadSemanticEvidenceRefreshService service = service();

        List<HcadSemanticEvidenceKey> keys = service.decisionEvidenceKeys(event(), metadata(), "CHALLENGE");

        assertThat(keys).extracting(HcadSemanticEvidenceKey::type)
                .containsExactly(
                        HcadSemanticEvidenceType.RISK_REQUEST_SIMILARITY,
                        HcadSemanticEvidenceType.RESOURCE_LLM_DECISION_SUMMARY);
        assertThat(keys).allSatisfy(key -> {
            assertThat(key.tenantId()).isEqualTo("tenant-a");
            assertThat(key.resourceId()).isEqualTo("/contexa/admin/users/{id}");
            assertThat(key.policyVersion()).isEqualTo("policy-v1");
            assertThat(key.promptTemplateVersion()).isEqualTo("prompt-v1");
            assertThat(key.embeddingModel()).isEqualTo("text-embedding-3-small");
            assertThat(key.dimension()).isEqualTo(1024);
        });
        assertThat(keys.get(0).userId()).isEqualTo("admin");
        assertThat(keys.get(1).userId()).isNull();
    }

    @Test
    @DisplayName("BLOCK decision refresh should target risk semantic evidence keys")
    void decisionEvidenceKeys_block_shouldTargetRiskEvidence() {
        HcadSemanticEvidenceRefreshService service = service();

        List<HcadSemanticEvidenceKey> keys = service.decisionEvidenceKeys(event(), metadata(), "BLOCK");

        assertThat(keys).extracting(HcadSemanticEvidenceKey::type)
                .containsExactly(
                        HcadSemanticEvidenceType.RISK_REQUEST_SIMILARITY,
                        HcadSemanticEvidenceType.RESOURCE_LLM_DECISION_SUMMARY);
    }

    @Test
    @DisplayName("Decision refresh should target both protectable resource id and path family")
    void decisionEvidenceKeys_shouldTargetProtectableIdAndPathFamily() {
        HcadSemanticEvidenceRefreshService service = service();
        Map<String, Object> metadata = Map.of(
                "tenantId", "tenant-a",
                "protectableResourceId", "hcad.live.vendor.export",
                "requestPath", "/contexa/test/hcad/live/vendors/123/export",
                "authorizationPolicyId", "policy-v1",
                "promptContextContractVersion", "prompt-v1");

        List<HcadSemanticEvidenceKey> keys = service.decisionEvidenceKeys(event(), metadata, "CHALLENGE");

        assertThat(keys).hasSize(4);
        assertThat(keys).extracting(key -> key.resourceId() + ":" + key.type())
                .containsExactly(
                        "hcad.live.vendor.export:RISK_REQUEST_SIMILARITY",
                        "hcad.live.vendor.export:RESOURCE_LLM_DECISION_SUMMARY",
                        "/contexa/test/hcad/live/vendors/{id}/export:RISK_REQUEST_SIMILARITY",
                        "/contexa/test/hcad/live/vendors/{id}/export:RESOURCE_LLM_DECISION_SUMMARY");
    }
    @Test
    @DisplayName("Ambiguous or failed actions should not refresh semantic evidence")
    void decisionEvidenceKeys_nonLearningAction_shouldReturnEmpty() {
        HcadSemanticEvidenceRefreshService service = service();

        assertThat(service.decisionEvidenceKeys(event(), metadata(), "ESCALATE")).isEmpty();
        assertThat(service.decisionEvidenceKeys(event(), metadata(), "PENDING_ANALYSIS")).isEmpty();
        assertThat(service.decisionEvidenceKeys(event(), metadata(), "UNKNOWN")).isEmpty();
    }

    private HcadSemanticEvidenceRefreshService service() {
        HcadProperties properties = new HcadProperties();
        properties.getSemanticEvidence().setEmbeddingModel("text-embedding-3-small");
        properties.getVector().setEmbeddingDimension(1024);
        return new HcadSemanticEvidenceRefreshService(() -> null, () -> null, properties);
    }

    private SecurityEvent event() {
        return SecurityEvent.builder()
                .userId("admin")
                .metadata(Map.of())
                .build();
    }

    private Map<String, Object> metadata() {
        return Map.of(
                "tenantId", "tenant-a",
                "requestPath", "/contexa/admin/users/123",
                "authorizationPolicyId", "policy-v1",
                "promptContextContractVersion", "prompt-v1");
    }
}
