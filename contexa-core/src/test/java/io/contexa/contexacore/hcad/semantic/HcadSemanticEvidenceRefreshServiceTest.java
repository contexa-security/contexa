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
    @DisplayName("Decision refresh should target only normal ALLOW semantic evidence key")
    void decisionEvidenceKeys_shouldTargetOnlyNormalAllowEvidence() {
        HcadProperties properties = new HcadProperties();
        properties.getSemanticEvidence().setEmbeddingModel("text-embedding-3-small");
        properties.getVector().setEmbeddingDimension(1024);
        HcadSemanticEvidenceRefreshService service =
                new HcadSemanticEvidenceRefreshService(() -> null, () -> null, properties);
        SecurityEvent event = SecurityEvent.builder()
                .userId("admin")
                .metadata(Map.of())
                .build();

        List<HcadSemanticEvidenceKey> keys = service.decisionEvidenceKeys(event, Map.of(
                "tenantId", "tenant-a",
                "requestPath", "/contexa/admin/users/123",
                "authorizationPolicyId", "policy-v1",
                "promptContextContractVersion", "prompt-v1"
        ));

        assertThat(keys).hasSize(1);
        HcadSemanticEvidenceKey key = keys.get(0);
        assertThat(key.type()).isEqualTo(HcadSemanticEvidenceType.NORMAL_REQUEST_SIMILARITY);
        assertThat(key.tenantId()).isEqualTo("tenant-a");
        assertThat(key.userId()).isEqualTo("admin");
        assertThat(key.resourceId()).isEqualTo("/contexa/admin/users/{id}");
        assertThat(key.embeddingModel()).isEqualTo("text-embedding-3-small");
        assertThat(key.dimension()).isEqualTo(1024);
    }
}
