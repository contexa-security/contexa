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
package io.contexa.contexaiam.admin.promptquality.official.api;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.contexa.contexacore.verification.evidence.SealedEvidencePackage;
import io.contexa.contexacore.verification.evidence.SealedEvidencePackageIntegrity;
import io.contexa.contexacore.verification.evidence.SealedEvidencePackageLookupService;
import io.contexa.contexacore.verification.evidence.SealedEvidencePackageRepository;
import io.contexa.contexacore.verification.runtime.OfficialVerificationRunStore;
import io.contexa.contexaiam.admin.promptquality.official.application.PromptQualityOfficialRunDetailService;
import io.contexa.contexaiam.admin.promptquality.official.application.PromptQualityRuntimeEvidenceService;
import io.contexa.contexaiam.admin.promptquality.official.application.RuntimeEvidencePromptConsistencyGate;
import io.contexa.contexaiam.testsupport.PromptQualityTestResolvers;
import org.junit.jupiter.api.Test;
import org.springframework.data.domain.PageImpl;
import org.springframework.data.domain.Pageable;

import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/**
 * PR-74: GET /runtime-evidence/{id} and the views built on the same summary (the dashboard's count of ready evidence)
 * answer with the package's real state, not with whether a hash is written down.
 */
class RuntimeEvidenceIntegrityApiTest {

    private final SealedEvidencePackageIntegrity integrity = new SealedEvidencePackageIntegrity();
    private final SealedEvidencePackageRepository repository = mock(SealedEvidencePackageRepository.class);
    private final PromptQualityOfficialConsoleViewAssembler views = new PromptQualityOfficialConsoleViewAssembler(
            new SealedEvidencePackageLookupService(repository, integrity),
            mock(PromptQualityOfficialRunDetailService.class),
            mock(OfficialVerificationRunStore.class),
            new ObjectMapper(),
            mock(RuntimeEvidencePromptConsistencyGate.class),
            PromptQualityTestResolvers.koreanBundle());
    private final PromptQualityOfficialRuntimeEvidenceApiController api =
            new PromptQualityOfficialRuntimeEvidenceApiController(mock(PromptQualityRuntimeEvidenceService.class), views);

    @Test
    void theDetailOfAnIntactPackageSaysValid() {
        SealedEvidencePackage intact = sealed("pkg-1");
        when(repository.findByPackageId("pkg-1")).thenReturn(Optional.of(intact));

        assertThat(integrityValidOf(api.runtimeEvidenceDetail("pkg-1"))).isTrue();
    }

    @Test
    void theDetailOfAChangedPackageSaysInvalid() {
        SealedEvidencePackage changed = sealed("pkg-1");
        changed.setDecisionJson("{\"action\":\"BLOCK\"}");
        when(repository.findByPackageId("pkg-1")).thenReturn(Optional.of(changed));

        assertThat(integrityValidOf(api.runtimeEvidenceDetail("pkg-1"))).isFalse();
    }

    @Test
    void aSealWithoutAHashIsNotValid() {
        SealedEvidencePackage unverifiable = sealed("pkg-1");
        unverifiable.setPackageHash(null);
        when(repository.findByPackageId("pkg-1")).thenReturn(Optional.of(unverifiable));

        assertThat(integrityValidOf(api.runtimeEvidenceDetail("pkg-1"))).isFalse();
    }

    @Test
    void aChangedPackageDoesNotCountAsReadyEvidence() {
        SealedEvidencePackage intact = sealed("pkg-1");
        SealedEvidencePackage changed = sealed("pkg-2");
        changed.setDecisionJson("{\"action\":\"BLOCK\"}");
        when(repository.findByCapturedAtBetweenOrderByCapturedAtDesc(any(Instant.class), any(Instant.class), any(Pageable.class)))
                .thenReturn(new PageImpl<>(List.of(intact, changed)));

        List<Map<String, Object>> evidence = views.searchEvidence(null, null, null, null, null, null, null, null, 0, 20);

        assertThat(evidence).extracting(item -> item.get("integrityValid")).containsExactly(true, false);
    }

    @SuppressWarnings("unchecked")
    private static boolean integrityValidOf(Map<String, Object> detail) {
        Map<String, Object> summary = (Map<String, Object>) detail.get("summary");
        Map<String, Object> sealedEvidence = (Map<String, Object>) detail.get("sealedEvidence");
        Map<String, Object> sealedSummary = (Map<String, Object>) sealedEvidence.get("summary");
        assertThat(sealedSummary.get("integrityValid")).isEqualTo(summary.get("integrityValid"));
        return (boolean) summary.get("integrityValid");
    }

    private SealedEvidencePackage sealed(String packageId) {
        SealedEvidencePackage pkg = SealedEvidencePackage.builder()
                .packageId(packageId)
                .correlationId("req-" + packageId)
                .requestFactsJson("{\"requestPath\":\"/orders\",\"httpMethod\":\"GET\"}")
                .decisionJson("{\"action\":\"ALLOW\"}")
                .sealed(true)
                .build();
        pkg.setPackageHash(integrity.computeHash(pkg));
        return pkg;
    }
}
