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
package io.contexa.contexacore.autonomous.learning.evidence;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

class LearningContextEvidenceTest {

    @Test
    @DisplayName("representative comparable should prefer evidence aligned to the strongest delta dimension")
    void representativeComparableShouldPreferStrongestDeltaDimension() {
        RetrievedBehaviorEvidence browserOnly = new RetrievedBehaviorEvidence(
                LearningEvidenceScope.PERSONAL,
                "alice",
                "behavior",
                "doc-browser",
                0.98d,
                "10.10.0.20",
                "CORPORATE",
                "/admin/api/security-test/sensitive/resource-001",
                null,
                "10",
                "1",
                "Chrome",
                "Windows",
                "PASSWORD",
                "READ",
                "SELF_PROFILE",
                "HIGH",
                "resource",
                "15",
                null,
                "browser aligned");
        RetrievedBehaviorEvidence pathAware = new RetrievedBehaviorEvidence(
                LearningEvidenceScope.PERSONAL,
                "alice",
                "behavior",
                "doc-path",
                0.91d,
                "10.10.0.20",
                "CORPORATE",
                "/admin/api/security-test/sensitive/resource-001",
                "/admin/api/security-test/*",
                "10",
                "1",
                "Chrome",
                "Windows",
                "PASSWORD",
                "READ",
                "SELF_PROFILE",
                "HIGH",
                "resource",
                "15",
                null,
                "path aligned");

        LearningContextEvidence evidence = new LearningContextEvidence(
                new CurrentLearningContextSnapshot("10", "1", "CORPORATE", "Chrome", "Windows", "/admin/api/security-test/*", "PASSWORD", "READ", "SELF_PROFILE"),
                emptyBaseline(LearningEvidenceScope.PERSONAL),
                emptyBaseline(LearningEvidenceScope.SUPPORTING),
                List.of(browserOnly, pathAware),
                List.of(),
                new ObservedPatternSnapshot(
                        List.of("CORPORATE"),
                        List.of("10"),
                        List.of("1"),
                        List.of("Chrome"),
                        List.of("Windows"),
                        List.of("/admin/api/security-test/*"),
                        List.of("PASSWORD"),
                        List.of("READ"),
                        List.of("SELF_PROFILE")),
                List.of(new CurrentVsObservedDeltaSnapshot(
                        "pathFamily",
                        "/admin/api/security-test/sensitive/*",
                        "/admin/api/security-test/*",
                        false,
                        "path family unseen in observed paths",
                        LearningEvidenceScope.PERSONAL)),
                List.of("CurrentPathPresentInObservedPaths"),
                List.of());

        assertThat(evidence.representativeComparable(evidence.strongestDelta())).isEqualTo(pathAware);
    }

    private BaselineEvidenceSnapshot emptyBaseline(LearningEvidenceScope scope) {
        return new BaselineEvidenceSnapshot(
                scope,
                false,
                false,
                0L,
                null,
                List.of(),
                List.of(),
                List.of(),
                List.of(),
                List.of(),
                List.of(),
                List.of(),
                List.of(),
                List.of(),
                "");
    }
}
