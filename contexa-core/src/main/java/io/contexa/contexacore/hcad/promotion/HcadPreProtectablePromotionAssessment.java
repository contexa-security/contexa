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
package io.contexa.contexacore.hcad.promotion;

import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

public record HcadPreProtectablePromotionAssessment(
        int score,
        HcadPreProtectablePromotionBand band,
        boolean eligible,
        List<String> anchorSignals,
        List<String> corroboratingSignals,
        List<String> reasonCodes,
        String summary,
        String evaluationVersion,
        Map<String, Object> rawSignalSnapshot
) {

    public HcadPreProtectablePromotionAssessment {
        band = band == null ? HcadPreProtectablePromotionBand.LOW : band;
        anchorSignals = anchorSignals == null ? List.of() : List.copyOf(anchorSignals);
        corroboratingSignals = corroboratingSignals == null ? List.of() : List.copyOf(corroboratingSignals);
        reasonCodes = reasonCodes == null ? List.of() : List.copyOf(reasonCodes);
        summary = summary == null ? "" : summary;
        evaluationVersion = evaluationVersion == null || evaluationVersion.isBlank() ? "hcad-promotion-v1" : evaluationVersion;
        rawSignalSnapshot = rawSignalSnapshot == null
                ? Map.of()
                : Collections.unmodifiableMap(new LinkedHashMap<>(rawSignalSnapshot));
    }

    public static HcadPreProtectablePromotionAssessment unavailable(String summary) {
        return new HcadPreProtectablePromotionAssessment(
                0,
                HcadPreProtectablePromotionBand.LOW,
                false,
                List.of(),
                List.of(),
                List.of(),
                summary,
                "hcad-promotion-v1",
                Map.of());
    }

    public int earlyAnalysisScore() {
        return score;
    }
}
