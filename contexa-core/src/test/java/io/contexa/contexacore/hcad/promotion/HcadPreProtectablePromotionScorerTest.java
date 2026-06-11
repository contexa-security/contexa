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

import io.contexa.contexacommon.hcad.domain.HCADContext;
import io.contexa.contexacore.properties.HcadProperties;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.LinkedHashMap;

import static org.assertj.core.api.Assertions.assertThat;

class HcadPreProtectablePromotionScorerTest {

    @Test
    @DisplayName("impossible travel and new device should cross the redline")
    void score_strongAnchorCombination_shouldBeEligible() {
        HcadProperties properties = new HcadProperties();
        HcadPreProtectablePromotionScorer scorer = new HcadPreProtectablePromotionScorer(properties);
        HCADContext context = new HCADContext();
        context.setRequestPath("/admin/export/reports");
        context.setHttpMethod("GET");
        context.setIsNewDevice(true);
        context.setAdditionalAttributes(new LinkedHashMap<>());
        context.getAdditionalAttributes().put("impossibleTravel", true);
        context.getAdditionalAttributes().put("resourceSensitivity", "CRITICAL");

        HcadPreProtectablePromotionAssessment assessment = scorer.score(context);

        assertThat(assessment.eligible()).isTrue();
        assertThat(assessment.score()).isGreaterThanOrEqualTo(properties.getPreTrigger().getRedlineScore());
        assertThat(assessment.anchorSignals()).contains("IMPOSSIBLE_TRAVEL", "NEW_DEVICE");
        assertThat(assessment.band()).isEqualTo(HcadPreProtectablePromotionBand.REDLINE);
    }

    @Test
    @DisplayName("single weak signal should stay below the redline")
    void score_singleWeakSignal_shouldRemainLow() {
        HcadProperties properties = new HcadProperties();
        HcadPreProtectablePromotionScorer scorer = new HcadPreProtectablePromotionScorer(properties);
        HCADContext context = new HCADContext();
        context.setRequestPath("/profile");
        context.setHttpMethod("GET");
        context.setRecentRequestCount(2);
        context.setAdditionalAttributes(new LinkedHashMap<>());

        HcadPreProtectablePromotionAssessment assessment = scorer.score(context);

        assertThat(assessment.eligible()).isFalse();
        assertThat(assessment.band()).isEqualTo(HcadPreProtectablePromotionBand.LOW);
    }
}