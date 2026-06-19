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

import io.contexa.contexacore.hcad.trigger.HcadPreTriggerMode;
import jakarta.servlet.http.HttpServletRequest;

public final class HcadPreProtectablePromotionRequestProjector {

    private HcadPreProtectablePromotionRequestProjector() {
    }

    public static void project(HttpServletRequest request, HcadPreProtectablePromotionAssessment assessment) {
        project(request, assessment, null);
    }

    public static void project(
            HttpServletRequest request,
            HcadPreProtectablePromotionAssessment assessment,
            HcadPreTriggerMode mode) {
        if (request == null || assessment == null) {
            return;
        }
        request.setAttribute(HcadPreProtectablePromotionAttributes.REQUEST_EVALUATED, true);
        if (mode != null) {
            request.setAttribute(HcadPreProtectablePromotionAttributes.REQUEST_MODE, mode.metadataValue());
        }
        request.setAttribute(HcadPreProtectablePromotionAttributes.REQUEST_SCORE, assessment.score());
        request.setAttribute(HcadPreProtectablePromotionAttributes.REQUEST_EARLY_ANALYSIS_SCORE, assessment.earlyAnalysisScore());
        request.setAttribute(HcadPreProtectablePromotionAttributes.REQUEST_BAND, assessment.band().serializedValue());
        request.setAttribute(HcadPreProtectablePromotionAttributes.REQUEST_ELIGIBLE, assessment.eligible());
        request.setAttribute(HcadPreProtectablePromotionAttributes.REQUEST_ANCHOR_SIGNALS, assessment.anchorSignals());
        request.setAttribute(HcadPreProtectablePromotionAttributes.REQUEST_CORROBORATING_SIGNALS, assessment.corroboratingSignals());
        request.setAttribute(HcadPreProtectablePromotionAttributes.REQUEST_REASON_CODES, assessment.reasonCodes());
        request.setAttribute(HcadPreProtectablePromotionAttributes.REQUEST_SUMMARY, assessment.summary());
        request.setAttribute(HcadPreProtectablePromotionAttributes.REQUEST_VERSION, assessment.evaluationVersion());
        request.setAttribute(HcadPreProtectablePromotionAttributes.REQUEST_RAW_SIGNALS, assessment.rawSignalSnapshot());
        Object provenance = assessment.rawSignalSnapshot().get("signalProvenance");
        if (provenance != null) {
            request.setAttribute(HcadPreProtectablePromotionAttributes.REQUEST_PROVENANCE, provenance);
        }
        Object ignoredInputs = assessment.rawSignalSnapshot().get("ignoredInputs");
        if (ignoredInputs != null) {
            request.setAttribute(HcadPreProtectablePromotionAttributes.REQUEST_IGNORED_INPUTS, ignoredInputs);
        }
    }
}
