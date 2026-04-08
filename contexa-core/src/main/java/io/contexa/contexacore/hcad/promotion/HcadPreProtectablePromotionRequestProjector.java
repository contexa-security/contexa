package io.contexa.contexacore.hcad.promotion;

import jakarta.servlet.http.HttpServletRequest;

public final class HcadPreProtectablePromotionRequestProjector {

    private HcadPreProtectablePromotionRequestProjector() {
    }

    public static void project(HttpServletRequest request, HcadPreProtectablePromotionAssessment assessment) {
        if (request == null || assessment == null) {
            return;
        }
        request.setAttribute(HcadPreProtectablePromotionAttributes.REQUEST_SCORE, assessment.score());
        request.setAttribute(HcadPreProtectablePromotionAttributes.REQUEST_BAND, assessment.band().serializedValue());
        request.setAttribute(HcadPreProtectablePromotionAttributes.REQUEST_ELIGIBLE, assessment.eligible());
        request.setAttribute(HcadPreProtectablePromotionAttributes.REQUEST_ANCHOR_SIGNALS, assessment.anchorSignals());
        request.setAttribute(HcadPreProtectablePromotionAttributes.REQUEST_CORROBORATING_SIGNALS, assessment.corroboratingSignals());
        request.setAttribute(HcadPreProtectablePromotionAttributes.REQUEST_REASON_CODES, assessment.reasonCodes());
        request.setAttribute(HcadPreProtectablePromotionAttributes.REQUEST_SUMMARY, assessment.summary());
        request.setAttribute(HcadPreProtectablePromotionAttributes.REQUEST_VERSION, assessment.evaluationVersion());
        request.setAttribute(HcadPreProtectablePromotionAttributes.REQUEST_RAW_SIGNALS, assessment.rawSignalSnapshot());
    }
}