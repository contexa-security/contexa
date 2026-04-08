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
}