package io.contexa.contexacore.hcad.promotion;

import io.contexa.contexacommon.hcad.domain.HCADContext;
import io.contexa.contexacore.properties.HcadProperties;
import org.springframework.util.StringUtils;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;

public class HcadPreProtectablePromotionScorer {

    private static final String EVALUATION_VERSION = "hcad-promotion-v1";

    private final HcadProperties hcadProperties;

    public HcadPreProtectablePromotionScorer(HcadProperties hcadProperties) {
        this.hcadProperties = hcadProperties;
    }

    public HcadPreProtectablePromotionAssessment score(HCADContext context) {
        if (context == null) {
            return HcadPreProtectablePromotionAssessment.unavailable(
                    "HCAD context was not available for pre-protectable promotion scoring.");
        }

        List<HcadPreProtectablePromotionSignal> anchors = new ArrayList<>();
        List<HcadPreProtectablePromotionSignal> corroborating = new ArrayList<>();
        Map<String, Object> rawSignals = createRawSignalSnapshot(context);

        if (Boolean.TRUE.equals(resolveImpossibleTravel(context))) {
            anchors.add(HcadPreProtectablePromotionSignal.IMPOSSIBLE_TRAVEL);
        }
        if (Boolean.TRUE.equals(context.getIsNewDevice())) {
            anchors.add(HcadPreProtectablePromotionSignal.NEW_DEVICE);
        }
        if (resolveFailedLoginAttempts(context) >= hcadProperties.getPreTrigger().getFailedLoginBurstThreshold()) {
            anchors.add(HcadPreProtectablePromotionSignal.FAILED_LOGIN_BURST);
        }
        if (isAuthContextInconsistent(context, isSensitiveSurface(context))) {
            anchors.add(HcadPreProtectablePromotionSignal.AUTH_CONTEXT_INCONSISTENT);
        }

        if (resolveRecentRequestCount(context) >= hcadProperties.getPreTrigger().getRequestBurstThreshold()) {
            corroborating.add(HcadPreProtectablePromotionSignal.REQUEST_BURST);
        }
        Long lastInterval = context.getLastRequestInterval();
        if (lastInterval != null && lastInterval > 0 && lastInterval <= hcadProperties.getPreTrigger().getRapidRequestIntervalMs()) {
            corroborating.add(HcadPreProtectablePromotionSignal.RAPID_SEQUENCE);
        }
        if (hasPathJump(context.getPreviousPath(), context.getRequestPath())) {
            corroborating.add(HcadPreProtectablePromotionSignal.PREVIOUS_PATH_JUMP);
        }
        if (isSensitiveSurface(context)) {
            corroborating.add(HcadPreProtectablePromotionSignal.SENSITIVE_SURFACE);
        }
        if (isBaselineUncertain(context.getBaselineConfidence())) {
            corroborating.add(HcadPreProtectablePromotionSignal.BASELINE_UNCERTAIN);
        }

        int score = calculateScore(anchors, corroborating);
        List<String> anchorSignals = anchors.stream().map(Enum::name).toList();
        List<String> corroboratingSignals = corroborating.stream().map(Enum::name).toList();
        List<String> reasonCodes = new ArrayList<>(anchorSignals);
        for (String signal : corroboratingSignals) {
            if (!reasonCodes.contains(signal)) {
                reasonCodes.add(signal);
            }
        }
        HcadPreProtectablePromotionBand band = resolveBand(score);
        boolean eligible = !anchors.isEmpty() && score >= hcadProperties.getPreTrigger().getRedlineScore();
        String summary = buildSummary(context, band, score, anchorSignals, corroboratingSignals, eligible);

        rawSignals.put("promotionScore", score);
        rawSignals.put("promotionBand", band.serializedValue());
        rawSignals.put("promotionEligible", eligible);
        rawSignals.put("promotionVersion", EVALUATION_VERSION);

        return new HcadPreProtectablePromotionAssessment(
                score,
                band,
                eligible,
                anchorSignals,
                corroboratingSignals,
                reasonCodes,
                summary,
                EVALUATION_VERSION,
                rawSignals);
    }

    private Map<String, Object> createRawSignalSnapshot(HCADContext context) {
        Map<String, Object> snapshot = new LinkedHashMap<>();
        snapshot.put("userId", context.getUserId());
        snapshot.put("requestPath", context.getRequestPath());
        snapshot.put("httpMethod", context.getHttpMethod());
        snapshot.put("remoteIp", context.getRemoteIp());
        snapshot.put("failedLoginAttempts", resolveFailedLoginAttempts(context));
        snapshot.put("recentRequestCount", resolveRecentRequestCount(context));
        snapshot.put("lastRequestIntervalMs", context.getLastRequestInterval());
        snapshot.put("previousPath", context.getPreviousPath());
        snapshot.put("isNewDevice", context.getIsNewDevice());
        snapshot.put("impossibleTravel", resolveImpossibleTravel(context));
        snapshot.put("resourceSensitivity", resolveResourceSensitivity(context));
        snapshot.put("isSensitiveResource", context.getIsSensitiveResource());
        snapshot.put("authMethod", normalize(context.getAuthenticationMethod()));
        snapshot.put("mfaVerified", context.getHasValidMFA());
        snapshot.put("baselineConfidence", context.getBaselineConfidence());
        return snapshot;
    }

    private int calculateScore(
            List<HcadPreProtectablePromotionSignal> anchors,
            List<HcadPreProtectablePromotionSignal> corroborating) {
        int score = 0;
        for (HcadPreProtectablePromotionSignal signal : anchors) {
            score += signal.weight();
        }
        for (HcadPreProtectablePromotionSignal signal : corroborating) {
            score += signal.weight();
        }
        return Math.min(100, score);
    }

    private HcadPreProtectablePromotionBand resolveBand(int score) {
        if (score >= hcadProperties.getPreTrigger().getRedlineScore()) {
            return HcadPreProtectablePromotionBand.REDLINE;
        }
        if (score >= hcadProperties.getPreTrigger().getHighRiskScore()) {
            return HcadPreProtectablePromotionBand.HIGH;
        }
        if (score >= hcadProperties.getPreTrigger().getMediumRiskScore()) {
            return HcadPreProtectablePromotionBand.MEDIUM;
        }
        return HcadPreProtectablePromotionBand.LOW;
    }

    private String buildSummary(
            HCADContext context,
            HcadPreProtectablePromotionBand band,
            int score,
            List<String> anchorSignals,
            List<String> corroboratingSignals,
            boolean eligible) {
        String requestPath = context.getRequestPath() == null ? "unknown" : context.getRequestPath();
        String method = context.getHttpMethod() == null ? "UNKNOWN" : context.getHttpMethod();
        String anchors = anchorSignals.isEmpty() ? "none" : String.join(", ", anchorSignals);
        String corroborators = corroboratingSignals.isEmpty() ? "none" : String.join(", ", corroboratingSignals);
        return String.format(
                "HCAD pre-protectable promotion scored %d (%s, eligible=%s) for %s %s with anchor signals [%s] and corroborating signals [%s].",
                score,
                band.serializedValue(),
                eligible,
                method,
                requestPath,
                anchors,
                corroborators);
    }

    private boolean isAuthContextInconsistent(HCADContext context, boolean sensitiveSurface) {
        String authMethod = normalize(context.getAuthenticationMethod());
        boolean mfaVerified = Boolean.TRUE.equals(context.getHasValidMFA());
        if ("mfa".equals(authMethod) && !mfaVerified) {
            return true;
        }
        return sensitiveSurface && !mfaVerified && (!StringUtils.hasText(authMethod) || "password".equals(authMethod));
    }

    private boolean isSensitiveSurface(HCADContext context) {
        String resourceSensitivity = resolveResourceSensitivity(context);
        if ("high".equals(resourceSensitivity) || "critical".equals(resourceSensitivity)) {
            return true;
        }
        if (Boolean.TRUE.equals(context.getIsSensitiveResource())) {
            return true;
        }
        String requestPath = context.getRequestPath();
        if (!StringUtils.hasText(requestPath)) {
            return false;
        }
        String normalizedPath = requestPath.toLowerCase(Locale.ROOT);
        for (String indicator : hcadProperties.getPreTrigger().getSensitivePathIndicators()) {
            if (indicator != null && !indicator.isBlank() && normalizedPath.contains(indicator.toLowerCase(Locale.ROOT))) {
                return true;
            }
        }
        return false;
    }

    private boolean hasPathJump(String previousPath, String requestPath) {
        if (!StringUtils.hasText(previousPath) || !StringUtils.hasText(requestPath)) {
            return false;
        }
        String previous = previousPath.trim();
        String current = requestPath.trim();
        if (previous.equals(current)) {
            return false;
        }
        return !current.startsWith(previous) && !previous.startsWith(current);
    }

    private boolean isBaselineUncertain(Double baselineConfidence) {
        if (baselineConfidence == null || baselineConfidence.isNaN()) {
            return true;
        }
        return baselineConfidence < hcadProperties.getPreTrigger().getLowBaselineConfidenceThreshold();
    }

    private Boolean resolveImpossibleTravel(HCADContext context) {
        Map<String, Object> attrs = context.getAdditionalAttributes();
        if (attrs == null) {
            return false;
        }
        Object impossibleTravel = attrs.get("impossibleTravel");
        return impossibleTravel instanceof Boolean bool ? bool : false;
    }

    private String resolveResourceSensitivity(HCADContext context) {
        Map<String, Object> attrs = context.getAdditionalAttributes();
        if (attrs == null) {
            return null;
        }
        Object resourceSensitivity = attrs.get("resourceSensitivity");
        return normalize(resourceSensitivity == null ? null : resourceSensitivity.toString());
    }

    private int resolveRecentRequestCount(HCADContext context) {
        return context.getRecentRequestCount() == null ? 0 : context.getRecentRequestCount();
    }

    private int resolveFailedLoginAttempts(HCADContext context) {
        return context.getFailedLoginAttempts() == null ? 0 : context.getFailedLoginAttempts();
    }

    private String normalize(String value) {
        return value == null ? null : value.trim().toLowerCase(Locale.ROOT);
    }
}