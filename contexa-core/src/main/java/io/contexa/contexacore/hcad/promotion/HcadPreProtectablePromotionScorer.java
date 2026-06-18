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
        if (isAuthContextInconsistent(context)) {
            anchors.add(HcadPreProtectablePromotionSignal.AUTH_CONTEXT_INCONSISTENT);
        }
        if (hasRecentPermissionChanges(context)) {
            anchors.add(HcadPreProtectablePromotionSignal.RECENT_PERMISSION_CHANGE);
        }
        if (isPrivilegedAuthorization(context)) {
            anchors.add(HcadPreProtectablePromotionSignal.PRIVILEGED_AUTHORIZATION);
        }
        if (isFreshMfaRequiredButNotFresh(context)) {
            anchors.add(HcadPreProtectablePromotionSignal.FRESH_MFA_REQUIRED);
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
        if (isStaleAuthentication(context)) {
            corroborating.add(HcadPreProtectablePromotionSignal.STALE_AUTHENTICATION);
        }
        if (isLowAuthenticationAssurance(context)) {
            corroborating.add(HcadPreProtectablePromotionSignal.LOW_AUTH_ASSURANCE);
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
        snapshot.put("verificationRequired", attr(context, "verificationRequired"));
        snapshot.put("freshMfaRequired", attr(context, "freshMfaRequired"));
        snapshot.put("authMethod", normalize(context.getAuthenticationMethod()));
        snapshot.put("mfaVerified", context.getHasValidMFA());
        snapshot.put("mfaFresh", attr(context, "mfaFresh"));
        snapshot.put("mfaFreshnessSeconds", attr(context, "mfaFreshnessSeconds"));
        snapshot.put("authenticationAssurance", attr(context, "authenticationAssurance"));
        snapshot.put("authenticationAgeSeconds", attr(context, "authenticationAgeSeconds"));
        snapshot.put("authorizationPrivileged", attr(context, "authorizationPrivileged"));
        snapshot.put("authorizationPolicyId", attr(context, "authorizationPolicyId"));
        snapshot.put("recentPermissionChanges", attr(context, "recentPermissionChanges"));
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

    private boolean isAuthContextInconsistent(HCADContext context) {
        String authMethod = normalize(context.getAuthenticationMethod());
        boolean mfaVerified = Boolean.TRUE.equals(context.getHasValidMFA());
        return "mfa".equals(authMethod) && !mfaVerified;
    }

    private boolean hasRecentPermissionChanges(HCADContext context) {
        Object changes = attr(context, "recentPermissionChanges");
        if (changes instanceof List<?> list) {
            return !list.isEmpty();
        }
        if (changes instanceof String text) {
            return StringUtils.hasText(text);
        }
        return changes != null;
    }

    private boolean isPrivilegedAuthorization(HCADContext context) {
        return asBoolean(attr(context, "authorizationPrivileged"));
    }

    private boolean isFreshMfaRequiredButNotFresh(HCADContext context) {
        return asBoolean(attr(context, "freshMfaRequired")) && !asBoolean(attr(context, "mfaFresh"));
    }

    private boolean isStaleAuthentication(HCADContext context) {
        Long authAgeSeconds = asLong(attr(context, "authenticationAgeSeconds"));
        if (authAgeSeconds == null && context.getSessionAgeMinutes() != null) {
            authAgeSeconds = context.getSessionAgeMinutes() * 60L;
        }
        return authAgeSeconds != null
                && authAgeSeconds > hcadProperties.getPreTrigger().getStaleAuthenticationMaxAgeSeconds();
    }

    private boolean isLowAuthenticationAssurance(HCADContext context) {
        String assurance = normalizeText(attr(context, "authenticationAssurance"));
        if (!StringUtils.hasText(assurance)) {
            return "password".equals(normalize(context.getAuthenticationMethod()));
        }
        List<String> lowValues = hcadProperties.getPreTrigger().getLowAuthenticationAssuranceValues();
        if (lowValues == null || lowValues.isEmpty()) {
            return false;
        }
        return lowValues.stream()
                .filter(StringUtils::hasText)
                .map(this::normalize)
                .anyMatch(assurance::equals);
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

    private int resolveRecentRequestCount(HCADContext context) {
        return context.getRecentRequestCount() == null ? 0 : context.getRecentRequestCount();
    }

    private int resolveFailedLoginAttempts(HCADContext context) {
        return context.getFailedLoginAttempts() == null ? 0 : context.getFailedLoginAttempts();
    }

    private Object attr(HCADContext context, String key) {
        if (context == null || context.getAdditionalAttributes() == null) {
            return null;
        }
        return context.getAdditionalAttributes().get(key);
    }

    private boolean asBoolean(Object value) {
        if (value instanceof Boolean bool) {
            return bool;
        }
        if (value instanceof String text) {
            String normalized = normalize(text);
            return "true".equals(normalized) || "1".equals(normalized) || "yes".equals(normalized);
        }
        return false;
    }

    private Long asLong(Object value) {
        if (value instanceof Number number) {
            return number.longValue();
        }
        if (value instanceof String text && StringUtils.hasText(text)) {
            try {
                return Long.parseLong(text.trim());
            } catch (NumberFormatException ignored) {
                return null;
            }
        }
        return null;
    }

    private String normalizeText(Object value) {
        return value == null ? null : normalize(value.toString());
    }

    private String normalize(String value) {
        return value == null ? null : value.trim().toLowerCase(Locale.ROOT);
    }
}
