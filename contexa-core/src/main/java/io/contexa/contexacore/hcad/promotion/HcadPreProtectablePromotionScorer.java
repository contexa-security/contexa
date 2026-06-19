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

import io.contexa.contexacore.hcad.projection.HcadTrustedSource;
import io.contexa.contexacore.hcad.projection.TrustedHcadContextProjection;
import io.contexa.contexacore.properties.HcadProperties;
import org.springframework.util.StringUtils;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;

public class HcadPreProtectablePromotionScorer {

    private final HcadProperties hcadProperties;

    public HcadPreProtectablePromotionScorer(HcadProperties hcadProperties) {
        this.hcadProperties = hcadProperties;
    }

    public HcadPreProtectablePromotionAssessment score(TrustedHcadContextProjection projection) {
        if (projection == null) {
            return HcadPreProtectablePromotionAssessment.unavailable(
                    "Trusted HCAD context projection was not available for pre-protectable promotion scoring.");
        }

        List<HcadPreProtectablePromotionSignal> anchors = new ArrayList<>();
        List<HcadPreProtectablePromotionSignal> corroborating = new ArrayList<>();
        Map<String, Object> rawSignals = createRawSignalSnapshot(projection);

        if (Boolean.TRUE.equals(projection.impossibleTravel())
                && projection.hasTrustedSource("impossibleTravel", HcadTrustedSource.STORE_DERIVED)) {
            anchors.add(HcadPreProtectablePromotionSignal.IMPOSSIBLE_TRAVEL);
        }
        if (projection.failedLoginBurst() != null
                && projection.failedLoginBurst() >= hcadProperties.getPreTrigger().getFailedLoginBurstThreshold()
                && projection.hasTrustedSource("failedLoginBurst", HcadTrustedSource.STORE_DERIVED)) {
            anchors.add(HcadPreProtectablePromotionSignal.FAILED_LOGIN_BURST);
        }
        if (isAuthContextInconsistent(projection)) {
            anchors.add(HcadPreProtectablePromotionSignal.AUTH_CONTEXT_INCONSISTENT);
        }
        if (hasRecentPermissionChanges(projection)) {
            anchors.add(HcadPreProtectablePromotionSignal.RECENT_PERMISSION_CHANGE);
        }
        if (Boolean.TRUE.equals(projection.authorizationPrivileged())
                && projection.hasTrustedSource("authorizationPrivileged", HcadTrustedSource.BRIDGE_VERIFIED)) {
            anchors.add(HcadPreProtectablePromotionSignal.PRIVILEGED_AUTHORIZATION);
        }
        if (isFreshMfaRequiredButNotFresh(projection)) {
            anchors.add(HcadPreProtectablePromotionSignal.FRESH_MFA_REQUIRED);
        }

        if (projection.requestBurst() != null
                && projection.requestBurst() >= hcadProperties.getPreTrigger().getRequestBurstThreshold()
                && projection.hasTrustedSource("requestBurst", HcadTrustedSource.STORE_DERIVED)) {
            corroborating.add(HcadPreProtectablePromotionSignal.REQUEST_BURST);
        }
        if (Boolean.TRUE.equals(projection.rapidSequence())
                && projection.hasTrustedSource("rapidSequence", HcadTrustedSource.STORE_DERIVED)) {
            corroborating.add(HcadPreProtectablePromotionSignal.RAPID_SEQUENCE);
        }
        if (hasPathJump(projection.previousPath(), projection.normalizedPath())
                && projection.hasTrustedSource("previousPath", HcadTrustedSource.STORE_DERIVED)
                && projection.hasTrustedSource("normalizedPath", HcadTrustedSource.TRUSTED_SERVER)) {
            corroborating.add(HcadPreProtectablePromotionSignal.PREVIOUS_PATH_JUMP);
        }
        if (isLowAuthenticationAssurance(projection)) {
            corroborating.add(HcadPreProtectablePromotionSignal.LOW_AUTH_ASSURANCE);
        }
        if (isBaselineUncertain(projection.baselineConfidence())
                && projection.hasTrustedSource("baselineConfidence", HcadTrustedSource.STORE_DERIVED)) {
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
        boolean eligible = hasTriggerQuorum(anchors, corroborating, score);
        String summary = buildSummary(projection, band, score, anchorSignals, corroboratingSignals, eligible);

        rawSignals.put("earlyAnalysisScore", score);
        rawSignals.put("preTriggerScore", score);
        rawSignals.put("earlyAnalysisBand", band.serializedValue());
        rawSignals.put("earlyAnalysisEligible", eligible);
        rawSignals.put("earlyAnalysisVersion", "hcad-early-analysis-v2-trusted-projection");
        rawSignals.put("signalProvenanceSummary", summarizeProvenance(projection));

        return new HcadPreProtectablePromotionAssessment(
                score,
                band,
                eligible,
                anchorSignals,
                corroboratingSignals,
                reasonCodes,
                summary,
                "hcad-early-analysis-v2-trusted-projection",
                rawSignals);
    }

    private Map<String, Object> createRawSignalSnapshot(TrustedHcadContextProjection projection) {
        Map<String, Object> snapshot = new LinkedHashMap<>();
        snapshot.put("userId", projection.userId());
        snapshot.put("tenantId", projection.tenantId());
        snapshot.put("organizationId", projection.organizationId());
        snapshot.put("sessionId", projection.sessionId());
        snapshot.put("contextBindingHash", projection.contextBindingHash());
        snapshot.put("requestPath", projection.normalizedPath());
        snapshot.put("httpMethod", projection.method());
        snapshot.put("remoteIp", projection.clientIp());
        snapshot.put("failedLoginAttempts", projection.failedLoginBurst());
        snapshot.put("recentRequestCount", projection.requestBurst());
        snapshot.put("rapidSequence", projection.rapidSequence());
        snapshot.put("previousPath", projection.previousPath());
        snapshot.put("impossibleTravel", projection.impossibleTravel());
        snapshot.put("verificationRequired", projection.verificationRequired());
        snapshot.put("authMethod", normalize(projection.authenticationMethod()));
        snapshot.put("mfaVerified", projection.mfaVerified());
        snapshot.put("mfaFreshnessSeconds", projection.mfaFreshnessSeconds());
        snapshot.put("authenticationAssurance", projection.authenticationAssurance());
        snapshot.put("authorizationPrivileged", projection.authorizationPrivileged());
        snapshot.put("authorizationPolicyId", projection.authorizationPolicyId());
        snapshot.put("recentPermissionChanges", projection.recentPermissionChanges());
        snapshot.put("baselineConfidence", projection.baselineConfidence());
        snapshot.put("baselineEstablished", projection.baselineEstablished());
        snapshot.put("signalProvenance", projection.provenance());
        snapshot.put("ignoredInputs", projection.ignoredInputs());
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

    private boolean hasTriggerQuorum(
            List<HcadPreProtectablePromotionSignal> anchors,
            List<HcadPreProtectablePromotionSignal> corroborating,
            int score) {
        return anchors != null
                && corroborating != null
                && !anchors.isEmpty()
                && !corroborating.isEmpty()
                && score >= hcadProperties.getPreTrigger().getRedlineScore();
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
            TrustedHcadContextProjection projection,
            HcadPreProtectablePromotionBand band,
            int score,
            List<String> anchorSignals,
            List<String> corroboratingSignals,
            boolean eligible) {
        String requestPath = projection.normalizedPath() == null ? "unknown" : projection.normalizedPath();
        String method = projection.method() == null ? "UNKNOWN" : projection.method();
        String anchors = anchorSignals.isEmpty() ? "none" : String.join(", ", anchorSignals);
        String corroborators = corroboratingSignals.isEmpty() ? "none" : String.join(", ", corroboratingSignals);
        return String.format(
                "Trusted HCAD pre-trigger earlyAnalysisScore=%d (%s, eligible=%s) for %s %s with anchor signals [%s] and corroborating signals [%s].",
                score,
                band.serializedValue(),
                eligible,
                method,
                requestPath,
                anchors,
                corroborators);
    }

    private Map<String, Object> summarizeProvenance(TrustedHcadContextProjection projection) {
        Map<String, Object> summary = new LinkedHashMap<>();
        projection.provenance().forEach((field, provenance) -> summary.put(field, provenance.source().name()));
        return summary;
    }

    private boolean isAuthContextInconsistent(TrustedHcadContextProjection projection) {
        if (!projection.hasTrustedSource("authenticationMethod")
                || !projection.hasTrustedSource("mfaVerified")) {
            return false;
        }
        String authMethod = normalize(projection.authenticationMethod());
        boolean mfaVerified = Boolean.TRUE.equals(projection.mfaVerified());
        return "mfa".equals(authMethod) && !mfaVerified;
    }

    private boolean hasRecentPermissionChanges(TrustedHcadContextProjection projection) {
        return projection.hasTrustedSource("recentPermissionChanges", HcadTrustedSource.STORE_DERIVED)
                && projection.recentPermissionChanges() != null
                && !projection.recentPermissionChanges().isEmpty();
    }

    private boolean isFreshMfaRequiredButNotFresh(TrustedHcadContextProjection projection) {
        if (!Boolean.TRUE.equals(projection.verificationRequired())
                || !projection.hasTrustedSource("verificationRequired", HcadTrustedSource.BRIDGE_VERIFIED)) {
            return false;
        }
        if (!Boolean.TRUE.equals(projection.mfaVerified())) {
            return true;
        }
        Long freshness = projection.mfaFreshnessSeconds();
        return freshness != null && freshness > hcadProperties.getPreTrigger().getFreshMfaMaxAgeSeconds();
    }

    private boolean isLowAuthenticationAssurance(TrustedHcadContextProjection projection) {
        if (!projection.hasTrustedSource("authenticationAssurance", HcadTrustedSource.BRIDGE_VERIFIED)) {
            return false;
        }
        String assurance = normalize(projection.authenticationAssurance());
        if (!StringUtils.hasText(assurance)) {
            return false;
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

    private String normalize(String value) {
        return value == null ? null : value.trim().toLowerCase(Locale.ROOT);
    }
}
