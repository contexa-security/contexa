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

import io.contexa.contexacore.hcad.projection.HcadFieldProvenance;
import io.contexa.contexacore.hcad.projection.HcadPromptSecurityContextFieldRegistry;
import io.contexa.contexacore.hcad.projection.HcadTrustedSource;
import io.contexa.contexacore.hcad.projection.TrustedHcadContextProjection;
import io.contexa.contexacore.hcad.semantic.CachedSemanticEvidenceProjection;
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
        return score(projection, CachedSemanticEvidenceProjection.unavailable("SEMANTIC_EVIDENCE_NOT_REQUESTED"));
    }

    public HcadPreProtectablePromotionAssessment score(
            TrustedHcadContextProjection projection,
            CachedSemanticEvidenceProjection semanticEvidence) {
        if (projection == null) {
            return HcadPreProtectablePromotionAssessment.unavailable(
                    "Trusted HCAD context projection was not available for pre-protectable promotion scoring.");
        }

        List<HcadPreProtectablePromotionSignal> anchors = new ArrayList<>();
        List<HcadPreProtectablePromotionSignal> corroborating = new ArrayList<>();
        Map<String, Object> rawSignals = createRawSignalSnapshot(projection);
        CachedSemanticEvidenceProjection evidence = semanticEvidence == null
                ? CachedSemanticEvidenceProjection.unavailable("SEMANTIC_EVIDENCE_NOT_AVAILABLE")
                : semanticEvidence;
        rawSignals.put("semanticEvidence", evidence.snapshot());
        Map<String, HcadFieldProvenance> scoringProvenance = new LinkedHashMap<>(projection.provenance());
        HcadFieldProvenance semanticEvidenceProvenance = evidence.hasUsableEvidence()
                ? HcadFieldProvenance.present(
                "semanticEvidence",
                HcadTrustedSource.CACHE_DERIVED,
                "Resolved from Redis/Caffeine cached semantic evidence built from prior ALLOW decisions.")
                : HcadFieldProvenance.absent(
                "semanticEvidence",
                "Redis/Caffeine cached semantic evidence was unavailable or not usable for scoring.");
        scoringProvenance.put("semanticEvidence", semanticEvidenceProvenance);
        rawSignals.put("signalProvenance", scoringProvenance);
        rawSignals.put("promptContextFieldContracts", HcadPromptSecurityContextFieldRegistry.snapshot(scoringProvenance));
        rawSignals.put("scoringContractSnapshot", HcadPromptSecurityContextFieldRegistry.scoringSnapshot(scoringProvenance));

        if (Boolean.TRUE.equals(projection.impossibleTravel())
                && projection.hasScorableTrustedSource("impossibleTravel", HcadTrustedSource.STORE_DERIVED)) {
            anchors.add(HcadPreProtectablePromotionSignal.IMPOSSIBLE_TRAVEL);
        }
        if (projection.failedLoginBurst() != null
                && projection.failedLoginBurst() >= hcadProperties.getPreTrigger().getFailedLoginBurstThreshold()
                && projection.hasScorableTrustedSource("failedLoginBurst", HcadTrustedSource.STORE_DERIVED)) {
            anchors.add(HcadPreProtectablePromotionSignal.FAILED_LOGIN_BURST);
        }
        if (isAuthContextInconsistent(projection)) {
            anchors.add(HcadPreProtectablePromotionSignal.AUTH_CONTEXT_INCONSISTENT);
        }
        if (hasRecentPermissionChanges(projection)) {
            anchors.add(HcadPreProtectablePromotionSignal.RECENT_PERMISSION_CHANGE);
        }
        if (Boolean.TRUE.equals(projection.authorizationPrivileged())
                && projection.hasScorableTrustedSource("authorizationPrivileged", HcadTrustedSource.BRIDGE_VERIFIED)) {
            anchors.add(HcadPreProtectablePromotionSignal.PRIVILEGED_AUTHORIZATION);
        }
        if (isFreshMfaRequiredButNotFresh(projection)) {
            anchors.add(HcadPreProtectablePromotionSignal.FRESH_MFA_REQUIRED);
        }

        if (projection.requestBurst() != null
                && projection.requestBurst() >= hcadProperties.getPreTrigger().getRequestBurstThreshold()
                && projection.hasScorableTrustedSource("requestBurst", HcadTrustedSource.STORE_DERIVED)) {
            corroborating.add(HcadPreProtectablePromotionSignal.REQUEST_BURST);
        }
        if (Boolean.TRUE.equals(projection.rapidSequence())
                && projection.hasScorableTrustedSource("rapidSequence", HcadTrustedSource.STORE_DERIVED)) {
            corroborating.add(HcadPreProtectablePromotionSignal.RAPID_SEQUENCE);
        }
        if (hasPathJump(projection.previousPath(), projection.normalizedPath())
                && projection.hasScorableTrustedSource("previousPath", HcadTrustedSource.STORE_DERIVED)
                && projection.hasScorableTrustedSource("normalizedPath", HcadTrustedSource.TRUSTED_SERVER)) {
            corroborating.add(HcadPreProtectablePromotionSignal.PREVIOUS_PATH_JUMP);
        }
        if (isLowAuthenticationAssurance(projection)) {
            corroborating.add(HcadPreProtectablePromotionSignal.LOW_AUTH_ASSURANCE);
        }
        if (hasMaterialBaselineMismatch(projection)) {
            corroborating.add(HcadPreProtectablePromotionSignal.BASELINE_MATERIAL_MISMATCH);
        }
        List<HcadPreProtectablePromotionSignal> semanticCorroborating = new ArrayList<>();
        if (evidence.hasMismatchAtLeast(hcadProperties.getSemanticEvidence().getMismatchScoreThreshold())) {
            semanticCorroborating.add(HcadPreProtectablePromotionSignal.SEMANTIC_EVIDENCE_MISMATCH);
        }
        if (evidence.hasRiskSimilarityAtLeast(hcadProperties.getSemanticEvidence().getRiskSimilarityThreshold())) {
            semanticCorroborating.add(HcadPreProtectablePromotionSignal.SEMANTIC_RISK_SIMILARITY);
        }
        corroborating.addAll(semanticCorroborating);

        int structuredScore = calculateScore(anchors, corroboratingWithoutSemantic(corroborating));
        int semanticScore = calculateSemanticScore(semanticCorroborating, evidence);
        int normalSuppressionScore = calculateNormalSimilaritySuppression(evidence);
        int score = boundScore(structuredScore + semanticScore - normalSuppressionScore);
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
        rawSignals.put("structuredScore", structuredScore);
        rawSignals.put("semanticEvidenceScore", semanticScore);
        rawSignals.put("semanticNormalSuppressionScore", normalSuppressionScore);
        rawSignals.put("semanticEvidenceScoreApplied", semanticScore - normalSuppressionScore);
        rawSignals.put("earlyAnalysisBand", band.serializedValue());
        rawSignals.put("earlyAnalysisEligible", eligible);
        rawSignals.put("earlyAnalysisVersion", "hcad-early-analysis-v2-trusted-projection");
        rawSignals.put("scoringThresholds", scoringThresholds());
        rawSignals.put("eligibleQuorum", eligibleQuorum(anchors, corroborating, score));
        rawSignals.put("eligibleFalseReasons", eligibleFalseReasons(anchors, corroborating, score, eligible));
        rawSignals.put("scoreFormula", scoreFormula(structuredScore, semanticScore, normalSuppressionScore, score));
        rawSignals.put("signalExplanations", signalExplanations(
                HcadPreProtectablePromotionSignal.values(),
                anchors,
                corroborating,
                rawSignals,
                scoringProvenance,
                evidence));
        rawSignals.put("signalProvenanceSummary", summarizeProvenance(scoringProvenance));

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
        snapshot.put("baselineComparison", projection.baselineComparison());
        snapshot.put("promptContextContractVersion", projection.promptContextContractVersion());
        snapshot.put("promptContextFieldContracts", projection.promptContextFieldContracts());
        snapshot.put("scoringContractSnapshot",
                HcadPromptSecurityContextFieldRegistry.scoringSnapshot(projection.provenance()));
        snapshot.put("signalProvenance", projection.provenance());
        snapshot.put("ignoredInputs", projection.ignoredInputs());
        snapshot.put("ignoredInputReasons", ignoredInputReasons(projection.ignoredInputs()));
        return snapshot;
    }

    private Map<String, Object> ignoredInputReasons(Map<String, Object> ignoredInputs) {
        Map<String, Object> reasons = new LinkedHashMap<>();
        if (ignoredInputs == null || ignoredInputs.isEmpty()) {
            return reasons;
        }
        ignoredInputs.forEach((key, value) -> {
            if (value instanceof Map<?, ?> map && map.containsKey("reason")) {
                reasons.put(key, map.get("reason"));
            } else {
                reasons.put(key, "Client-supplied value is excluded from HCAD pre-trigger scoring.");
            }
        });
        return reasons;
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
        return boundScore(score);
    }

    private int calculateSemanticScore(
            List<HcadPreProtectablePromotionSignal> semanticCorroborating,
            CachedSemanticEvidenceProjection evidence) {
        if (semanticCorroborating == null || semanticCorroborating.isEmpty() || evidence == null) {
            return 0;
        }
        int score = 0;
        for (HcadPreProtectablePromotionSignal signal : semanticCorroborating) {
            score += signal.weight();
        }
        if (evidence.hasStaleHit() && !evidence.hasFreshHit()) {
            double multiplier = Math.max(0.0d, Math.min(1.0d,
                    hcadProperties.getSemanticEvidence().getStaleEvidenceWeightMultiplier()));
            score = (int) Math.round(score * multiplier);
        }
        return boundScore(score);
    }

    private int calculateNormalSimilaritySuppression(CachedSemanticEvidenceProjection evidence) {
        if (evidence == null || !evidence.hasUsableEvidence()) {
            return 0;
        }
        if (evidence.maxSimilarityToNormal() < hcadProperties.getSemanticEvidence().getNormalSimilarityThreshold()) {
            return 0;
        }
        return Math.max(0, hcadProperties.getSemanticEvidence().getNormalSimilaritySuppressionScore());
    }

    private List<HcadPreProtectablePromotionSignal> corroboratingWithoutSemantic(
            List<HcadPreProtectablePromotionSignal> corroborating) {
        if (corroborating == null || corroborating.isEmpty()) {
            return List.of();
        }
        return corroborating.stream()
                .filter(signal -> signal != HcadPreProtectablePromotionSignal.SEMANTIC_EVIDENCE_MISMATCH)
                .filter(signal -> signal != HcadPreProtectablePromotionSignal.SEMANTIC_RISK_SIMILARITY)
                .toList();
    }

    private int boundScore(int score) {
        return Math.max(0, Math.min(100, score));
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

    private Map<String, Object> summarizeProvenance(Map<String, HcadFieldProvenance> provenance) {
        Map<String, Object> summary = new LinkedHashMap<>();
        if (provenance != null) {
            provenance.forEach((field, fieldProvenance) -> {
                if (fieldProvenance != null) {
                    summary.put(field, fieldProvenance.source().name());
                }
            });
        }
        return summary;
    }

    private Map<String, Object> scoringThresholds() {
        Map<String, Object> thresholds = new LinkedHashMap<>();
        thresholds.put("mediumRiskScore", hcadProperties.getPreTrigger().getMediumRiskScore());
        thresholds.put("highRiskScore", hcadProperties.getPreTrigger().getHighRiskScore());
        thresholds.put("redlineScore", hcadProperties.getPreTrigger().getRedlineScore());
        thresholds.put("failedLoginBurstThreshold", hcadProperties.getPreTrigger().getFailedLoginBurstThreshold());
        thresholds.put("requestBurstThreshold", hcadProperties.getPreTrigger().getRequestBurstThreshold());
        thresholds.put("freshMfaMaxAgeSeconds", hcadProperties.getPreTrigger().getFreshMfaMaxAgeSeconds());
        thresholds.put("semanticMismatchScoreThreshold", hcadProperties.getSemanticEvidence().getMismatchScoreThreshold());
        thresholds.put("semanticRiskSimilarityThreshold", hcadProperties.getSemanticEvidence().getRiskSimilarityThreshold());
        thresholds.put("semanticNormalSimilarityThreshold", hcadProperties.getSemanticEvidence().getNormalSimilarityThreshold());
        thresholds.put("semanticNormalSimilaritySuppressionScore", hcadProperties.getSemanticEvidence().getNormalSimilaritySuppressionScore());
        thresholds.put("semanticStaleEvidenceWeightMultiplier", hcadProperties.getSemanticEvidence().getStaleEvidenceWeightMultiplier());
        return thresholds;
    }

    private Map<String, Object> eligibleQuorum(
            List<HcadPreProtectablePromotionSignal> anchors,
            List<HcadPreProtectablePromotionSignal> corroborating,
            int score) {
        Map<String, Object> quorum = new LinkedHashMap<>();
        quorum.put("requiresAnchorSignal", true);
        quorum.put("requiresCorroboratingSignal", true);
        quorum.put("minimumScore", hcadProperties.getPreTrigger().getRedlineScore());
        quorum.put("actualAnchorCount", anchors == null ? 0 : anchors.size());
        quorum.put("actualCorroboratingCount", corroborating == null ? 0 : corroborating.size());
        quorum.put("actualScore", score);
        return quorum;
    }

    private List<String> eligibleFalseReasons(
            List<HcadPreProtectablePromotionSignal> anchors,
            List<HcadPreProtectablePromotionSignal> corroborating,
            int score,
            boolean eligible) {
        if (eligible) {
            return List.of();
        }
        List<String> reasons = new ArrayList<>();
        if (anchors == null || anchors.isEmpty()) {
            reasons.add("TRUSTED_ANCHOR_SIGNAL_REQUIRED");
        }
        if (corroborating == null || corroborating.isEmpty()) {
            reasons.add("CORROBORATING_SIGNAL_REQUIRED");
        }
        if (score < hcadProperties.getPreTrigger().getRedlineScore()) {
            reasons.add("REDLINE_SCORE_THRESHOLD_NOT_MET");
        }
        return reasons;
    }

    private Map<String, Object> scoreFormula(
            int structuredScore,
            int semanticScore,
            int normalSuppressionScore,
            int finalScore) {
        Map<String, Object> formula = new LinkedHashMap<>();
        formula.put("expression", "bounded(structuredScore + semanticEvidenceScore - normalSuppressionScore)");
        formula.put("structuredScore", structuredScore);
        formula.put("semanticEvidenceScore", semanticScore);
        formula.put("normalSuppressionScore", normalSuppressionScore);
        formula.put("finalScore", finalScore);
        return formula;
    }

    private List<Map<String, Object>> signalExplanations(
            HcadPreProtectablePromotionSignal[] allSignals,
            List<HcadPreProtectablePromotionSignal> anchors,
            List<HcadPreProtectablePromotionSignal> corroborating,
            Map<String, Object> rawSignals,
            Map<String, HcadFieldProvenance> scoringProvenance,
            CachedSemanticEvidenceProjection evidence) {
        if (allSignals == null) {
            return List.of();
        }
        List<Map<String, Object>> explanations = new ArrayList<>();
        for (HcadPreProtectablePromotionSignal signal : allSignals) {
            boolean appliedAsAnchor = anchors != null && anchors.contains(signal);
            boolean appliedAsCorroborating = corroborating != null && corroborating.contains(signal);
            Map<String, Object> explanation = new LinkedHashMap<>();
            explanation.put("signal", signal.name());
            explanation.put("role", signal.isAnchor() ? "ANCHOR" : "CORROBORATING");
            explanation.put("weight", signal.weight());
            explanation.put("requiredFields", signal.requiredContractFields());
            explanation.put("condition", signalCondition(signal));
            explanation.put("applied", appliedAsAnchor || appliedAsCorroborating);
            explanation.put("appliedAs", appliedAsAnchor ? "ANCHOR" : appliedAsCorroborating ? "CORROBORATING" : null);
            explanation.put("currentValues", valuesForFields(rawSignals, signal.requiredContractFields()));
            explanation.put("fieldSources", sourcesForFields(scoringProvenance, signal.requiredContractFields()));
            explanation.put("unmetReason", appliedAsAnchor || appliedAsCorroborating
                    ? null
                    : signalUnmetReason(signal, scoringProvenance, evidence));
            explanations.add(explanation);
        }
        return explanations;
    }

    private String signalCondition(HcadPreProtectablePromotionSignal signal) {
        return switch (signal) {
            case IMPOSSIBLE_TRAVEL -> "Stored impossible-travel indicator is true.";
            case FAILED_LOGIN_BURST -> "Stored failed-login burst count meets the configured threshold.";
            case AUTH_CONTEXT_INCONSISTENT -> "Trusted authentication context is internally inconsistent.";
            case RECENT_PERMISSION_CHANGE -> "Stored recent permission changes exist.";
            case PRIVILEGED_AUTHORIZATION -> "Bridge-verified authorization context marks the request as privileged.";
            case FRESH_MFA_REQUIRED -> "Verified resource requires fresh MFA and the current MFA state is absent or stale.";
            case REQUEST_BURST -> "Stored request count meets the configured burst threshold.";
            case RAPID_SEQUENCE -> "Stored request sequence is marked rapid.";
            case PREVIOUS_PATH_JUMP -> "Stored previous path and current path indicate an unusual navigation jump.";
            case LOW_AUTH_ASSURANCE -> "Bridge-verified authentication assurance matches a configured low assurance value.";
            case BASELINE_MATERIAL_MISMATCH -> "Personal baseline comparison reports a material mismatch.";
            case SEMANTIC_EVIDENCE_MISMATCH -> "Fresh cached semantic evidence differs from prior allowed request evidence.";
            case SEMANTIC_RISK_SIMILARITY -> "Fresh cached semantic evidence is similar to verified risk evidence.";
        };
    }

    private String signalUnmetReason(
            HcadPreProtectablePromotionSignal signal,
            Map<String, HcadFieldProvenance> scoringProvenance,
            CachedSemanticEvidenceProjection evidence) {
        if (signal == HcadPreProtectablePromotionSignal.SEMANTIC_EVIDENCE_MISMATCH
                || signal == HcadPreProtectablePromotionSignal.SEMANTIC_RISK_SIMILARITY) {
            if (evidence == null || !evidence.hasFreshHit()) {
                return "FRESH_SEMANTIC_EVIDENCE_REQUIRED";
            }
            return "SEMANTIC_THRESHOLD_NOT_MET";
        }
        if (!requiredFieldsPresentForScoring(signal, scoringProvenance)) {
            return "REQUIRED_TRUSTED_CONTEXT_ABSENT";
        }
        return "CONDITION_NOT_MET";
    }

    private boolean requiredFieldsPresentForScoring(
            HcadPreProtectablePromotionSignal signal,
            Map<String, HcadFieldProvenance> scoringProvenance) {
        if (signal == null || signal.requiredContractFields().isEmpty()) {
            return true;
        }
        if (scoringProvenance == null || scoringProvenance.isEmpty()) {
            return false;
        }
        for (String field : signal.requiredContractFields()) {
            HcadFieldProvenance provenance = scoringProvenance.get(field);
            if (provenance == null || !provenance.present()) {
                return false;
            }
            if (!scoringAllowed(field, provenance.source())) {
                return false;
            }
        }
        return true;
    }

    private Map<String, Object> valuesForFields(Map<String, Object> rawSignals, List<String> fields) {
        Map<String, Object> values = new LinkedHashMap<>();
        if (fields == null || fields.isEmpty()) {
            return values;
        }
        for (String field : fields) {
            values.put(field, rawSignals == null ? null : rawSignals.get(field));
        }
        return values;
    }

    private List<Map<String, Object>> sourcesForFields(
            Map<String, HcadFieldProvenance> scoringProvenance,
            List<String> fields) {
        if (fields == null || fields.isEmpty()) {
            return List.of();
        }
        List<Map<String, Object>> sources = new ArrayList<>();
        for (String field : fields) {
            HcadFieldProvenance provenance = scoringProvenance == null ? null : scoringProvenance.get(field);
            Map<String, Object> source = new LinkedHashMap<>();
            source.put("field", field);
            source.put("source", provenance == null ? HcadTrustedSource.ABSENT.name() : provenance.source().name());
            source.put("present", provenance != null && provenance.present());
            source.put("reason", provenance == null ? "No trusted value was projected for this field." : provenance.reason());
            source.put("scoringAllowed", provenance != null && scoringAllowed(field, provenance.source()));
            sources.add(source);
        }
        return sources;
    }

    private boolean scoringAllowed(String field, HcadTrustedSource source) {
        return HcadPromptSecurityContextFieldRegistry.contract(field) != null
                && HcadPromptSecurityContextFieldRegistry.contract(field).allowsScoringFrom(source);
    }

    private boolean isAuthContextInconsistent(TrustedHcadContextProjection projection) {
        if (!projection.hasScorableTrustedSource("authenticationMethod")
                || !projection.hasScorableTrustedSource("mfaVerified")) {
            return false;
        }
        String authMethod = normalize(projection.authenticationMethod());
        boolean mfaVerified = Boolean.TRUE.equals(projection.mfaVerified());
        return ("mfa".equals(authMethod) || "mfa_only".equals(authMethod)) && !mfaVerified;
    }

    private boolean hasRecentPermissionChanges(TrustedHcadContextProjection projection) {
        return projection.hasScorableTrustedSource("recentPermissionChanges", HcadTrustedSource.STORE_DERIVED)
                && projection.recentPermissionChanges() != null
                && !projection.recentPermissionChanges().isEmpty();
    }

    private boolean isFreshMfaRequiredButNotFresh(TrustedHcadContextProjection projection) {
        if (!Boolean.TRUE.equals(projection.verificationRequired())
                || !projection.hasScorableTrustedSource("verificationRequired", HcadTrustedSource.BRIDGE_VERIFIED)) {
            return false;
        }
        if (!Boolean.TRUE.equals(projection.mfaVerified())) {
            return true;
        }
        Long freshness = projection.mfaFreshnessSeconds();
        return freshness != null && freshness > hcadProperties.getPreTrigger().getFreshMfaMaxAgeSeconds();
    }

    private boolean isLowAuthenticationAssurance(TrustedHcadContextProjection projection) {
        if (!projection.hasScorableTrustedSource("authenticationAssurance", HcadTrustedSource.BRIDGE_VERIFIED)) {
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

    private boolean hasMaterialBaselineMismatch(TrustedHcadContextProjection projection) {
        return projection.baselineComparison() != null
                && projection.baselineComparison().materialMismatch()
                && projection.hasScorableTrustedSource("baselineComparison", HcadTrustedSource.STORE_DERIVED);
    }

    private String normalize(String value) {
        return value == null ? null : value.trim().toLowerCase(Locale.ROOT);
    }
}
