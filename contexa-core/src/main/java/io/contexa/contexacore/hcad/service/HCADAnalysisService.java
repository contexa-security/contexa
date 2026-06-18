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
package io.contexa.contexacore.hcad.service;

import io.contexa.contexacommon.hcad.domain.HCADAnalysisResult;
import io.contexa.contexacommon.hcad.domain.HCADContext;
import io.contexa.contexacore.hcad.promotion.HcadPreProtectablePromotionAssessment;
import io.contexa.contexacore.hcad.promotion.HcadPreProtectablePromotionAttributes;
import io.contexa.contexacore.hcad.promotion.HcadPreProtectablePromotionScorer;
import io.contexa.contexacore.hcad.store.HCADDataStore;
import io.contexa.contexacore.properties.HcadProperties;
import jakarta.servlet.http.HttpServletRequest;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.Authentication;

import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.Map;

@Slf4j
public class HCADAnalysisService {

    private final HCADContextExtractor contextExtractor;
    private final HcadProperties hcadProperties;
    private final HCADDataStore hcadDataStore;
    private final HcadPreProtectablePromotionScorer preProtectablePromotionScorer;

    public HCADAnalysisService(HCADContextExtractor contextExtractor,
                               HcadProperties hcadProperties,
                               HCADDataStore hcadDataStore,
                               HcadPreProtectablePromotionScorer preProtectablePromotionScorer) {
        this.contextExtractor = contextExtractor;
        this.hcadProperties = hcadProperties;
        this.hcadDataStore = hcadDataStore;
        this.preProtectablePromotionScorer = preProtectablePromotionScorer;
    }

    public HCADAnalysisResult analyze(HttpServletRequest request, Authentication authentication) {
        long startTime = System.currentTimeMillis();

        try {
            HCADContext context = contextExtractor.extractContext(request, authentication);
            applyPreProtectablePromotionAssessment(context);
            String userId = context.getUserId();

            Map<String, Object> llmAnalysis = getLLMAnalysis(userId);
            boolean isStale = (boolean) llmAnalysis.getOrDefault("isStale", false);
            if (isStale) {
                log.warn("[HCADAnalysisService] LLM analysis data for user {} is stale. Evaluation might rely on outdated context.", userId);
            }

            double riskScore = (double) llmAnalysis.getOrDefault("riskScore", 0.0d);
            boolean isAnomaly = (boolean) llmAnalysis.getOrDefault("isAnomaly", false);
            double anomalyScore = riskScore;
            double trustScore = (double) llmAnalysis.getOrDefault("trustScore", 1.0d);
            String threatType = (String) llmAnalysis.getOrDefault("threatType", "NONE");
            String threatEvidence = (String) llmAnalysis.getOrDefault("threatEvidence", "");
            String action = (String) llmAnalysis.get("action");
            double confidence = (double) llmAnalysis.getOrDefault("confidence", Double.NaN);
            long processingTime = System.currentTimeMillis() - startTime;

            return HCADAnalysisResult.builder()
                    .userId(userId)
                    .trustScore(trustScore)
                    .threatType(threatType)
                    .threatEvidence(threatEvidence)
                    .isAnomaly(isAnomaly)
                    .anomalyScore(anomalyScore)
                    .action(action)
                    .confidence(confidence)
                    .processingTimeMs(processingTime)
                    .context(context)
                    .build();

        } catch (Exception e) {
            log.error("[HCADAnalysisService] Analysis failed: request={}", request.getRequestURI(), e);

            HCADContext errorContext = new HCADContext();
            errorContext.setIsNewSession(false);
            errorContext.setNewUser(false);
            errorContext.setIsNewDevice(false);
            errorContext.setRecentRequestCount(0);
            Map<String, Object> errorAttributes = new LinkedHashMap<>();
            errorAttributes.put("analysisFailed", true);
            errorAttributes.put("analysisFailureType", e.getClass().getSimpleName());
            errorContext.setAdditionalAttributes(errorAttributes);

            return HCADAnalysisResult.builder()
                    .userId("error")
                    .trustScore(Double.NaN)
                    .threatType("ANALYSIS_ERROR")
                    .threatEvidence("LLM analysis retrieval failed: " + e.getMessage())
                    .isAnomaly(false)
                    .anomalyScore(Double.NaN)
                    .action(null)
                    .confidence(Double.NaN)
                    .processingTimeMs(System.currentTimeMillis() - startTime)
                    .context(errorContext)
                    .build();
        }
    }

    private void applyPreProtectablePromotionAssessment(HCADContext context) {
        if (context == null) {
            return;
        }
        HcadPreProtectablePromotionAssessment assessment = preProtectablePromotionScorer.score(context);
        Map<String, Object> attributes = context.getAdditionalAttributes();
        if (attributes == null) {
            attributes = new LinkedHashMap<>();
            context.setAdditionalAttributes(attributes);
        }
        attributes.put(HcadPreProtectablePromotionAttributes.CONTEXT_SCORE, assessment.score());
        attributes.put(HcadPreProtectablePromotionAttributes.CONTEXT_BAND, assessment.band().serializedValue());
        attributes.put(HcadPreProtectablePromotionAttributes.CONTEXT_ELIGIBLE, assessment.eligible());
        attributes.put(HcadPreProtectablePromotionAttributes.CONTEXT_ANCHOR_SIGNALS, assessment.anchorSignals());
        attributes.put(HcadPreProtectablePromotionAttributes.CONTEXT_CORROBORATING_SIGNALS, assessment.corroboratingSignals());
        attributes.put(HcadPreProtectablePromotionAttributes.CONTEXT_REASON_CODES, assessment.reasonCodes());
        attributes.put(HcadPreProtectablePromotionAttributes.CONTEXT_SUMMARY, assessment.summary());
        attributes.put(HcadPreProtectablePromotionAttributes.CONTEXT_VERSION, assessment.evaluationVersion());
        attributes.put(HcadPreProtectablePromotionAttributes.CONTEXT_RAW_SIGNALS, assessment.rawSignalSnapshot());
        if (assessment.eligible()) {
            log.info("[HCAD-PRE-TRIGGER-SCORE] userId={}, method={}, path={}, score={}, band={}, eligible={}, anchors={}, corroborators={}, resourceId={}, freshMfaRequired={}, permissionChangeSignals={}",
                    context.getUserId(),
                    context.getHttpMethod(),
                    context.getRequestPath(),
                    assessment.score(),
                    assessment.band().serializedValue(),
                    assessment.eligible(),
                    assessment.anchorSignals(),
                    assessment.corroboratingSignals(),
                    attributes.get("resourceId"),
                    attributes.get("freshMfaRequired"),
                    attributes.get("recentPermissionChanges"));
        }
    }

    private Map<String, Object> getLLMAnalysis(String userId) {
        Map<String, Object> result = new HashMap<>();

        result.put("riskScore", Double.NaN);
        result.put("isAnomaly", false);
        result.put("trustScore", Double.NaN);
        result.put("threatType", "NOT_ANALYZED");
        result.put("threatEvidence", "LLM analysis not yet performed for this user");
        result.put("confidence", Double.NaN);

        try {
            Map<Object, Object> analysis = hcadDataStore.getHcadAnalysis(userId);

            if (!analysis.isEmpty()) {
                boolean isStale = false;
                if (analysis.containsKey("analyzedAt")) {
                    long analyzedAt = parseLong(analysis.get("analyzedAt"));
                    long ageMs = System.currentTimeMillis() - analyzedAt;
                    if (ageMs > hcadProperties.getAnalysis().getMaxAgeMs()) {
                        isStale = true;
                    }
                }
                result.put("isStale", isStale);

                if (analysis.containsKey("riskScore")) {
                    result.put("riskScore", parseDouble(analysis.get("riskScore")));
                }
                if (analysis.containsKey("isAnomaly")) {
                    result.put("isAnomaly", parseBoolean(analysis.get("isAnomaly")));
                }
                if (analysis.containsKey("trustScore")) {
                    result.put("trustScore", parseDouble(analysis.get("trustScore")));
                }
                if (analysis.containsKey("threatType")) {
                    result.put("threatType", analysis.get("threatType").toString());
                }
                if (analysis.containsKey("threatEvidence")) {
                    result.put("threatEvidence", analysis.get("threatEvidence").toString());
                }

                if (analysis.containsKey("action")) {
                    result.put("action", analysis.get("action").toString());
                }
                if (analysis.containsKey("confidence")) {
                    result.put("confidence", parseDouble(analysis.get("confidence")));
                }
            }

        } catch (Exception e) {
            log.error("[HCADAnalysisService] HCAD analysis retrieval failed: userId={}", userId, e);
        }

        return result;
    }

    private double parseDouble(Object value) {
        if (value instanceof Number number) {
            return number.doubleValue();
        }
        if (value instanceof String text) {
            try {
                return Double.parseDouble(text);
            } catch (NumberFormatException e) {
                return 0.0;
            }
        }
        return 0.0;
    }

    private boolean parseBoolean(Object value) {
        if (value instanceof Boolean bool) {
            return bool;
        }
        if (value instanceof String text) {
            return Boolean.parseBoolean(text);
        }
        return false;
    }

    private long parseLong(Object value) {
        if (value instanceof Number number) {
            return number.longValue();
        }
        if (value instanceof String text) {
            try {
                return Long.parseLong(text);
            } catch (NumberFormatException e) {
                return 0L;
            }
        }
        return 0L;
    }

    public void updateBaselineIfNeeded(HCADAnalysisResult result) {
        if (result == null || result.getUserId() == null || result.getUserId().startsWith("anonymous:")) {
            return;
        }
        log.debug("[HCADAnalysisService] updateBaselineIfNeeded called for user={}. (Baseline learning integration stub)", result.getUserId());
    }
}
