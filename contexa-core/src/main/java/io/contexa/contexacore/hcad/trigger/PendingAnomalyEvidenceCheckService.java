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
package io.contexa.contexacore.hcad.trigger;

import io.contexa.contexacore.autonomous.utils.OfficialVerificationRequestContext;
import io.contexa.contexacore.autonomous.utils.RequestInfoExtractor;
import io.contexa.contexacore.autonomous.utils.RequestInfoExtractor.RequestInfo;
import io.contexa.contexacore.hcad.promotion.HcadPreProtectablePromotionAssessment;
import io.contexa.contexacore.hcad.promotion.HcadPreProtectablePromotionRequestResolver;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.util.StringUtils;

import java.util.LinkedHashMap;
import java.util.Map;

public class PendingAnomalyEvidenceCheckService {

    public PendingAnomalyEvidenceCheckService() {
    }

    public PendingAnomalyEvidenceReport evaluate(HttpServletRequest request, PendingAnomalyEligibility eligibility) {
        HcadPreProtectablePromotionAssessment assessment = HcadPreProtectablePromotionRequestResolver.resolve(request);
        RequestInfo requestInfo = RequestInfoExtractor.extract(request, null);
        String normalizedRequestPath = HcadRequestPathUtils.normalizedPath(request);
        String requestPath = StringUtils.hasText(normalizedRequestPath)
                ? normalizedRequestPath
                : (requestInfo != null && requestInfo.getRequestUri() != null
                        ? HcadRequestPathUtils.normalizePathText(requestInfo.getRequestUri())
                        : null);
        String httpMethod = requestInfo != null && requestInfo.getMethod() != null
                ? requestInfo.getMethod()
                : request.getMethod();
        String requestId = requestInfo != null ? requestInfo.getRequestId() : null;
        String sessionId = requestInfo != null ? requestInfo.getSessionId() : OfficialVerificationRequestContext.resolveSessionId(request);
        String clientIp = requestInfo != null ? requestInfo.getClientIp() : request.getRemoteAddr();
        Map<String, Object> rawSnapshot = new LinkedHashMap<>(assessment.rawSignalSnapshot());
        rawSnapshot.put("currentAction", "PENDING_ANALYSIS");
        rawSnapshot.put("contextBindingHash", eligibility.contextBindingHash());

        String reasonSummary = assessment.summary();
        boolean explanationReady = StringUtils.hasText(requestPath)
                && StringUtils.hasText(httpMethod)
                && StringUtils.hasText(clientIp)
                && !rawSnapshot.isEmpty();
        if (!explanationReady || !assessment.eligible()) {
            return PendingAnomalyEvidenceReport.noTrigger(
                    eligibility.userId(),
                    eligibility.contextBindingHash(),
                    eligibility.baseKey(),
                    requestId,
                    sessionId,
                    requestPath,
                    httpMethod,
                    clientIp,
                    assessment.score(),
                    assessment.band().serializedValue(),
                    assessment.eligible(),
                    assessment.evaluationVersion(),
                    assessment.anchorSignals(),
                    assessment.corroboratingSignals(),
                    assessment.reasonCodes(),
                    reasonSummary,
                    rawSnapshot);
        }

        String riskSignature = PendingAnomalyKeyFactory.buildRiskSignature(httpMethod, requestPath, assessment.reasonCodes());
        String triggerStateKey = PendingAnomalyKeyFactory.buildTriggerKey(
                eligibility.userId(),
                eligibility.contextBindingHash(),
                httpMethod,
                requestPath,
                StringUtils.hasText(riskSignature) ? riskSignature : requestId);
        return new PendingAnomalyEvidenceReport(
                true,
                eligibility.userId(),
                eligibility.contextBindingHash(),
                triggerStateKey,
                requestId,
                sessionId,
                requestPath,
                httpMethod,
                clientIp,
                assessment.score(),
                assessment.band().serializedValue(),
                true,
                assessment.evaluationVersion(),
                assessment.anchorSignals(),
                assessment.corroboratingSignals(),
                assessment.reasonCodes(),
                reasonSummary,
                riskSignature,
                rawSnapshot);
    }
}
