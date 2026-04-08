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
        String requestPath = requestInfo != null && requestInfo.getRequestUri() != null
                ? requestInfo.getRequestUri()
                : request.getRequestURI();
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
        return new PendingAnomalyEvidenceReport(
                true,
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