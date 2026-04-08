package io.contexa.contexacore.hcad.trigger;

import io.contexa.contexacommon.enums.ZeroTrustAction;
import io.contexa.contexacore.autonomous.repository.ZeroTrustActionRepository;
import io.contexa.contexacore.autonomous.utils.OfficialVerificationRequestContext;
import io.contexa.contexacore.autonomous.utils.SessionFingerprintUtil;
import io.contexa.contexacore.hcad.promotion.HcadPreProtectablePromotionAssessment;
import io.contexa.contexacore.hcad.promotion.HcadPreProtectablePromotionRequestResolver;
import io.contexa.contexacore.hcad.trigger.store.AnalysisTriggerStateRepository;
import io.contexa.contexacore.properties.HcadProperties;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.security.authentication.AuthenticationTrustResolver;
import org.springframework.security.authentication.AuthenticationTrustResolverImpl;
import org.springframework.security.core.Authentication;
import org.springframework.util.StringUtils;

public class PendingAnomalyEligibilityGate {
    private final ZeroTrustActionRepository actionRepository;
    private final AnalysisTriggerStateRepository analysisTriggerStateRepository;
    private final HcadProperties hcadProperties;
    private final AuthenticationTrustResolver trustResolver = new AuthenticationTrustResolverImpl();

    public PendingAnomalyEligibilityGate(
            ZeroTrustActionRepository actionRepository,
            AnalysisTriggerStateRepository analysisTriggerStateRepository,
            HcadProperties hcadProperties) {
        this.actionRepository = actionRepository;
        this.analysisTriggerStateRepository = analysisTriggerStateRepository;
        this.hcadProperties = hcadProperties;
    }

    public PendingAnomalyEligibility evaluate(HttpServletRequest request, Authentication authentication) {
        if (request == null || !trustResolver.isAuthenticated(authentication) || !hcadProperties.getPreTrigger().isEnabled()) {
            return null;
        }

        String userId = OfficialVerificationRequestContext.resolveUserId(request);
        if (!StringUtils.hasText(userId)) {
            return null;
        }

        HcadPreProtectablePromotionAssessment assessment = HcadPreProtectablePromotionRequestResolver.resolve(request);
        if (assessment.rawSignalSnapshot().isEmpty()) {
            return null;
        }

        String contextBindingHash = SessionFingerprintUtil.generateContextBindingHash(request);
        ZeroTrustAction currentAction = actionRepository.getCurrentAction(userId, contextBindingHash);
        if (currentAction != ZeroTrustAction.PENDING_ANALYSIS) {
            return null;
        }

        String triggerKey = PendingAnomalyKeyFactory.buildTriggerKey(
                userId,
                contextBindingHash,
                request.getMethod(),
                request.getRequestURI(),
                buildStateSignature(assessment));

        if (analysisTriggerStateRepository.isNegativeCached(triggerKey)
                || analysisTriggerStateRepository.isCoolingDown(triggerKey)
                || analysisTriggerStateRepository.isInFlight(triggerKey)) {
            return null;
        }
        return new PendingAnomalyEligibility(userId, contextBindingHash, triggerKey);
    }

    private String buildStateSignature(HcadPreProtectablePromotionAssessment assessment) {
        return String.join("|",
                Integer.toString(bucketize(assessment.score())),
                assessment.band().serializedValue(),
                Boolean.toString(assessment.eligible()),
                String.join(",", assessment.anchorSignals()),
                String.join(",", assessment.reasonCodes()));
    }

    private int bucketize(int score) {
        if (score >= hcadProperties.getPreTrigger().getRedlineScore()) {
            return 3;
        }
        if (score >= hcadProperties.getPreTrigger().getHighRiskScore()) {
            return 2;
        }
        if (score >= hcadProperties.getPreTrigger().getMediumRiskScore()) {
            return 1;
        }
        return 0;
    }
}