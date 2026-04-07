package io.contexa.contexacore.hcad.trigger;

import io.contexa.contexacommon.enums.ZeroTrustAction;
import io.contexa.contexacore.autonomous.repository.ZeroTrustActionRepository;
import io.contexa.contexacore.autonomous.utils.OfficialVerificationRequestContext;
import io.contexa.contexacore.autonomous.utils.SessionFingerprintUtil;
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
                buildStateSignature(request));
        if (analysisTriggerStateRepository.isNegativeCached(triggerKey)
                || analysisTriggerStateRepository.isCoolingDown(triggerKey)
                || analysisTriggerStateRepository.isInFlight(triggerKey)) {
            return null;
        }
        return new PendingAnomalyEligibility(userId, contextBindingHash, triggerKey);
    }
    private String buildStateSignature(HttpServletRequest request) {
        int failedLoginAttempts = castInt(request.getAttribute("hcad.failed_login_attempts"));
        int recentRequestCount = castInt(request.getAttribute("hcad.recent_request_count"));
        long lastRequestIntervalMs = castLong(request.getAttribute("hcad.last_request_interval_ms"));
        boolean impossibleTravel = castBoolean(request.getAttribute("hcad.impossibleTravel"));
        boolean newDevice = castBoolean(request.getAttribute("hcad.is_new_device"));
        boolean mfaVerified = castBoolean(request.getAttribute("hcad.mfa_verified"));
        boolean sensitiveSurface = isSensitiveSurface(request.getRequestURI(), normalize(request.getAttribute("hcad.resource_sensitivity")));
        String previousPath = normalize(request.getAttribute("hcad.previous_path"));
        String authMethod = normalize(request.getAttribute("hcad.auth_method"));
        String resourceSensitivity = normalize(request.getAttribute("hcad.resource_sensitivity"));
        return String.join("|",
                Boolean.toString(impossibleTravel),
                Boolean.toString(newDevice),
                Integer.toString(bucketize(failedLoginAttempts, Math.max(1, hcadProperties.getPreTrigger().getFailedLoginBurstThreshold()))),
                Integer.toString(bucketize(recentRequestCount, Math.max(1, hcadProperties.getPreTrigger().getRequestBurstThreshold()))),
                lastRequestIntervalMs > 0 && lastRequestIntervalMs <= hcadProperties.getPreTrigger().getRapidRequestIntervalMs() ? "rapid" : "normal",
                previousPath,
                authMethod,
                Boolean.toString(mfaVerified),
                resourceSensitivity,
                Boolean.toString(sensitiveSurface));
    }
    private boolean isSensitiveSurface(String requestPath, String resourceSensitivity) {
        if ("high".equals(resourceSensitivity) || "critical".equals(resourceSensitivity)) {
            return true;
        }
        if (!StringUtils.hasText(requestPath)) {
            return false;
        }
        String normalizedPath = requestPath.toLowerCase();
        for (String indicator : hcadProperties.getPreTrigger().getSensitivePathIndicators()) {
            if (indicator != null && !indicator.isBlank() && normalizedPath.contains(indicator.toLowerCase())) {
                return true;
            }
        }
        return false;
    }
    private String normalize(Object value) {
        if (value == null) {
            return "";
        }
        String text = value.toString().trim();
        return text.toLowerCase();
    }
    private boolean castBoolean(Object value) {
        return value instanceof Boolean bool && bool;
    }
    private int castInt(Object value) {
        return value instanceof Number number ? number.intValue() : 0;
    }
    private long castLong(Object value) {
        return value instanceof Number number ? number.longValue() : 0L;
    }
    private int bucketize(int value, int threshold) {
        if (value <= 0) {
            return 0;
        }
        if (value >= threshold * 2) {
            return 2;
        }
        return value >= threshold ? 1 : 0;
    }
}
