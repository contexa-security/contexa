package io.contexa.contexacore.hcad.trigger;

import io.contexa.contexacore.autonomous.utils.OfficialVerificationRequestContext;
import io.contexa.contexacore.autonomous.utils.RequestInfoExtractor;
import io.contexa.contexacore.autonomous.utils.RequestInfoExtractor.RequestInfo;
import io.contexa.contexacore.properties.HcadProperties;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.util.StringUtils;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;

public class PendingAnomalyEvidenceCheckService {

    private final HcadProperties hcadProperties;

    public PendingAnomalyEvidenceCheckService(HcadProperties hcadProperties) {
        this.hcadProperties = hcadProperties;
    }

    public PendingAnomalyEvidenceReport evaluate(HttpServletRequest request, PendingAnomalyEligibility eligibility) {
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

        boolean sensitiveSurface = isSensitiveSurface(requestInfo, requestPath);
        int failedLoginAttempts = requestInfo != null && requestInfo.getFailedLoginAttempts() != null
                ? requestInfo.getFailedLoginAttempts()
                : 0;
        int recentRequestCount = requestInfo != null && requestInfo.getRecentRequestCount() != null
                ? requestInfo.getRecentRequestCount()
                : 0;
        Long lastRequestIntervalMs = requestInfo != null ? requestInfo.getLastRequestIntervalMs() : null;
        String previousPath = requestInfo != null ? requestInfo.getPreviousPath() : null;
        boolean impossibleTravel = requestInfo != null && Boolean.TRUE.equals(requestInfo.getImpossibleTravel());
        boolean newDevice = requestInfo != null && Boolean.TRUE.equals(requestInfo.getIsNewDevice());
        boolean authContextInconsistent = isAuthContextInconsistent(requestInfo, sensitiveSurface);

        List<String> anchorSignals = new ArrayList<>();
        List<String> corroboratingSignals = new ArrayList<>();
        Map<String, Object> rawSignals = new LinkedHashMap<>();
        rawSignals.put("userId", eligibility.userId());
        rawSignals.put("contextBindingHash", eligibility.contextBindingHash());
        rawSignals.put("currentAction", "PENDING_ANALYSIS");
        rawSignals.put("requestPath", requestPath);
        rawSignals.put("httpMethod", httpMethod);
        rawSignals.put("clientIp", clientIp);
        rawSignals.put("failedLoginAttempts", failedLoginAttempts);
        rawSignals.put("recentRequestCount", recentRequestCount);
        rawSignals.put("lastRequestIntervalMs", lastRequestIntervalMs);
        rawSignals.put("previousPath", previousPath);
        rawSignals.put("isNewDevice", newDevice);
        rawSignals.put("impossibleTravel", impossibleTravel);
        rawSignals.put("sensitiveSurface", sensitiveSurface);
        rawSignals.put("authMethod", requestInfo != null ? requestInfo.getAuthMethod() : null);
        rawSignals.put("mfaVerified", requestInfo != null ? requestInfo.getMfaVerified() : null);
        rawSignals.put("resourceSensitivity", requestInfo != null ? requestInfo.getResourceSensitivity() : null);

        if (impossibleTravel) {
            anchorSignals.add("IMPOSSIBLE_TRAVEL");
        }
        if (newDevice) {
            anchorSignals.add("NEW_DEVICE");
        }
        if (failedLoginAttempts >= hcadProperties.getPreTrigger().getFailedLoginBurstThreshold()) {
            anchorSignals.add("FAILED_LOGIN_BURST");
        }
        if (authContextInconsistent) {
            anchorSignals.add("AUTH_CONTEXT_INCONSISTENT");
        }

        if (recentRequestCount >= hcadProperties.getPreTrigger().getRequestBurstThreshold()) {
            corroboratingSignals.add("REQUEST_BURST");
        }
        if (lastRequestIntervalMs != null
                && lastRequestIntervalMs > 0
                && lastRequestIntervalMs <= hcadProperties.getPreTrigger().getRapidRequestIntervalMs()) {
            corroboratingSignals.add("RAPID_SEQUENCE");
        }
        if (hasPathJump(previousPath, requestPath)) {
            corroboratingSignals.add("PREVIOUS_PATH_JUMP");
        }
        if (sensitiveSurface) {
            corroboratingSignals.add("SENSITIVE_SURFACE");
        }

        List<String> reasonCodes = new ArrayList<>(anchorSignals);
        for (String signal : corroboratingSignals) {
            if (!reasonCodes.contains(signal)) {
                reasonCodes.add(signal);
            }
        }

        String reasonSummary = buildReasonSummary(anchorSignals, corroboratingSignals, httpMethod, requestPath);
        if (!shouldTrigger(anchorSignals, reasonCodes, requestPath, httpMethod, clientIp, rawSignals)) {
            return PendingAnomalyEvidenceReport.noTrigger(
                    eligibility.userId(),
                    eligibility.contextBindingHash(),
                    eligibility.baseKey(),
                    requestId,
                    sessionId,
                    requestPath,
                    httpMethod,
                    clientIp,
                    anchorSignals,
                    corroboratingSignals,
                    reasonCodes,
                    reasonSummary,
                    rawSignals);
        }

        String riskSignature = PendingAnomalyKeyFactory.buildRiskSignature(httpMethod, requestPath, reasonCodes);
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
                anchorSignals,
                corroboratingSignals,
                reasonCodes,
                reasonSummary,
                riskSignature,
                rawSignals);
    }

    private boolean shouldTrigger(
            List<String> anchorSignals,
            List<String> reasonCodes,
            String requestPath,
            String httpMethod,
            String clientIp,
            Map<String, Object> rawSignals) {
        boolean explanationReady = StringUtils.hasText(requestPath)
                && StringUtils.hasText(httpMethod)
                && StringUtils.hasText(clientIp)
                && !rawSignals.isEmpty();
        if (!explanationReady) {
            return false;
        }
        if (anchorSignals.size() >= 2) {
            return true;
        }
        return anchorSignals.size() == 1 && reasonCodes.size() >= 3;
    }

    private boolean isSensitiveSurface(RequestInfo requestInfo, String requestPath) {
        if (requestInfo != null) {
            String sensitivity = normalize(requestInfo.getResourceSensitivity());
            if ("high".equals(sensitivity) || "critical".equals(sensitivity)) {
                return true;
            }
            if (Boolean.TRUE.equals(requestInfo.getIsSensitiveResource())) {
                return true;
            }
        }

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

    private boolean isAuthContextInconsistent(RequestInfo requestInfo, boolean sensitiveSurface) {
        if (requestInfo == null) {
            return false;
        }
        String authMethod = normalize(requestInfo.getAuthMethod());
        boolean mfaVerified = Boolean.TRUE.equals(requestInfo.getMfaVerified());
        if ("mfa".equals(authMethod) && !mfaVerified) {
            return true;
        }
        return sensitiveSurface && !mfaVerified && (!StringUtils.hasText(authMethod) || "password".equals(authMethod));
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

    private String buildReasonSummary(
            List<String> anchorSignals,
            List<String> corroboratingSignals,
            String httpMethod,
            String requestPath) {
        String anchors = anchorSignals.isEmpty() ? "none" : String.join(", ", anchorSignals);
        String corroborating = corroboratingSignals.isEmpty() ? "none" : String.join(", ", corroboratingSignals);
        return String.format(
                "Pre-protectable anomaly evidence matched anchor signals [%s] and corroborating signals [%s] for %s %s while the current action remained PENDING_ANALYSIS.",
                anchors,
                corroborating,
                httpMethod,
                requestPath);
    }

    private String normalize(String value) {
        return value == null ? null : value.trim().toLowerCase(Locale.ROOT);
    }
}

