package io.contexa.contexacore.autonomous.exception;

import io.contexa.contexacommon.enums.ZeroTrustAction;
import org.springframework.security.authorization.AuthorizationDeniedException;

public class ZeroTrustAccessDeniedException extends AuthorizationDeniedException {

    private static final long serialVersionUID = 1L;

    private final ZeroTrustAction action;

    private final String resourceId;

    private final double riskScore;

    private final String reason;

    private final boolean analysisTimeout;

    public ZeroTrustAccessDeniedException(String action, String resourceId,
                                          double riskScore, String reason) {
        super(formatMessage(action, reason));
        this.action = ZeroTrustAction.fromString(action);
        this.resourceId = resourceId;
        this.riskScore = riskScore;
        this.reason = reason;
        this.analysisTimeout = false;
    }

    public ZeroTrustAccessDeniedException(String action, String resourceId,
                                          double riskScore, String reason,
                                          boolean analysisTimeout) {
        super(formatMessage(action, reason));
        this.action = ZeroTrustAction.fromString(action);
        this.resourceId = resourceId;
        this.riskScore = riskScore;
        this.reason = reason;
        this.analysisTimeout = analysisTimeout;
    }

    public static ZeroTrustAccessDeniedException analysisTimeout(String resourceId, long timeoutMs) {
        return new ZeroTrustAccessDeniedException(
            ZeroTrustAction.PENDING_ANALYSIS.name(),
            resourceId,
            0.5,
            String.format("Security analysis timeout after %dms", timeoutMs),
            true
        );
    }

    public static ZeroTrustAccessDeniedException analysisRequired(String resourceId) {
        return new ZeroTrustAccessDeniedException(
            ZeroTrustAction.PENDING_ANALYSIS.name(),
            resourceId,
            0.5,
            "Security analysis required but not completed"
        );
    }

    public static ZeroTrustAccessDeniedException blocked(String resourceId, double riskScore) {
        return new ZeroTrustAccessDeniedException(
            ZeroTrustAction.BLOCK.name(),
            resourceId,
            riskScore,
            "Access blocked by AI security analysis"
        );
    }

    public static ZeroTrustAccessDeniedException challengeRequired(String resourceId, double riskScore) {
        return new ZeroTrustAccessDeniedException(
            ZeroTrustAction.CHALLENGE.name(),
            resourceId,
            riskScore,
            "Additional authentication required"
        );
    }

    public static ZeroTrustAccessDeniedException pendingReview(String resourceId, double riskScore) {
        return new ZeroTrustAccessDeniedException(
            ZeroTrustAction.ESCALATE.name(),
            resourceId,
            riskScore,
            "Access pending security review"
        );
    }

    private static String formatMessage(String action, String reason) {
        return String.format("Zero Trust: %s - %s", action, reason);
    }

    public int getHttpStatus() {
        if (action == null) {
            return 403;
        }
        if (action == ZeroTrustAction.PENDING_ANALYSIS && analysisTimeout) {
            return 408;
        }
        return action.getHttpStatus();
    }

    public String getErrorCode() {
        return "ZERO_TRUST_" + (action != null ? action.name() : "UNKNOWN");
    }

    public String getAction() {
        return action != null ? action.name() : null;
    }

    public String getResourceId() {
        return resourceId;
    }

    public double getRiskScore() {
        return riskScore;
    }

    public String getReason() {
        return reason;
    }

    public boolean isAnalysisTimeout() {
        return analysisTimeout;
    }
}
