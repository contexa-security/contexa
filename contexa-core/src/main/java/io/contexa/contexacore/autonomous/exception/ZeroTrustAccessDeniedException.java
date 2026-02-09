package io.contexa.contexacore.autonomous.exception;

import org.springframework.security.authorization.AuthorizationDeniedException;

public class ZeroTrustAccessDeniedException extends AuthorizationDeniedException {

    private static final long serialVersionUID = 1L;

    private final String action;

    private final String resourceId;

    private final double riskScore;

    private final String reason;

    private final boolean analysisTimeout;

    public ZeroTrustAccessDeniedException(String action, String resourceId,
                                          double riskScore, String reason) {
        super(formatMessage(action, reason));
        this.action = action;
        this.resourceId = resourceId;
        this.riskScore = riskScore;
        this.reason = reason;
        this.analysisTimeout = false;
    }

    public ZeroTrustAccessDeniedException(String action, String resourceId,
                                          double riskScore, String reason,
                                          boolean analysisTimeout) {
        super(formatMessage(action, reason));
        this.action = action;
        this.resourceId = resourceId;
        this.riskScore = riskScore;
        this.reason = reason;
        this.analysisTimeout = analysisTimeout;
    }

    public static ZeroTrustAccessDeniedException analysisTimeout(String resourceId, long timeoutMs) {
        return new ZeroTrustAccessDeniedException(
            "PENDING_ANALYSIS",
            resourceId,
            0.5,
            String.format("Security analysis timeout after %dms", timeoutMs),
            true
        );
    }

    public static ZeroTrustAccessDeniedException analysisRequired(String resourceId) {
        return new ZeroTrustAccessDeniedException(
            "PENDING_ANALYSIS",
            resourceId,
            0.5,
            "Security analysis required but not completed"
        );
    }

    public static ZeroTrustAccessDeniedException blocked(String resourceId, double riskScore) {
        return new ZeroTrustAccessDeniedException(
            "BLOCK",
            resourceId,
            riskScore,
            "Access blocked by AI security analysis"
        );
    }

    public static ZeroTrustAccessDeniedException challengeRequired(String resourceId, double riskScore) {
        return new ZeroTrustAccessDeniedException(
            "CHALLENGE",
            resourceId,
            riskScore,
            "Additional authentication required"
        );
    }

    public static ZeroTrustAccessDeniedException pendingReview(String resourceId, double riskScore) {
        return new ZeroTrustAccessDeniedException(
            "ESCALATE",
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
        
        return switch (action.toUpperCase()) {
            case "BLOCK" -> 403;           
            case "CHALLENGE" -> 401;       
            case "ESCALATE" -> 423;        
            case "PENDING_ANALYSIS" -> analysisTimeout ? 408 : 503; 
            default -> 403;
        };
    }

    public String getErrorCode() {
        return "ZERO_TRUST_" + (action != null ? action.toUpperCase() : "UNKNOWN");
    }

    public String getAction() {
        return action;
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
