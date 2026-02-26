package io.contexa.contexacore.autonomous.utils;

public class ZeroTrustRedisKeys {

    private static final String NAMESPACE = "security";

    public static String threatScore(String userId) {
        validateUserId(userId);
        return String.format("threat_score:%s", userId);
    }

    public static String userSessions(String userId) {
        validateUserId(userId);
        return String.format("%s:user:sessions:%s", NAMESPACE, userId);
    }

    public static String userDevices(String userId) {
        validateUserId(userId);
        return String.format("%s:user:devices:%s", NAMESPACE, userId);
    }

    public static String userRegistered(String userId) {
        validateUserId(userId);
        return String.format("%s:user:registered:%s", NAMESPACE, userId);
    }

    public static String hcadAnalysis(String userId) {
        validateUserId(userId);
        return String.format("%s:hcad:analysis:%s", NAMESPACE, userId);
    }

    public static String hcadLastVerifiedAction(String userId) {
        validateUserId(userId);
        return String.format("%s:hcad:lastAction:%s", NAMESPACE, userId);
    }

    public static String hcadLastVerifiedActionContext(String userId) {
        validateUserId(userId);
        return String.format("%s:hcad:lastActionContext:%s", NAMESPACE, userId);
    }

    public static String userBlocked(String userId) {
        validateUserId(userId);
        return String.format("security:blocked:users:%s", userId);
    }

    public static String blockMfaPending(String userId) {
        validateUserId(userId);
        return String.format("%s:block:mfa:pending:%s", NAMESPACE, userId);
    }

    public static String blockMfaVerified(String userId) {
        validateUserId(userId);
        return String.format("%s:block:mfa:verified:%s", NAMESPACE, userId);
    }

    public static String soarExecution(String eventId) {
        if (eventId == null || eventId.trim().isEmpty()) {
            throw new IllegalArgumentException("Event ID cannot be null or empty");
        }
        return String.format("%s:soar:execution:%s", NAMESPACE, eventId);
    }

    public static String sessionMetadata(String sessionId) {
        validateSessionId(sessionId);
        return String.format("%s:session:meta:%s", NAMESPACE, sessionId);
    }

    public static String invalidSession(String sessionId) {
        validateSessionId(sessionId);
        return String.format("%s:session:invalid:%s", NAMESPACE, sessionId);
    }

    public static String sessionActions(String sessionId) {
        validateSessionId(sessionId);
        return String.format("%s:session:actions:%s", NAMESPACE, sessionId);
    }

    public static String sessionRisk(String sessionId) {
        validateSessionId(sessionId);
        return String.format("%s:session:risk:%s", NAMESPACE, sessionId);
    }

    public static String approvalWorkflow(Long proposalId) {
        if (proposalId == null) {
            throw new IllegalArgumentException("Proposal ID cannot be null");
        }
        return String.format("%s:governance:approval:workflow:%d", NAMESPACE, proposalId);
    }

    public static String approvalWorkflowIndex() {
        return String.format("%s:governance:approval:index", NAMESPACE);
    }

    public static String approvalRequest(String requestId) {
        if (requestId == null || requestId.isBlank()) {
            throw new IllegalArgumentException("Request ID cannot be null or empty");
        }
        return String.format("%s:governance:approval:request:%s", NAMESPACE, requestId);
    }

    public static String eventProcessed(String eventId) {
        if (eventId == null || eventId.isBlank()) {
            throw new IllegalArgumentException("Event ID cannot be null or empty");
        }
        return String.format("%s:processed:%s", NAMESPACE, eventId);
    }

    private static void validateUserId(String userId) {
        if (userId == null || userId.trim().isEmpty()) {
            throw new IllegalArgumentException("UserId is required for Zero Trust architecture");
        }
    }

    private static void validateSessionId(String sessionId) {
        if (sessionId == null || sessionId.trim().isEmpty()) {
            throw new IllegalArgumentException("SessionId cannot be null or empty");
        }
    }
}
