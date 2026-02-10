package io.contexa.contexacore.autonomous.utils;

public class ZeroTrustRedisKeys {

    private static final String NAMESPACE = "security";

    public static String userContext(String userId) {
        validateUserId(userId);
        return String.format("%s:user:context:%s", NAMESPACE, userId);
    }

    public static String threatScore(String userId) {
        validateUserId(userId);
        return String.format("threat_score:%s", userId);
    }

    public static String baselineVector(String userId) {
        validateUserId(userId);
        return String.format("%s:baseline:vector:%s", NAMESPACE, userId);
    }

    public static String userAuthorities(String userId) {
        validateUserId(userId);
        return String.format("%s:trust:authorities:%s", NAMESPACE, userId);
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

    public static String anomalyDetected(String userId) {
        validateUserId(userId);
        return String.format("anomaly_detected:%s", userId);
    }

    public static String analysisLock(String userId) {
        validateUserId(userId);
        return String.format("%s:analysis:lock:%s", NAMESPACE, userId);
    }

    public static String analysisValidUntil(String userId) {
        validateUserId(userId);
        return String.format("%s:analysis:validUntil:%s", NAMESPACE, userId);
    }

    public static String hcadAnalysis(String userId) {
        validateUserId(userId);
        return String.format("%s:hcad:analysis:%s", NAMESPACE, userId);
    }

    public static String hcadLastVerifiedAction(String userId) {
        validateUserId(userId);
        return String.format("%s:hcad:lastAction:%s", NAMESPACE, userId);
    }

    public static String userBlocked(String userId) {
        validateUserId(userId);
        return String.format("security:blocked:users:%s", userId);
    }

    public static String userBlockCount(String userId) {
        validateUserId(userId);
        return String.format("%s:user:block:count:%s", NAMESPACE, userId);
    }

    public static String userChallengeCount(String userId) {
        validateUserId(userId);
        return String.format("%s:user:challenge:count:%s", NAMESPACE, userId);
    }

    public static String ipReputation(String ip) {
        if (ip == null || ip.trim().isEmpty()) {
            throw new IllegalArgumentException("IP address cannot be null or empty");
        }
        return String.format("%s:ip:reputation:%s", NAMESPACE, ip);
    }

    public static String attackCount(String sourceIp) {
        if (sourceIp == null || sourceIp.trim().isEmpty()) {
            throw new IllegalArgumentException("Source IP cannot be null or empty");
        }
        return String.format("%s:attacks:count:%s", NAMESPACE, sourceIp);
    }

    public static String assetMetadata(String resource) {
        if (resource == null || resource.trim().isEmpty()) {
            throw new IllegalArgumentException("Resource cannot be null or empty");
        }
        return String.format("%s:asset:metadata:%s", NAMESPACE, resource);
    }

    public static String incident(String incidentId) {
        if (incidentId == null || incidentId.trim().isEmpty()) {
            throw new IllegalArgumentException("Incident ID cannot be null or empty");
        }
        return String.format("%s:incident:%s", NAMESPACE, incidentId);
    }

    public static String soarExecution(String eventId) {
        if (eventId == null || eventId.trim().isEmpty()) {
            throw new IllegalArgumentException("Event ID cannot be null or empty");
        }
        return String.format("%s:soar:execution:%s", NAMESPACE, eventId);
    }

    public static String feedbackLayer(int layer, String eventId) {
        if (layer < 1 || layer > 3) {
            throw new IllegalArgumentException("Layer must be 1, 2, or 3");
        }
        if (eventId == null || eventId.trim().isEmpty()) {
            throw new IllegalArgumentException("Event ID cannot be null or empty");
        }
        return String.format("%s:feedback:layer%d:%s", NAMESPACE, layer, eventId);
    }

    public static String normalPattern(String userId) {
        validateUserId(userId);
        return String.format("%s:user:normal:pattern:%s", NAMESPACE, userId);
    }

    public static String sessionUser(String sessionId) {
        validateSessionId(sessionId);
        return String.format("%s:session:user:%s", NAMESPACE, sessionId);
    }

    public static String sessionToUser(String sessionId) {
        validateSessionId(sessionId);
        return String.format("%s:session:user:%s", NAMESPACE, sessionId);
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

    public static String sessionHijackChannel() {
        return String.format("%s:session:hijack:event", NAMESPACE);
    }

    public static String sessionInvalidationChannel() {
        return String.format("%s:session:invalidation:event", NAMESPACE);
    }

    public static String userThreatChannel() {
        return String.format("%s:user:threat:event", NAMESPACE);
    }

    public static String getUserSessionKey(String userId, String sessionId) {
        validateUserId(userId);
        validateSessionId(sessionId);
        return String.format("%s:user:%s:session:%s", NAMESPACE, userId, sessionId);
    }

    public static String migrateKey(String legacyKey) {
        if (legacyKey.contains(":session:context:")) {

            return legacyKey.replace(":session:context:", ":migration:pending:");
        }
        return legacyKey;
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

    public static String userKeyPattern(String userId) {
        validateUserId(userId);
        return String.format("%s:user:*:%s", NAMESPACE, userId);
    }

    public static String userContextPattern(String userId) {
        validateUserId(userId);
        return String.format("%s:*:*:%s", NAMESPACE, userId);
    }

    public static String legacySessionPattern() {
        return String.format("%s:session:context:*", NAMESPACE);
    }

    public static String eventsCache() {
        return String.format("%s:events:cache", NAMESPACE);
    }

    public static String eventsCounter() {
        return String.format("%s:events:counter", NAMESPACE);
    }

    public static String eventsLimiter() {
        return String.format("%s:events:limiter", NAMESPACE);
    }

    public static String eventsDedup() {
        return String.format("%s:events:dedup", NAMESPACE);
    }

    public static String authDeniedStream() {
        return String.format("%s:auth:denied:stream", NAMESPACE);
    }

    public static String incidentCriticalStream() {
        return String.format("%s:incident:critical:stream", NAMESPACE);
    }

    public static String threatHighStream() {
        return String.format("%s:threat:high:stream", NAMESPACE);
    }

    public static String threatCounter(String threatType) {
        if (threatType == null || threatType.isBlank()) {
            throw new IllegalArgumentException("Threat type cannot be null or empty");
        }
        return String.format("%s:threat:counter:%s", NAMESPACE, threatType);
    }

    public static String authAnomalyStream(String userId) {
        validateUserId(userId);
        return String.format("%s:auth:anomaly:stream:%s", NAMESPACE, userId);
    }

    public static String authAnomalyCounter(String userId) {
        validateUserId(userId);
        return String.format("%s:auth:anomaly:counter:%s", NAMESPACE, userId);
    }

    public static String userAuthStream(String userId) {
        validateUserId(userId);
        return String.format("%s:user:auth:stream:%s", NAMESPACE, userId);
    }

    public static String authFailures(String username) {
        if (username == null || username.isBlank()) {
            throw new IllegalArgumentException("Username cannot be null or empty");
        }
        return String.format("%s:auth:failures:%s", NAMESPACE, username);
    }

    public static String authAttackStream(String sourceIp) {
        if (sourceIp == null || sourceIp.isBlank()) {
            throw new IllegalArgumentException("Source IP cannot be null or empty");
        }
        return String.format("%s:auth:attack:stream:%s", NAMESPACE, sourceIp);
    }

    public static String authAttackCounter(String sourceIp) {
        if (sourceIp == null || sourceIp.isBlank()) {
            throw new IllegalArgumentException("Source IP cannot be null or empty");
        }
        return String.format("%s:auth:attack:counter:%s", NAMESPACE, sourceIp);
    }

    public static String authBlockedIp(String sourceIp) {
        if (sourceIp == null || sourceIp.isBlank()) {
            throw new IllegalArgumentException("Source IP cannot be null or empty");
        }
        return String.format("%s:auth:blocked:ip:%s", NAMESPACE, sourceIp);
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

}