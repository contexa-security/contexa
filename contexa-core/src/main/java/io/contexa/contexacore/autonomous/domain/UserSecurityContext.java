package io.contexa.contexacore.autonomous.domain;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonTypeInfo;
import com.fasterxml.jackson.databind.annotation.JsonDeserialize;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
@JsonIgnoreProperties(ignoreUnknown = true)
@JsonTypeInfo(use = JsonTypeInfo.Id.CLASS)
public class UserSecurityContext {

    private String userId;

    private String userName;

    private String organizationId;

    @Builder.Default
    private List<SessionContext> activeSessions = new ArrayList<>();

    @Builder.Default
    private Map<String, String> behaviorPatterns = new HashMap<>();

    @Builder.Default
    private Map<String, String> threatIndicators = new HashMap<>();

    @Builder.Default
    private Double currentThreatScore = 0.5;

    @Builder.Default
    private LocalDateTime lastActivity = LocalDateTime.now();

    @Builder.Default
    private Map<String, Integer> failureCounters = new HashMap<>();

    @Builder.Default
    private Map<String, String> accessPatterns = new HashMap<>();

    private String currentIp;

    private String deviceFingerprint;

    @Builder.Default
    private List<PermissionChange> permissionHistory = new ArrayList<>();

    private MfaStatus mfaStatus;

    @Builder.Default
    private LocalDateTime createdAt = LocalDateTime.now();

    @Builder.Default
    private LocalDateTime updatedAt = LocalDateTime.now();

    @Data
    @Builder
    @NoArgsConstructor
    @AllArgsConstructor
    @JsonIgnoreProperties(ignoreUnknown = true)
    @JsonTypeInfo(use = JsonTypeInfo.Id.CLASS)
    public static class SessionContext {
        private String sessionId;
        private String sourceIp;
        private String userAgent;
        private LocalDateTime startTime;
        private LocalDateTime lastAccessTime;
        private boolean active;
    }

    @Data
    @Builder
    @NoArgsConstructor
    @AllArgsConstructor
    @JsonIgnoreProperties(ignoreUnknown = true)
    @JsonTypeInfo(use = JsonTypeInfo.Id.CLASS)
    public static class PermissionChange {
        private LocalDateTime timestamp;
        private String changeType; 
        private String permission;
        private String reason;
        private String approvedBy;
    }

    @Data
    @Builder
    @NoArgsConstructor
    @AllArgsConstructor
    @JsonIgnoreProperties(ignoreUnknown = true)
    @JsonTypeInfo(use = JsonTypeInfo.Id.CLASS)
    public static class MfaStatus {
        private boolean enabled;
        private String method; 
        private LocalDateTime lastVerified;
        private int failedAttempts;
    }

    public void addSession(SessionContext session) {
        if (activeSessions == null) {
            activeSessions = new ArrayList<>();
        }
        
        activeSessions.removeIf(s -> s.getSessionId().equals(session.getSessionId()));
        activeSessions.add(session);
        updateLastActivity();
    }

    public void removeSession(String sessionId) {
        if (activeSessions != null) {
            activeSessions.removeIf(s -> s.getSessionId().equals(sessionId));
        }
        updateLastActivity();
    }

    public boolean hasActiveSession(String sessionId) {
        return activeSessions != null && 
               activeSessions.stream()
                   .anyMatch(s -> s.getSessionId().equals(sessionId) && s.isActive());
    }

    public void addBehaviorPattern(String key, String value) {
        if (behaviorPatterns == null) {
            behaviorPatterns = new HashMap<>();
        }
        behaviorPatterns.put(key, value);
        updateLastActivity();
    }

    public void addThreatIndicator(String key, String value) {
        if (threatIndicators == null) {
            threatIndicators = new HashMap<>();
        }
        threatIndicators.put(key, value);
        updateLastActivity();
    }

    public void incrementFailureCounter(String type) {
        if (failureCounters == null) {
            failureCounters = new HashMap<>();
        }
        failureCounters.merge(type, 1, Integer::sum);
        updateLastActivity();
    }

    public void resetFailureCounter(String type) {
        if (failureCounters != null) {
            failureCounters.remove(type);
        }
    }

    public void updateThreatScore(double score) {
        this.currentThreatScore = Math.max(0.0, Math.min(1.0, score));
        updateLastActivity();
    }

    public double getCurrentTrustScore() {
        return 1.0 - currentThreatScore;
    }

    private void updateLastActivity() {
        this.lastActivity = LocalDateTime.now();
        this.updatedAt = LocalDateTime.now();
    }

    // MFA/session decisions are driven by ZeroTrustAction (CHALLENGE/BLOCK) in the AI-native ZT pipeline.
    // RiskLevel-based conditions removed: updateThreatScore() has no callers, riskLevel is always MEDIUM.
    public boolean requiresMfa() {
        return (mfaStatus != null && !mfaStatus.isEnabled()) ||
               (failureCounters != null && failureCounters.values().stream().anyMatch(c -> c > 3));
    }

    public boolean requiresSessionInvalidation() {
        return failureCounters != null && failureCounters.values().stream().anyMatch(c -> c > 5);
    }
}