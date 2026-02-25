package io.contexa.contexacore.autonomous.domain;

import io.contexa.contexacore.autonomous.event.domain.AuthorizationDecisionEvent;
import io.contexa.contexacore.domain.entity.ThreatIndicator;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.springframework.ai.document.Document;

import java.time.LocalDateTime;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class SecurityContext {

    private String userId;

    private String organizationId;

    private UserSecurityContext userSecurityContext;

    @Builder.Default
    private List<Document> behaviorPatterns = new ArrayList<>();

    @Builder.Default
    private List<ThreatIndicator> threatIndicators = new ArrayList<>();

    @Builder.Default
    private List<AuthorizationDecisionEvent> protectableAccessHistory = new ArrayList<>();

    @Builder.Default
    private Map<String, Object> metadata = new ConcurrentHashMap<>();

    @Builder.Default
    private LocalDateTime createdAt = LocalDateTime.now();

    @Builder.Default
    private LocalDateTime updatedAt = LocalDateTime.now();

    @Builder.Default
    private Long ttlSeconds = 3600L; 

    @Builder.Default
    private String version = "1.0.0";

    public void addProtectableAccess(AuthorizationDecisionEvent event) {
        if (protectableAccessHistory == null) {
            protectableAccessHistory = new ArrayList<>();
        }
        protectableAccessHistory.add(event);
        updateTimestamp();
    }

    public void addBehaviorPattern(Document pattern) {
        if (behaviorPatterns == null) {
            behaviorPatterns = new ArrayList<>();
        }
        behaviorPatterns.add(pattern);
        updateTimestamp();
    }

    public void addThreatIndicator(ThreatIndicator indicator) {
        if (threatIndicators == null) {
            threatIndicators = new ArrayList<>();
        }
        threatIndicators.add(indicator);
        updateTimestamp();
    }

    public void addMetadata(String key, Object value) {
        if (metadata == null) {
            metadata = new ConcurrentHashMap<>();
        }
        metadata.put(key, value);
        updateTimestamp();
    }

    public Double getCurrentTrustScore() {
        if (userSecurityContext != null) {
            return userSecurityContext.getCurrentTrustScore();
        }
        return 0.5; 
    }

    public Double getTrustScore() {
        return getCurrentTrustScore();
    }

    public Map<String, Integer> getFailureCounters() {
        if (userSecurityContext != null) {
            return userSecurityContext.getFailureCounters();
        }
        return new HashMap<>();
    }

    public Map<String, Object> getThreatIndicators() {
        if (userSecurityContext != null) {
            return new HashMap<>(userSecurityContext.getThreatIndicators());
        }
        return new HashMap<>();
    }

    public Map<String, Object> getAccessPatterns() {
        if (userSecurityContext != null) {
            return new HashMap<>(userSecurityContext.getAccessPatterns());
        }
        return new HashMap<>();
    }

    public boolean requiresMfa() {
        if (userSecurityContext != null) {
            return userSecurityContext.requiresMfa();
        }
        return false;
    }

    public boolean requiresSessionInvalidation() {
        if (userSecurityContext != null) {
            return userSecurityContext.requiresSessionInvalidation();
        }
        return false;
    }

    public long getRecentProtectableAccessCount(int minutes) {
        if (protectableAccessHistory == null || protectableAccessHistory.isEmpty()) {
            return 0;
        }
        
        LocalDateTime threshold = LocalDateTime.now().minusMinutes(minutes);
        return protectableAccessHistory.stream()
            .filter(event -> {
                
                if (event.getTimestamp() != null) {
                    LocalDateTime eventTime = LocalDateTime.ofInstant(
                        event.getTimestamp(), 
                        java.time.ZoneId.systemDefault()
                    );
                    return eventTime.isAfter(threshold);
                }
                return false;
            })
            .count();
    }

    public long getRecentAccessDeniedCount(int minutes) {
        if (protectableAccessHistory == null || protectableAccessHistory.isEmpty()) {
            return 0;
        }
        
        LocalDateTime threshold = LocalDateTime.now().minusMinutes(minutes);
        return protectableAccessHistory.stream()
            .filter(event -> event.getResult() == AuthorizationDecisionEvent.AuthorizationResult.DENIED)
            .filter(event -> {
                if (event.getTimestamp() != null) {
                    LocalDateTime eventTime = LocalDateTime.ofInstant(
                        event.getTimestamp(), 
                        java.time.ZoneId.systemDefault()
                    );
                    return eventTime.isAfter(threshold);
                }
                return false;
            })
            .count();
    }

    public void merge(SecurityContext other) {
        if (other == null) {
            return;
        }

        if (other.getUserSecurityContext() != null) {
            this.userSecurityContext = other.getUserSecurityContext();
        }

        if (other.getBehaviorPatterns() != null) {
            this.behaviorPatterns.addAll(other.getBehaviorPatterns());
        }

        if (other.threatIndicators != null) {
            this.threatIndicators.addAll(other.threatIndicators);
        }
        
        if (other.getProtectableAccessHistory() != null) {
            this.protectableAccessHistory.addAll(other.getProtectableAccessHistory());
        }

        if (other.getMetadata() != null) {
            this.metadata.putAll(other.getMetadata());
        }
        
        updateTimestamp();
    }

    public boolean isValid() {
        
        if (ttlSeconds != null && ttlSeconds > 0) {
            LocalDateTime expiryTime = createdAt.plusSeconds(ttlSeconds);
            if (LocalDateTime.now().isAfter(expiryTime)) {
                return false;
            }
        }

        return userId != null && !userId.isEmpty();
    }

    public void reset() {
        this.behaviorPatterns.clear();
        this.threatIndicators.clear();
        this.protectableAccessHistory.clear();
        this.metadata.clear();
        this.createdAt = LocalDateTime.now();
        this.updatedAt = LocalDateTime.now();
    }

    private void updateTimestamp() {
        this.updatedAt = LocalDateTime.now();
    }

    public Map<String, Object> getSummary() {
        Map<String, Object> summary = new HashMap<>();
        summary.put("userId", userId);
        summary.put("organizationId", organizationId);
        summary.put("trustScore", getCurrentTrustScore());
        summary.put("behaviorPatternCount", behaviorPatterns != null ? behaviorPatterns.size() : 0);
        summary.put("threatIndicatorCount", threatIndicators != null ? threatIndicators.size() : 0);
        summary.put("protectableAccessCount", protectableAccessHistory != null ? protectableAccessHistory.size() : 0);
        summary.put("recentAccessDenied", getRecentAccessDeniedCount(60));
        summary.put("requiresMfa", requiresMfa());
        summary.put("createdAt", createdAt);
        summary.put("updatedAt", updatedAt);
        summary.put("version", version);
        return summary;
    }
}