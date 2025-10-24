package io.contexa.contexacommon.entity.behavior;

import jakarta.persistence.*;
import lombok.Getter;
import lombok.Setter;

import java.time.LocalDateTime;
import java.util.List;
import java.util.Map;

@Entity
@Table(name = "behavior_realtime_cache")
@Getter
@Setter
public class BehaviorRealtimeCache {

    @Id
    @Column(name = "user_id")
    private String userId;

    @Column(name = "recent_activities", columnDefinition = "JSON")
    private String recentActivities;

    @Column(name = "last_activity_timestamp")
    private LocalDateTime lastActivityTimestamp;

    @Column(name = "current_session_id")
    private String currentSessionId;

    @Column(name = "session_start_time")
    private LocalDateTime sessionStartTime;

    @Column(name = "session_ip", length = 45)
    private String sessionIp;

    @Column(name = "current_risk_score")
    private Float currentRiskScore = 0.0f;

    @Column(name = "risk_factors", columnDefinition = "JSON")
    private String riskFactors;

    @Column(name = "expires_at")
    private LocalDateTime expiresAt;

    @Transient
    public List<Map<String, Object>> getRecentActivitiesList() {
        try {
            if (recentActivities == null || recentActivities.isEmpty()) {
                return new java.util.ArrayList<>();
            }
            return new com.fasterxml.jackson.databind.ObjectMapper()
                    .readValue(recentActivities,
                            new com.fasterxml.jackson.core.type.TypeReference<List<Map<String, Object>>>() {});
        } catch (Exception e) {
            return new java.util.ArrayList<>();
        }
    }
}
