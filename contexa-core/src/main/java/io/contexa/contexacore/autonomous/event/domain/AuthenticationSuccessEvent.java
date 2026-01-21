package io.contexa.contexacore.autonomous.event.domain;

import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import lombok.AllArgsConstructor;
import com.fasterxml.jackson.annotation.JsonInclude;

import java.time.LocalDateTime;
import java.util.Map;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
@JsonInclude(JsonInclude.Include.NON_NULL)
public class AuthenticationSuccessEvent {

    private String eventId;
    private String userId;  
    private String username;
    private String sessionId;
    private LocalDateTime eventTimestamp;

    private String sourceIp;
    private String userAgent;
    private String deviceId;

    private String authenticationType; 
    private boolean mfaCompleted;
    private String mfaMethod;

    private Double trustScore;
    private RiskLevel riskLevel;  
    private Map<String, Object> riskIndicators;
    private boolean anomalyDetected;

    private Map<String, Object> sessionContext;
    private String previousSessionId;
    private LocalDateTime lastLoginTime;

    private Map<String, Object> metadata;

    public RiskLevel calculateRiskLevel() {

        if (riskLevel != null) {
            return riskLevel;
        }

        if (anomalyDetected) {
            return RiskLevel.CRITICAL;
        }

        return RiskLevel.UNKNOWN;
    }

    public enum RiskLevel {
        MINIMAL, LOW, MEDIUM, HIGH, CRITICAL, UNKNOWN
    }
}