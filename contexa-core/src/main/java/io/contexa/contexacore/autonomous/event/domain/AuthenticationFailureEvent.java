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
public class AuthenticationFailureEvent {

    private String eventId;
    private String userId;    
    private String username;  
    private String sessionId;
    private LocalDateTime eventTimestamp;

    private String sourceIp;
    private String userAgent;
    private String deviceId;

    private String failureReason;
    private String exceptionClass;
    private String exceptionMessage;
    private int failureCount;  

    private String authenticationType; 
    private String attemptedMethod;

    private Double riskScore;
    private Map<String, Object> attackIndicators;
    private boolean bruteForceDetected;
    private boolean credentialStuffingDetected;

    private Map<String, Object> metadata;

    public AttackType determineAttackType() {
        if (bruteForceDetected) {
            return AttackType.BRUTE_FORCE;
        }
        if (credentialStuffingDetected) {
            return AttackType.CREDENTIAL_STUFFING;
        }
        if (failureCount > 10) {
            return AttackType.SUSTAINED_ATTACK;
        }
        if (failureCount > 5) {
            return AttackType.SUSPICIOUS;
        }
        return AttackType.NORMAL;
    }
    
    public enum AttackType {
        NORMAL, SUSPICIOUS, BRUTE_FORCE, CREDENTIAL_STUFFING, SUSTAINED_ATTACK
    }
}