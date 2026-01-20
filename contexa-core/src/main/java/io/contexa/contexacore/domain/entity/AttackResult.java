package io.contexa.contexacore.domain.entity;

import com.fasterxml.jackson.annotation.JsonIgnore;
import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.hibernate.annotations.JdbcTypeCode;
import org.hibernate.type.SqlTypes;

import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;


@Entity
@Table(name = "attack_results", indexes = {
    @Index(name = "idx_attack_campaign_id", columnList = "campaign_id"),
    @Index(name = "idx_attack_type", columnList = "attack_type"),
    @Index(name = "idx_attack_execution_time", columnList = "execution_time"),
    @Index(name = "idx_attack_successful", columnList = "attack_successful")
})
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class AttackResult {

    @Id
    @Column(name = "attack_id", length = 50)
    private String attackId;

    @Column(name = "campaign_id", length = 50)
    private String campaignId;

    @Enumerated(EnumType.STRING)
    @Column(name = "attack_type", length = 50)
    private AttackType attackType;

    @Column(name = "attack_name", length = 255)
    private String attackName;

    @Column(name = "execution_time")
    private LocalDateTime executionTime;

    @Column(name = "username", length = 100)
    private String username;

    @Column(name = "description", length = 1000)
    private String description;

    @Column(name = "successful")
    private boolean successful;

    @Column(name = "target_user", length = 100)
    private String targetUser;

    @Column(name = "target_resource", length = 255)
    private String targetResource;

    @Column(name = "detected")
    private boolean detected;

    @Column(name = "detection_time")
    private LocalDateTime detectionTime;

    @Column(name = "blocked")
    private boolean blocked;

    @Column(name = "attack_successful")
    private boolean attackSuccessful;

    @Column(name = "risk_score")
    private Double riskScore;

    @Enumerated(EnumType.STRING)
    @Column(name = "risk_level", length = 20)
    private RiskLevel riskLevel;

    @Column(name = "data_breached")
    private boolean dataBreached;

    @Column(name = "breached_record_count")
    private Integer breachedRecordCount;

    
    @JdbcTypeCode(SqlTypes.JSON)
    @Column(name = "additional_data", columnDefinition = "jsonb")
    @Builder.Default
    private Map<String, Object> additionalData = new HashMap<>();

    
    @Transient
    private AttackType type;  
    @Transient
    private LocalDateTime timestamp;
    @Transient
    private String mitreTechnique;
    @Transient
    private String riskLevelString;
    @Transient
    private Map<String, Object> platformVerification;
    @Transient
    private String attackVector;
    @Transient
    private String sourceIp;
    @Transient
    private Integer attemptCount;
    @Transient
    private Long duration;
    @Transient
    private Long durationMs;
    @Transient
    private Map<String, Object> details;
    @Transient
    private Map<String, Object> attackDetails;
    @Transient
    private Long detectionTimeMs;
    @Transient
    private String detectionMethod;
    @Transient
    @Builder.Default
    private List<String> triggeredPolicies = new ArrayList<>();
    @Transient
    @Builder.Default
    private List<String> soarActions = new ArrayList<>();
    @Transient
    private boolean requiresMfa;
    @Transient
    private boolean sessionTerminated;
    @Transient
    private Double aiConfidenceScore;
    @Transient
    private String aiThreatCategory;
    @Transient
    private String aiRecommendation;
    @Transient
    @Builder.Default
    private Map<String, Double> aiFeatureScores = new HashMap<>();
    @Transient
    private boolean hotPathProcessed;
    @Transient
    private boolean coldPathProcessed;
    @Transient
    private Long hotPathLatencyMs;
    @Transient
    private Long coldPathLatencyMs;
    @Transient
    private String impactAssessment;
    @Transient
    @Builder.Default
    private List<Evidence> evidences = new ArrayList<>();
    @Transient
    @Builder.Default
    private Map<String, Object> attackPayload = new HashMap<>();
    @Transient
    @Builder.Default
    private Map<String, String> httpHeaders = new HashMap<>();
    @Transient
    private String successCriteria;
    @Transient
    private String failureReason;
    @Transient
    private List<String> breachedCustomerIds;
    @Transient
    private Map<String, Object> breachedData;
    @Transient
    private String breachImpact;
    @Transient
    private Double estimatedDamage;
    
    
    public String getRiskLevel() {
        if (riskLevelString != null) return riskLevelString;
        if (riskLevel != null) return riskLevel.name();
        return "UNKNOWN";
    }
    
    public void setRiskLevel(String riskLevel) {
        this.riskLevelString = riskLevel;
        try {
            this.riskLevel = RiskLevel.valueOf(riskLevel);
        } catch (Exception e) {
            
        }
    }
    
    
    @Transient
    private Integer httpStatusCode;
    @Transient
    private Long responseTimeMs;
    @Transient
    private Long dataExfiltratedBytes;
    @Transient
    private Integer privilegeEscalationLevel;

    
    @Transient
    private VerificationStatus verificationStatus;
    @Transient
    private String verificationDetails;
    @Transient
    @Builder.Default
    private List<String> verificationFailures = new ArrayList<>();
    
    
    public enum AttackType {
        
        BRUTE_FORCE("Brute Force Attack"),
        CREDENTIAL_STUFFING("Credential Stuffing"),
        PASSWORD_SPRAY("Password Spray"),
        SESSION_HIJACKING("Session Hijacking"),
        TOKEN_MANIPULATION("Token Manipulation"),
        MFA_BYPASS("MFA Bypass"),
        TOKEN_REPLAY("Token Replay Attack"),
        ACCOUNT_ENUMERATION("Account Enumeration"),

        
        PRIVILEGE_ESCALATION("Privilege Escalation"),
        IDOR("Insecure Direct Object Reference"),
        API_BYPASS("API Bypass Attack"),
        API_AUTHORIZATION_BYPASS("API Authorization Bypass"),
        HORIZONTAL_PRIVILEGE_ESCALATION("Horizontal Privilege Escalation"),
        ROLE_MANIPULATION("Role Manipulation"),

        
        IMPOSSIBLE_TRAVEL("Impossible Travel"),
        ABNORMAL_BEHAVIOR("Abnormal Behavior Pattern"),
        BEHAVIORAL("Behavioral Anomaly"),
        BEHAVIORAL_ANOMALY("Behavioral Anomaly Attack"),
        VELOCITY_ATTACK("High Velocity Attack"),
        SEQUENCE_BREAKING("Workflow Sequence Breaking"),
        DEVICE_TRUST_VIOLATION("Device Trust Violation"),
        NETWORK_ANOMALY("Network Anomaly"),
        TIME_BASED_ANOMALY("Time-based Anomaly"),

        
        API_ABUSE("API Abuse Attack"),
        GRAPHQL_INJECTION("GraphQL Injection Attack"),
        RATE_LIMIT_BYPASS("Rate Limit Bypass Attack"),
        API_KEY_EXPOSURE("API Key Exposure Attack"),

        
        MODEL_POISONING("Model Poisoning Attack"),
        ADVERSARIAL_EVASION("Adversarial Evasion Attack"),
        PROMPT_INJECTION("Prompt Injection Attack"),
        MODEL_EXTRACTION("Model Extraction Attack"),

        
        ACCOUNT_TAKEOVER("Account Takeover"),
        INSIDER_THREAT("Insider Threat"),
        DORMANT_ACCOUNT_ABUSE("Dormant Account Abuse"),
        SERVICE_ACCOUNT_ABUSE("Service Account Abuse"),

        
        UNKNOWN("Unknown Attack Type"),
        INJECTION("Injection Attack"),
        DOS("Denial of Service Attack"),
        AUTHORIZATION_BYPASS("Authorization Bypass Attack"),
        PHISHING("Phishing Attack"),
        DATA_EXFILTRATION("Data Exfiltration Attack");
        
        private final String description;
        
        AttackType(String description) {
            this.description = description;
        }
        
        public String getDescription() {
            return description;
        }
    }
    
    
    public enum RiskLevel {
        LOW(0.0, 0.3),
        MEDIUM(0.3, 0.6),
        HIGH(0.6, 0.85),
        CRITICAL(0.85, 1.0);
        
        private final double minScore;
        private final double maxScore;
        
        RiskLevel(double minScore, double maxScore) {
            this.minScore = minScore;
            this.maxScore = maxScore;
        }
        
        public static RiskLevel fromScore(Double score) {
            if (score == null) return LOW;
            for (RiskLevel level : values()) {
                if (score >= level.minScore && score < level.maxScore) {
                    return level;
                }
            }
            return CRITICAL;
        }
    }
    
    
    public enum VerificationStatus {
        NOT_VERIFIED,
        PARTIALLY_VERIFIED,
        FULLY_VERIFIED,
        VERIFICATION_FAILED
    }
    
    
    @Data
    @Builder
    @NoArgsConstructor
    @AllArgsConstructor
    public static class Evidence {
        private String type; 
        private LocalDateTime timestamp;
        private String source;
        private String content;
        private Map<String, Object> metadata;
    }
    
    
    public double calculateDetectionEffectiveness() {
        if (!detected) {
            return 0.0;
        }
        
        double score = 0.5; 
        
        
        if (detectionTimeMs != null && detectionTimeMs < 1000) {
            score += 0.2;
        } else if (detectionTimeMs != null && detectionTimeMs < 5000) {
            score += 0.1;
        }
        
        
        if (aiConfidenceScore != null && aiConfidenceScore > 0.8) {
            score += 0.2;
        }
        
        
        if (blocked) {
            score += 0.1;
        }
        
        return Math.min(score, 1.0);
    }
    
    
    @JsonIgnore
    public boolean isAttackSuccessful() {
        return attackSuccessful && !blocked && !sessionTerminated;
    }

    
    public String calculateBreachImpact() {
        if (!dataBreached || breachedRecordCount == null) {
            return "No data breach";
        }

        if (breachedRecordCount > 1000) {
            return "CRITICAL - Mass data breach (>1000 records)";
        } else if (breachedRecordCount > 100) {
            return "HIGH - Significant data breach (>100 records)";
        } else if (breachedRecordCount > 10) {
            return "MEDIUM - Moderate data breach (>10 records)";
        } else {
            return "LOW - Limited data breach (<10 records)";
        }
    }

    
    @JsonIgnore
    public boolean isSuccessful() {
        return successful || isAttackSuccessful();
    }

    
    @JsonIgnore
    public boolean isPlatformResponseAdequate() {
        
        if (riskLevel == RiskLevel.CRITICAL || riskLevel == RiskLevel.HIGH) {
            return blocked || sessionTerminated;
        }
        
        
        if (riskLevel == RiskLevel.MEDIUM) {
            return requiresMfa || !triggeredPolicies.isEmpty();
        }
        
        
        return detected;
    }
    
    
    public String getMitreTactic() {
        switch (type) {
            case BRUTE_FORCE:
            case CREDENTIAL_STUFFING:
            case PASSWORD_SPRAY:
                return "TA0006: Credential Access";
            
            case PRIVILEGE_ESCALATION:
            case HORIZONTAL_PRIVILEGE_ESCALATION:
                return "TA0004: Privilege Escalation";
            
            case SESSION_HIJACKING:
            case TOKEN_MANIPULATION:
                return "TA0001: Initial Access";
            
            case IMPOSSIBLE_TRAVEL:
            case ABNORMAL_BEHAVIOR:
                return "TA0005: Defense Evasion";
            
            default:
                return "TA0040: Impact";
        }
    }
    
    
    public String generateSummary() {
        StringBuilder summary = new StringBuilder();
        summary.append(String.format("Attack: %s (%s)\n", attackName, type.getDescription()));
        summary.append(String.format("Target: %s\n", targetUser != null ? targetUser : targetResource));
        summary.append(String.format("Detection: %s (%.2fms)\n", detected ? "YES" : "NO", 
                      detectionTimeMs != null ? detectionTimeMs.doubleValue() : 0.0));
        summary.append(String.format("Risk Level: %s (Score: %.2f)\n", riskLevel, riskScore));
        summary.append(String.format("Platform Response: %s\n", isPlatformResponseAdequate() ? "ADEQUATE" : "INADEQUATE"));
        
        if (!triggeredPolicies.isEmpty()) {
            summary.append("Triggered Policies: ").append(String.join(", ", triggeredPolicies)).append("\n");
        }
        
        if (!soarActions.isEmpty()) {
            summary.append("SOAR Actions: ").append(String.join(", ", soarActions)).append("\n");
        }
        
        return summary.toString();
    }
}