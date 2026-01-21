package io.contexa.contexaidentity.security.core.mfa.model;

import io.contexa.contexacommon.enums.AuthType;
import lombok.AccessLevel;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.ToString;
import org.springframework.lang.Nullable;

import java.io.Serializable;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.Objects;

@Getter
@Builder(toBuilder = true)
@ToString
@NoArgsConstructor(access = AccessLevel.PROTECTED, force = true)  
@AllArgsConstructor(access = AccessLevel.PRIVATE)                 
public class MfaDecision implements Serializable {
    
    private static final long serialVersionUID = 1L;

    private final boolean required;

    @Builder.Default
    private final int factorCount = 0;

    @Builder.Default
    private final DecisionType type = DecisionType.NO_MFA_REQUIRED;

    @Nullable
    @Builder.Default
    private final List<AuthType> requiredFactors = Collections.emptyList();

    @Nullable
    @Builder.Default
    private final Map<String, Object> metadata = Collections.emptyMap();

    @Nullable
    private final String reason;

    @Builder.Default
    private final long decisionTime = System.currentTimeMillis();

    public enum DecisionType {
        
        NO_MFA_REQUIRED("MFA not required"),

        STANDARD_MFA("Standard MFA required"),

        STRONG_MFA("Strong MFA required"),

        AI_ADAPTIVE_MFA("AI adaptive MFA"),

        BLOCKED("Access blocked");

        private final String description;
        
        DecisionType(String description) {
            this.description = description;
        }
        
        public String getDescription() {
            return description;
        }
    }

    public static MfaDecision noMfaRequired() {
        return MfaDecision.builder()
            .required(false)
            .factorCount(0)
            .type(DecisionType.NO_MFA_REQUIRED)
            .reason("MFA not required by policy")
            .build();
    }

    public static MfaDecision standardMfa(int factorCount) {
        return MfaDecision.builder()
            .required(true)
            .factorCount(factorCount)
            .type(DecisionType.STANDARD_MFA)
            .reason("Standard MFA policy applied")
            .build();
    }

    public static MfaDecision strongMfa(int factorCount, List<AuthType> requiredFactors) {
        return MfaDecision.builder()
            .required(true)
            .factorCount(Math.max(2, factorCount))
            .type(DecisionType.STRONG_MFA)
            .requiredFactors(requiredFactors != null ? List.copyOf(requiredFactors) : Collections.emptyList())
            .reason("Strong MFA required due to elevated risk")
            .build();
    }

    public static MfaDecision blocked(String reason) {
        return MfaDecision.builder()
            .required(false)
            .factorCount(0)
            .type(DecisionType.BLOCKED)
            .reason(Objects.requireNonNullElse(reason, "Access blocked by security policy"))
            .metadata(Map.of(
                "blocked", true,
                "blockReason", Objects.requireNonNullElse(reason, "Security policy violation")
            ))
            .build();
    }

    public static MfaDecision fromAiAssessment(
            boolean required,
            int factorCount,
            double riskScore,
            Map<String, Object> aiMetadata) {
        
        DecisionType type;
        if (!required) {
            type = DecisionType.NO_MFA_REQUIRED;
        } else if (riskScore > 0.9) {
            type = DecisionType.BLOCKED;
        } else if (riskScore > 0.7) {
            type = DecisionType.STRONG_MFA;
        } else {
            type = DecisionType.AI_ADAPTIVE_MFA;
        }
        
        return MfaDecision.builder()
            .required(required)
            .factorCount(factorCount)
            .type(type)
            .metadata(aiMetadata)
            .reason("AI risk assessment score: " + riskScore)
            .build();
    }

    public boolean isBlocked() {
        return type == DecisionType.BLOCKED;
    }

    public boolean isStrongMfaRequired() {
        return type == DecisionType.STRONG_MFA || factorCount >= 2;
    }

    @SuppressWarnings("unchecked")
    public <T> T getMetadataValue(String key, Class<T> type) {
        if (metadata == null || !metadata.containsKey(key)) {
            return null;
        }
        
        Object value = metadata.get(key);
        if (type.isInstance(value)) {
            return (T) value;
        }
        return null;
    }

    public boolean hasMetadata(String key) {
        return metadata != null && metadata.containsKey(key);
    }
}