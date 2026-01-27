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

        CHALLENGED("MFA challenge required"),

        BLOCKED("Access blocked"),

        ESCALATED("Escalated - access blocked");

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

    public static MfaDecision challenged(String reason) {
        return MfaDecision.builder()
            .required(true)
            .factorCount(1)
            .type(DecisionType.CHALLENGED)
            .reason(Objects.requireNonNullElse(reason, "MFA challenge required"))
            .build();
    }

    public static MfaDecision challenged(String reason, List<AuthType> requiredFactors) {
        return MfaDecision.builder()
            .required(true)
            .factorCount(requiredFactors != null ? requiredFactors.size() : 1)
            .type(DecisionType.CHALLENGED)
            .requiredFactors(requiredFactors != null ? List.copyOf(requiredFactors) : Collections.emptyList())
            .reason(Objects.requireNonNullElse(reason, "MFA challenge required"))
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

    public static MfaDecision escalated(String reason) {
        return MfaDecision.builder()
            .required(false)
            .factorCount(0)
            .type(DecisionType.ESCALATED)
            .reason(Objects.requireNonNullElse(reason, "Access escalated - blocked"))
            .metadata(Map.of(
                "escalated", true,
                "blockReason", Objects.requireNonNullElse(reason, "Security escalation")
            ))
            .build();
    }

    public boolean isAllowed() {
        return type == DecisionType.NO_MFA_REQUIRED;
    }

    public boolean isChallenged() {
        return type == DecisionType.CHALLENGED;
    }

    public boolean isBlocked() {
        return type == DecisionType.BLOCKED;
    }

    public boolean isEscalated() {
        return type == DecisionType.ESCALATED;
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