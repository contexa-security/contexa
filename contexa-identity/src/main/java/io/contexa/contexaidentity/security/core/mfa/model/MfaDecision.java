package io.contexa.contexaidentity.security.core.mfa.model;

import io.contexa.contexaidentity.security.enums.AuthType;
import lombok.Builder;
import lombok.Getter;
import lombok.ToString;
import org.springframework.lang.Nullable;

import java.io.Serializable;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.Objects;

/**
 * MFA 정책 평가 결과를 나타내는 DTO (Data Transfer Object)
 * 
 * 이 클래스는 MFA 정책 평가 로직의 결과를 캡슐화하여 
 * 정책 제공자(MfaPolicyProvider) 내부에서 데이터를 전달하는 용도로 사용됩니다.
 * 
 * @author AI3Security
 * @since 1.0
 */
@Getter
@Builder(toBuilder = true)
@ToString
public class MfaDecision implements Serializable {
    
    private static final long serialVersionUID = 1L;
    
    /**
     * MFA 인증이 필요한지 여부
     */
    private final boolean required;
    
    /**
     * 필요한 인증 팩터의 개수
     * 0: MFA 불필요
     * 1: 단일 팩터
     * 2+: 다중 팩터
     */
    @Builder.Default
    private final int factorCount = 0;
    
    /**
     * 결정 유형
     */
    @Builder.Default
    private final DecisionType type = DecisionType.NO_MFA_REQUIRED;
    
    /**
     * 필수 인증 팩터 목록
     * null이거나 빈 리스트일 수 있음
     */
    @Nullable
    @Builder.Default
    private final List<AuthType> requiredFactors = Collections.emptyList();
    
    /**
     * 추가 메타데이터
     * AI 평가 결과, 위험 점수, 차단 사유 등을 저장
     */
    @Nullable
    @Builder.Default
    private final Map<String, Object> metadata = Collections.emptyMap();
    
    /**
     * 결정 이유 (감사 및 로깅 목적)
     */
    @Nullable
    private final String reason;
    
    /**
     * 결정 시간 (타임스탬프)
     */
    @Builder.Default
    private final long decisionTime = System.currentTimeMillis();
    
    /**
     * MFA 결정 유형
     */
    public enum DecisionType {
        /**
         * MFA가 필요하지 않음
         */
        NO_MFA_REQUIRED("MFA not required"),
        
        /**
         * 표준 MFA 필요 (일반적으로 1-2개 팩터)
         */
        STANDARD_MFA("Standard MFA required"),
        
        /**
         * 강화된 MFA 필요 (2개 이상 팩터)
         */
        STRONG_MFA("Strong MFA required"),
        
        /**
         * AI 기반 적응형 MFA
         */
        AI_ADAPTIVE_MFA("AI adaptive MFA"),
        
        /**
         * 접근 차단
         */
        BLOCKED("Access blocked"),
        
        /**
         * MFA 구성 필요 (사용자가 MFA를 설정하지 않음)
         */
        MFA_CONFIGURATION_REQUIRED("MFA configuration required");
        
        private final String description;
        
        DecisionType(String description) {
            this.description = description;
        }
        
        public String getDescription() {
            return description;
        }
    }
    
    /**
     * 정적 팩토리 메서드 - MFA 불필요
     */
    public static MfaDecision noMfaRequired() {
        return MfaDecision.builder()
            .required(false)
            .factorCount(0)
            .type(DecisionType.NO_MFA_REQUIRED)
            .reason("MFA not required by policy")
            .build();
    }
    
    /**
     * 정적 팩토리 메서드 - 표준 MFA
     */
    public static MfaDecision standardMfa(int factorCount) {
        return MfaDecision.builder()
            .required(true)
            .factorCount(factorCount)
            .type(DecisionType.STANDARD_MFA)
            .reason("Standard MFA policy applied")
            .build();
    }
    
    /**
     * 정적 팩토리 메서드 - 강화된 MFA
     */
    public static MfaDecision strongMfa(int factorCount, List<AuthType> requiredFactors) {
        return MfaDecision.builder()
            .required(true)
            .factorCount(Math.max(2, factorCount))
            .type(DecisionType.STRONG_MFA)
            .requiredFactors(requiredFactors != null ? List.copyOf(requiredFactors) : Collections.emptyList())
            .reason("Strong MFA required due to elevated risk")
            .build();
    }
    
    /**
     * 정적 팩토리 메서드 - 차단
     */
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
    
    /**
     * 정적 팩토리 메서드 - MFA 구성 필요
     */
    public static MfaDecision configurationRequired() {
        return MfaDecision.builder()
            .required(true)
            .factorCount(0)
            .type(DecisionType.MFA_CONFIGURATION_REQUIRED)
            .reason("User needs to configure MFA")
            .build();
    }
    
    /**
     * AI 결정 생성을 위한 빌더 메서드
     */
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
    
    /**
     * 결정이 차단인지 확인
     */
    public boolean isBlocked() {
        return type == DecisionType.BLOCKED;
    }
    
    /**
     * MFA 구성이 필요한지 확인
     */
    public boolean isConfigurationRequired() {
        return type == DecisionType.MFA_CONFIGURATION_REQUIRED;
    }
    
    /**
     * 강화된 MFA가 필요한지 확인
     */
    public boolean isStrongMfaRequired() {
        return type == DecisionType.STRONG_MFA || factorCount >= 2;
    }
    
    /**
     * 메타데이터에서 특정 값 가져오기
     */
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
    
    /**
     * 메타데이터에 특정 키가 있는지 확인
     */
    public boolean hasMetadata(String key) {
        return metadata != null && metadata.containsKey(key);
    }
}