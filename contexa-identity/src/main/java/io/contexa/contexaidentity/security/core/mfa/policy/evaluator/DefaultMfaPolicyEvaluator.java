package io.contexa.contexaidentity.security.core.mfa.policy.evaluator;

import io.contexa.contexaidentity.security.core.config.AuthenticationFlowConfig;
import io.contexa.contexaidentity.security.core.mfa.context.FactorContext;
import io.contexa.contexaidentity.security.core.mfa.model.MfaDecision;
import io.contexa.contexaidentity.security.enums.AuthType;
import io.contexa.contexacommon.entity.Users;
import io.contexa.contexacommon.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;
import org.springframework.util.Assert;
import org.springframework.util.CollectionUtils;
import org.springframework.util.StringUtils;

import java.util.*;
import java.util.stream.Collectors;

/**
 * 기본 MFA 정책 평가자 구현
 * 
 * 규칙 기반 정책 평가를 수행합니다.
 * 사용자 역할, 등록된 MFA 팩터, 플로우 타입 등을 고려하여 MFA 요구사항을 결정합니다.
 * 
 * @author contexa
 * @since 1.0
 */
@Slf4j
@Component
@RequiredArgsConstructor
public class DefaultMfaPolicyEvaluator implements MfaPolicyEvaluator {
    
    private final UserRepository userRepository;
    
    @Override
    public boolean supports(FactorContext context) {
        return true;
    }
    
    @Override
    public boolean isAvailable() {
        // 항상 사용 가능 (폴백)
        return true;
    }
    
    @Override
    public int getPriority() {
        // 가장 낮은 우선순위 (폴백)
        return -100;
    }
    
    /**
     * MFA 정책을 평가하고 결정을 반환합니다.
     */
    @Override
    public MfaDecision evaluatePolicy(FactorContext context) {
        Assert.notNull(context, "FactorContext cannot be null");
        
        String username = context.getUsername();
        log.debug("Evaluating MFA policy for user: {}", username);
        
        // 사용자 정보 조회
        Optional<Users> userOptional = userRepository.findByUsernameWithGroupsRolesAndPermissions(username);
        if (userOptional.isEmpty()) {
            log.warn("User not found for MFA evaluation: {}", username);
            return MfaDecision.noMfaRequired();
        }
        
        Users user = userOptional.get();
        
        // MFA 필요 여부 평가
        boolean mfaRequired = evaluateMfaRequirement(user, context);
        
        if (!mfaRequired) {
            log.info("MFA not required for user: {}", username);
            return MfaDecision.noMfaRequired();
        }
        
        // DSL에서 사용 가능한 MFA 팩터 확인
        Set<AuthType> availableFactors = getAvailableFactorsFromDsl(context);

        if (CollectionUtils.isEmpty(availableFactors)) {
            log.warn("MFA required but no factors defined in DSL for user: {}", username);
            return MfaDecision.noMfaRequired();
        }

        // 필요한 팩터 수 결정 (DSL 기반: 한 번에 하나씩 챌린지)
        int requiredFactorCount = 1;

        // DSL 사용 가능한 팩터를 리스트로 변환
        List<AuthType> availableFactorsList = new ArrayList<>(availableFactors);

        // 필수 팩터 결정 (DSL 기반)
        List<AuthType> requiredFactors = determineRequiredFactors(
            user,
            context,
            availableFactorsList,
            requiredFactorCount
        );

        // 결정 유형 판단 (항상 STANDARD_MFA)
        MfaDecision.DecisionType decisionType = MfaDecision.DecisionType.STANDARD_MFA;

        // MFA 결정 생성
        MfaDecision decision = MfaDecision.builder()
            .required(true)
            .factorCount(requiredFactorCount)
            .type(decisionType)
            .requiredFactors(requiredFactors)
            .reason("DSL 정의 팩터로 MFA 인증 필요")
            .metadata(Map.of(
                "availableFactors", availableFactors.stream()
                    .map(AuthType::name)
                    .collect(Collectors.toList())
            ))
            .build();

        log.info("MFA decision for user {}: type={}, factorCount={}, availableFactors={}",
                username, decisionType, requiredFactorCount, availableFactors);

        return decision;
    }
    
    /**
     * MFA 필요 여부를 평가합니다.
     */
    private boolean evaluateMfaRequirement(Users user, FactorContext context) {
        // 관리자는 항상 MFA 필요
        if (isAdminUser(user)) {
            log.debug("Admin user {} requires MFA", user.getUsername());
            return true;
        }
        
        // 제거됨: 사용자 팩터 등록 체크 - DSL 기반으로 전환
        
        // 플로우 타입에 따른 MFA 요구
        String flowType = context.getFlowTypeName();
        if ("mfa".equalsIgnoreCase(flowType) || 
            "mfa-stepup".equalsIgnoreCase(flowType) ||
            "mfa-transactional".equalsIgnoreCase(flowType)) {
            log.debug("Flow type {} requires MFA", flowType);
            return true;
        }
        
        // 컨텍스트에 MFA 필수 플래그가 있는 경우
        Boolean mfaRequiredFlag = (Boolean) context.getAttribute("mfaRequired");
        if (Boolean.TRUE.equals(mfaRequiredFlag)) {
            log.debug("MFA required flag is set in context");
            return true;
        }
        
        return false;
    }
    
    /**
     * 필요한 MFA 팩터 수를 결정합니다.
     */
    private int determineRequiredFactorCount(Users user, FactorContext context) {
        String flowType = context.getFlowTypeName();
        
        // 관리자는 최소 2개 팩터
        if (isAdminUser(user)) {
            return Math.max(2, getFlowBasedFactorCount(flowType));
        }
        
        // 플로우 타입별 기본값
        int baseCount = getFlowBasedFactorCount(flowType);

        // 제거됨: 사용자 등록 팩터 수 고려 - DSL 기반으로 전환
        // DSL 설정에 따라 필요한 팩터 수가 결정됨

        return baseCount;
    }
    
    /**
     * 플로우 타입에 따른 기본 팩터 수를 반환합니다.
     */
    private int getFlowBasedFactorCount(String flowType) {
        if (flowType == null) {
            return 1;
        }
        
        return switch (flowType.toLowerCase()) {
            case "mfa" -> 2;
            case "mfa-stepup" -> 1;
            case "mfa-transactional" -> 1;
            case "mfa-strong" -> 3;
            default -> 1;
        };
    }
    
    /**
     * 필수 MFA 팩터들을 결정합니다.
     */
    private List<AuthType> determineRequiredFactors(
            Users user,
            FactorContext context,
            List<AuthType> availableFactors,
            int requiredCount) {

        if (CollectionUtils.isEmpty(availableFactors)) {
            return Collections.emptyList();
        }

        // 우선순위에 따라 팩터 정렬
        List<AuthType> prioritizedFactors = prioritizeFactors(availableFactors, user, context);
        
        // 필요한 수만큼 선택
        if (prioritizedFactors.size() <= requiredCount) {
            return prioritizedFactors;
        }
        
        return prioritizedFactors.subList(0, requiredCount);
    }
    
    /**
     * 팩터를 우선순위에 따라 정렬합니다.
     */
    private List<AuthType> prioritizeFactors(
            List<AuthType> factors,
            Users user,
            FactorContext context) {
        
        // 우선순위 맵 (높을수록 우선)
        Map<AuthType, Integer> priorityMap = new HashMap<>();
        priorityMap.put(AuthType.PASSKEY, 100);  // 가장 안전하고 편리
        priorityMap.put(AuthType.OTT, 90);       // 일회용 토큰
        priorityMap.put(AuthType.MFA, 80);       // 일반 MFA
        priorityMap.put(AuthType.RECOVERY_CODE, 70);  // 복구 코드
        
        return factors.stream()
            .sorted((f1, f2) -> {
                int priority1 = priorityMap.getOrDefault(f1, 0);
                int priority2 = priorityMap.getOrDefault(f2, 0);
                return Integer.compare(priority2, priority1); // 내림차순
            })
            .collect(Collectors.toList());
    }
    
    /**
     * MFA 결정 유형을 판단합니다.
     */
    private MfaDecision.DecisionType determineDecisionType(
            Users user,
            FactorContext context,
            int requiredFactorCount) {
        
        // 관리자 또는 3개 이상 팩터 요구 시 강화된 MFA
        if (isAdminUser(user) || requiredFactorCount >= 3) {
            return MfaDecision.DecisionType.STRONG_MFA;
        }
        
        // 2개 팩터는 표준 MFA
        if (requiredFactorCount == 2) {
            return MfaDecision.DecisionType.STANDARD_MFA;
        }
        
        // 1개 팩터도 표준 MFA로 분류
        return MfaDecision.DecisionType.STANDARD_MFA;
    }
    
    /**
     * 결정 이유를 생성합니다.
     */
    private String buildDecisionReason(
            Users user,
            FactorContext context,
            MfaDecision.DecisionType type) {
        
        StringBuilder reason = new StringBuilder();
        
        if (isAdminUser(user)) {
            reason.append("Admin user requires enhanced security. ");
        }
        
        String flowType = context.getFlowTypeName();
        if (StringUtils.hasText(flowType)) {
            reason.append("Flow type: ").append(flowType).append(". ");
        }
        
        reason.append("Decision: ").append(type.getDescription());
        
        return reason.toString();
    }
    
    /**
     * 결정 메타데이터를 생성합니다.
     */
    private Map<String, Object> buildDecisionMetadata(Users user, FactorContext context) {
        Map<String, Object> metadata = new HashMap<>();
        
        metadata.put("userId", user.getId());
        metadata.put("username", user.getUsername());
        metadata.put("flowType", context.getFlowTypeName());
        metadata.put("evaluationTime", System.currentTimeMillis());
        metadata.put("evaluatorType", "DEFAULT");
        
        if (isAdminUser(user)) {
            metadata.put("userRole", "ADMIN");
        }
        
        return metadata;
    }
    
    /**
     * DSL에서 사용 가능한 MFA 팩터를 가져옵니다.
     */
    private Set<AuthType> getAvailableFactorsFromDsl(FactorContext context) {
        // FactorContext의 attribute에서 AuthenticationFlowConfig 가져오기
        Object configObj = context.getAttribute("mfaFlowConfig");
        if (!(configObj instanceof AuthenticationFlowConfig config)) {
            log.warn("AuthenticationFlowConfig를 찾을 수 없습니다");
            return Collections.emptySet();
        }

        Map<AuthType, ?> factorOptions = config.getRegisteredFactorOptions();
        if (factorOptions.isEmpty()) {
            log.warn("DSL에 정의된 팩터가 없습니다");
            return Collections.emptySet();
        }

        Set<AuthType> factors = factorOptions.keySet();
        log.debug("DSL에서 사용 가능한 팩터: {}", factors);
        return factors;
    }

    private boolean isAdminUser(Users user) {
        return true;
    }

    @Override
    public String getName() {
        return "DefaultMfaPolicyEvaluator";
    }
}