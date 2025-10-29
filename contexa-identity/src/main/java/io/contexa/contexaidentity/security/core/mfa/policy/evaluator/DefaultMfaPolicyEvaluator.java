package io.contexa.contexaidentity.security.core.mfa.policy.evaluator;

import io.contexa.contexaidentity.security.core.config.AuthenticationFlowConfig;
import io.contexa.contexaidentity.security.core.mfa.context.FactorContext;
import io.contexa.contexaidentity.security.core.mfa.model.MfaDecision;
import io.contexa.contexaidentity.security.enums.AuthType;
import io.contexa.contexacommon.entity.Users;
import io.contexa.contexacommon.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.ApplicationContext;
import org.springframework.stereotype.Component;
import org.springframework.util.Assert;
import org.springframework.util.CollectionUtils;

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
    private final ApplicationContext applicationContext;
    
    @Override
    public boolean supports(FactorContext context) {
        // 폴백 평가자로서 모든 컨텍스트를 지원합니다.
        // 다른 평가자가 없을 때 사용됩니다.
        return context != null;
    }

    @Override
    public boolean isAvailable() {
        // UserRepository와 ApplicationContext가 정상적으로 주입되었는지 확인
        boolean available = userRepository != null && applicationContext != null;

        if (!available) {
            log.warn("DefaultMfaPolicyEvaluator is not available - missing dependencies");
        }

        return available;
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

        // 필요한 팩터 수 결정
        int requiredFactorCount = determineFactorCount(user, context);

        // DSL 사용 가능한 팩터를 리스트로 변환
        List<AuthType> availableFactorsList = new ArrayList<>(availableFactors);

        // 필수 팩터 결정 (사용자 선호도 반영)
        List<AuthType> requiredFactors = determineRequiredFactors(
            user,
            context,
            availableFactorsList,
            requiredFactorCount
        );

        // 결정 유형 판단 (동적 결정)
        MfaDecision.DecisionType decisionType = determineDecisionType(user, context, requiredFactorCount);

        // 결정 이유 생성
        String reason = buildReason(user, context, decisionType);

        // 메타데이터 생성
        Map<String, Object> metadata = buildMetadata(user, context, availableFactors, requiredFactors);

        // MFA 결정 생성
        MfaDecision decision = MfaDecision.builder()
            .required(true)
            .factorCount(requiredFactorCount)
            .type(decisionType)
            .requiredFactors(requiredFactors)
            .reason(reason)
            .metadata(metadata)
            .build();

        log.info("MFA decision for user {}: type={}, factorCount={}, availableFactors={}, requiredFactors={}",
                username, decisionType, requiredFactorCount, availableFactors, requiredFactors);

        return decision;
    }
    
    /**
     * MFA 필요 여부를 평가합니다.
     *
     * 7가지 평가 기준을 체계적으로 적용합니다:
     * 1. 플로우 타입 (mfa, mfa-stepup, mfa-transactional)
     * 2. 사용자 MFA 활성화 여부 (user.mfaEnabled)
     * 3. 컨텍스트 MFA 필수 플래그
     * 4. 관리자 역할 (ROLE_ADMIN 등)
     * 5. 위험도 기반 평가 (riskScore > 0.7)
     * 6. Step-up 인증 요구
     * 7. 트랜잭션 보안 레벨
     */
    private boolean evaluateMfaRequirement(Users user, FactorContext context) {
        String username = user.getUsername();

        // 1. 플로우 타입 확인
        String flowType = context.getFlowTypeName();
        boolean isMfaFlow = isMfaFlowType(flowType);

        // 2. 사용자 MFA 활성화 여부 체크 (가장 중요!)
        if (!user.isMfaEnabled()) {
            log.debug("MFA disabled for user: {}", username);
            // MFA가 비활성화된 경우, MFA 플로우가 아니면 MFA 불필요
            if (!isMfaFlow) {
                log.info("MFA not required - user MFA disabled and not MFA flow: {}", username);
                return false;
            }
            // MFA 플로우인 경우 MFA 비활성화 사용자도 MFA 필요 (정책상 강제)
            log.debug("MFA required despite disabled flag - MFA flow type: {}", flowType);
        }

        // 3. MFA 플로우 타입 체크
        if (isMfaFlow) {
            log.debug("Flow type {} requires MFA for user: {}", flowType, username);
            return true;
        }

        // 4. 컨텍스트 MFA 필수 플래그
        Boolean mfaRequiredFlag = (Boolean) context.getAttribute("mfaRequired");
        if (Boolean.TRUE.equals(mfaRequiredFlag)) {
            log.debug("MFA required flag is set in context for user: {}", username);
            return true;
        }

        // 5. 관리자 역할 체크
        if (isAdminUser(user)) {
            log.debug("MFA required - user has admin role: {}", username);
            return true;
        }

        // 6. 위험도 기반 평가
        Double riskScore = (Double) context.getAttribute("riskScore");
        if (riskScore != null && riskScore > 0.7) {
            log.warn("MFA required - high risk score {} for user: {}", riskScore, username);
            return true;
        }

        // 7. Step-up 인증 요구
        Boolean stepUpRequired = (Boolean) context.getAttribute("stepUpRequired");
        if (Boolean.TRUE.equals(stepUpRequired)) {
            log.debug("MFA required - step-up authentication requested for user: {}", username);
            return true;
        }

        // 8. 트랜잭션 보안 레벨
        String securityLevel = (String) context.getAttribute("transactionSecurityLevel");
        if ("HIGH".equalsIgnoreCase(securityLevel) || "CRITICAL".equalsIgnoreCase(securityLevel)) {
            log.debug("MFA required - high/critical transaction security level for user: {}", username);
            return true;
        }

        log.debug("MFA not required for user: {} (all checks passed)", username);
        return false;
    }

    /**
     * 필수 MFA 팩터들을 결정합니다.
     * 사용자 선호도를 최우선으로 반영합니다.
     */
    private List<AuthType> determineRequiredFactors(
            Users user,
            FactorContext context,
            List<AuthType> availableFactors,
            int requiredCount) {

        if (CollectionUtils.isEmpty(availableFactors)) {
            return Collections.emptyList();
        }

        // 1. 사용자 선호 팩터 확인
        String preferredFactorStr = user.getPreferredMfaFactor();
        AuthType preferredFactor = null;

        if (preferredFactorStr != null && !preferredFactorStr.isEmpty()) {
            try {
                preferredFactor = AuthType.valueOf(preferredFactorStr.toUpperCase());
                // 선호 팩터가 사용 가능한지 확인
                if (!availableFactors.contains(preferredFactor)) {
                    log.warn("User preferred factor {} not available, ignoring preference for user: {}",
                            preferredFactor, user.getUsername());
                    preferredFactor = null;
                }
            } catch (IllegalArgumentException e) {
                log.warn("Invalid preferred MFA factor '{}' for user: {}", preferredFactorStr, user.getUsername());
            }
        }

        // 2. 우선순위에 따라 팩터 정렬 (선호 팩터 반영)
        List<AuthType> prioritizedFactors = prioritizeFactors(availableFactors, user, context, preferredFactor);

        // 3. 필요한 수만큼 선택
        if (prioritizedFactors.size() <= requiredCount) {
            return prioritizedFactors;
        }

        return prioritizedFactors.subList(0, requiredCount);
    }
    
    /**
     * 팩터를 우선순위에 따라 정렬합니다.
     * 사용자 선호 팩터를 최우선으로 배치합니다.
     */
    private List<AuthType> prioritizeFactors(
            List<AuthType> factors,
            Users user,
            FactorContext context,
            AuthType preferredFactor) {

        // 기본 우선순위 맵 (높을수록 우선)
        Map<AuthType, Integer> basePriorityMap = new HashMap<>();
        basePriorityMap.put(AuthType.PASSKEY, 100);  // 가장 안전하고 편리
        basePriorityMap.put(AuthType.OTT, 90);       // 일회용 토큰
        basePriorityMap.put(AuthType.MFA, 80);       // 일반 MFA
        basePriorityMap.put(AuthType.RECOVERY_CODE, 70);  // 복구 코드

        // 컨텍스트 기반 우선순위 조정
        Map<AuthType, Integer> adjustedPriorityMap = new HashMap<>(basePriorityMap);

        // 위험도가 높으면 PASSKEY 우선순위 증가
        Double riskScore = (Double) context.getAttribute("riskScore");
        if (riskScore != null && riskScore > 0.7) {
            adjustedPriorityMap.put(AuthType.PASSKEY, 110);
        }

        // 관리자는 PASSKEY 우선
        if (isAdminUser(user)) {
            adjustedPriorityMap.put(AuthType.PASSKEY, 105);
        }

        return factors.stream()
            .sorted((f1, f2) -> {
                // 선호 팩터가 있으면 최우선
                if (preferredFactor != null) {
                    if (f1 == preferredFactor) return -1;
                    if (f2 == preferredFactor) return 1;
                }

                // 우선순위 비교
                int priority1 = adjustedPriorityMap.getOrDefault(f1, 0);
                int priority2 = adjustedPriorityMap.getOrDefault(f2, 0);
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
     * DSL에서 사용 가능한 MFA 팩터를 가져옵니다.
     * 순환 참조 문제를 해결하기 위해 ApplicationContext에서 직접 조회합니다.
     */
    private Set<AuthType> getAvailableFactorsFromDsl(FactorContext context) {
        // 1. 컨텍스트에 이미 설정되어 있는지 확인
        Object configObj = context.getAttribute("mfaFlowConfig");
        if (configObj instanceof AuthenticationFlowConfig) {
            Set<AuthType> factors = extractFactorsFromConfig((AuthenticationFlowConfig) configObj);
            if (!factors.isEmpty()) {
                return factors;
            }
        }

        // 2. ApplicationContext에서 직접 조회 (순환 참조 해결!)
        AuthenticationFlowConfig mfaFlowConfig = findMfaFlowConfigFromContext();
        if (mfaFlowConfig != null) {
            Set<AuthType> factors = extractFactorsFromConfig(mfaFlowConfig);
            if (!factors.isEmpty()) {
                // 다음 호출을 위해 컨텍스트에 저장
                context.setAttribute("mfaFlowConfig", mfaFlowConfig);
                log.debug("DSL에서 사용 가능한 팩터 (ApplicationContext 조회): {}", factors);
                return factors;
            }
        }

        log.warn("DSL에 정의된 팩터를 찾을 수 없습니다");
        return Collections.emptySet();
    }

    /**
     * ApplicationContext에서 AuthenticationFlowConfig(MFA)를 찾습니다.
     */
    private AuthenticationFlowConfig findMfaFlowConfigFromContext() {
        try {
            Map<String, AuthenticationFlowConfig> flowConfigs =
                    applicationContext.getBeansOfType(AuthenticationFlowConfig.class);

            for (AuthenticationFlowConfig config : flowConfigs.values()) {
                // MFA 플로우 설정인지 확인 (typeName 사용)
                String typeName = config.getTypeName();
                if (typeName != null && isMfaFlowType(typeName)) {
                    log.debug("Found MFA FlowConfig: {}", typeName);
                    return config;
                }
            }

            log.warn("No MFA AuthenticationFlowConfig found in ApplicationContext");
        } catch (Exception e) {
            log.error("Error finding MFA FlowConfig from ApplicationContext", e);
        }

        return null;
    }

    /**
     * AuthenticationFlowConfig에서 팩터를 추출합니다.
     */
    private Set<AuthType> extractFactorsFromConfig(AuthenticationFlowConfig config) {
        if (config == null) {
            return Collections.emptySet();
        }

        Map<AuthType, ?> factorOptions = config.getRegisteredFactorOptions();
        if (factorOptions == null || factorOptions.isEmpty()) {
            log.debug("No factors registered in flow config");
            return Collections.emptySet();
        }

        return factorOptions.keySet();
    }

    /**
     * 관리자 사용자인지 확인합니다.
     */
    private boolean isAdminUser(Users user) {
        if (user == null) {
            return false;
        }

        List<String> roles = user.getRoleNames();
        if (roles == null || roles.isEmpty()) {
            return false;
        }

        // ROLE_ADMIN, ADMIN, ROLE_SYSTEM_ADMIN, SYSTEM_ADMIN 등 확인
        return roles.stream()
            .anyMatch(role -> {
                if (role == null) {
                    return false;
                }
                String upperRole = role.toUpperCase();
                return upperRole.equals("ROLE_ADMIN") ||
                       upperRole.equals("ADMIN") ||
                       upperRole.equals("ROLE_SYSTEM_ADMIN") ||
                       upperRole.equals("SYSTEM_ADMIN") ||
                       upperRole.equals("ROLE_SUPER_ADMIN") ||
                       upperRole.equals("SUPER_ADMIN");
            });
    }

    /**
     * MFA 플로우 타입인지 확인합니다.
     */
    private boolean isMfaFlowType(String flowType) {
        if (flowType == null || flowType.trim().isEmpty()) {
            return false;
        }

        String normalizedFlowType = flowType.trim().toLowerCase();
        return normalizedFlowType.equals("mfa") ||
               normalizedFlowType.equals("mfa-stepup") ||
               normalizedFlowType.equals("mfa-transactional") ||
               normalizedFlowType.startsWith("mfa-");
    }

    /**
     * 필요한 팩터 수를 결정합니다.
     */
    private int determineFactorCount(Users user, FactorContext context) {
        // 기본적으로 DSL 기반: 한 번에 하나씩 챌린지
        int baseCount = 1;

        // 관리자는 2개 이상
        if (isAdminUser(user)) {
            return Math.max(baseCount, 2);
        }

        // 고위험 사용자는 2개 이상
        Double riskScore = (Double) context.getAttribute("riskScore");
        if (riskScore != null && riskScore > 0.8) {
            return Math.max(baseCount, 2);
        }

        // 중요 트랜잭션은 2개 이상
        String securityLevel = (String) context.getAttribute("transactionSecurityLevel");
        if ("CRITICAL".equalsIgnoreCase(securityLevel)) {
            return Math.max(baseCount, 2);
        }

        return baseCount;
    }

    /**
     * MFA 결정 이유를 생성합니다.
     */
    private String buildReason(Users user, FactorContext context, MfaDecision.DecisionType decisionType) {
        StringBuilder reason = new StringBuilder();

        // 결정 타입 기반 기본 메시지
        switch (decisionType) {
            case STRONG_MFA:
                reason.append("강화된 MFA 인증 필요");
                break;
            case STANDARD_MFA:
                reason.append("표준 MFA 인증 필요");
                break;
            case AI_ADAPTIVE_MFA:
                reason.append("AI 적응형 MFA 인증 필요");
                break;
            default:
                reason.append("MFA 인증 필요");
        }

        // 상세 이유 추가
        List<String> details = new ArrayList<>();

        String flowType = context.getFlowTypeName();
        if (isMfaFlowType(flowType)) {
            details.add("MFA 플로우 타입: " + flowType);
        }

        if (isAdminUser(user)) {
            details.add("관리자 역할");
        }

        Double riskScore = (Double) context.getAttribute("riskScore");
        if (riskScore != null && riskScore > 0.7) {
            details.add(String.format("위험도: %.2f", riskScore));
        }

        if (!details.isEmpty()) {
            reason.append(" (").append(String.join(", ", details)).append(")");
        }

        return reason.toString();
    }

    /**
     * MFA 결정 메타데이터를 생성합니다.
     */
    private Map<String, Object> buildMetadata(Users user, FactorContext context,
                                              Set<AuthType> availableFactors,
                                              List<AuthType> requiredFactors) {
        Map<String, Object> metadata = new HashMap<>();

        // 사용 가능한 팩터
        metadata.put("availableFactors", availableFactors.stream()
                .map(AuthType::name)
                .collect(Collectors.toList()));

        // 필수 팩터
        metadata.put("requiredFactors", requiredFactors.stream()
                .map(AuthType::name)
                .collect(Collectors.toList()));

        // 사용자 선호 팩터
        String preferredFactor = user.getPreferredMfaFactor();
        if (preferredFactor != null && !preferredFactor.isEmpty()) {
            metadata.put("userPreferredFactor", preferredFactor);
        }

        // 위험도
        Double riskScore = (Double) context.getAttribute("riskScore");
        if (riskScore != null) {
            metadata.put("riskScore", riskScore);
        }

        // 관리자 여부
        metadata.put("isAdmin", isAdminUser(user));

        // MFA 활성화 여부
        metadata.put("mfaEnabled", user.isMfaEnabled());

        // 플로우 타입
        String flowType = context.getFlowTypeName();
        if (flowType != null) {
            metadata.put("flowType", flowType);
        }

        return metadata;
    }

    @Override
    public String getName() {
        return "DefaultMfaPolicyEvaluator";
    }
}