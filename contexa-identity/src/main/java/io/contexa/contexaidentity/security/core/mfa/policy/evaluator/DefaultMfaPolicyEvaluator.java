package io.contexa.contexaidentity.security.core.mfa.policy.evaluator;

import io.contexa.contexaidentity.security.core.config.AuthenticationFlowConfig;
import io.contexa.contexaidentity.security.core.config.PlatformConfig;
import io.contexa.contexaidentity.security.core.mfa.context.FactorContext;
import io.contexa.contexaidentity.security.core.mfa.context.FactorContextAttributes;
import io.contexa.contexaidentity.security.core.mfa.model.MfaDecision;
import io.contexa.contexacommon.enums.AuthType;
import io.contexa.contexacommon.entity.Users;
import io.contexa.contexacommon.repository.UserRepository;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.ApplicationContext;
import org.springframework.util.Assert;
import org.springframework.util.CollectionUtils;

import java.util.*;
import java.util.stream.Collectors;

@Slf4j
public class DefaultMfaPolicyEvaluator implements MfaPolicyEvaluator {

    private final UserRepository userRepository;
    private final ApplicationContext applicationContext;

    public DefaultMfaPolicyEvaluator(
            UserRepository userRepository,
            ApplicationContext applicationContext) {
        this.userRepository = userRepository;
        this.applicationContext = applicationContext;
    }
    
    @Override
    public boolean supports(FactorContext context) {

        return context != null;
    }

    @Override
    public boolean isAvailable() {
        
        boolean available = userRepository != null && applicationContext != null;

        if (!available) {
            log.warn("DefaultMfaPolicyEvaluator is not available - missing dependencies");
        }

        return available;
    }
    
    @Override
    public int getPriority() {
        
        return -100;
    }

    @Override
    public MfaDecision evaluatePolicy(FactorContext context) {
        Assert.notNull(context, "FactorContext cannot be null");
        
        String username = context.getUsername();

        Optional<Users> userOptional = userRepository.findByUsernameWithGroupsRolesAndPermissions(username);
        if (userOptional.isEmpty()) {
            log.warn("User not found for MFA evaluation: {}", username);
            return MfaDecision.noMfaRequired();
        }
        
        Users user = userOptional.get();

        boolean mfaRequired = evaluateMfaRequirement(user, context);
        
        if (!mfaRequired) {
                        return MfaDecision.noMfaRequired();
        }

        Set<AuthType> availableFactors = getAvailableFactorsFromDsl(context);

        if (CollectionUtils.isEmpty(availableFactors)) {
            log.warn("MFA required but no factors defined in DSL for user: {}", username);
            return MfaDecision.noMfaRequired();
        }

        int requiredFactorCount = determineFactorCount(user, context);

        List<AuthType> availableFactorsList = new ArrayList<>(availableFactors);

        List<AuthType> requiredFactors = determineRequiredFactors(
            user,
            context,
            availableFactorsList,
            requiredFactorCount
        );

        MfaDecision.DecisionType decisionType = determineDecisionType(user, context, requiredFactorCount);

        String reason = buildReason(user, context, decisionType);

        Map<String, Object> metadata = buildMetadata(user, context, availableFactors, requiredFactors);

        MfaDecision decision = MfaDecision.builder()
            .required(true)
            .factorCount(requiredFactorCount)
            .type(decisionType)
            .requiredFactors(requiredFactors)
            .reason(reason)
            .metadata(metadata)
            .build();

        return decision;
    }

    private boolean evaluateMfaRequirement(Users user, FactorContext context) {
        String username = user.getUsername();

        String flowType = context.getFlowTypeName();
        boolean isMfaFlow = isMfaFlowType(flowType);

        if (!user.isMfaEnabled()) {
                        
            if (!isMfaFlow) {
                                return false;
            }
            
                    }

        if (isMfaFlow) {
                        return true;
        }

        Boolean mfaRequiredFlag = (Boolean) context.getAttribute("mfaRequired");
        if (Boolean.TRUE.equals(mfaRequiredFlag)) {
                        return true;
        }

        if (isAdminUser(user)) {
                        return true;
        }

        Double riskScore = (Double) context.getAttribute("riskScore");
        if (riskScore != null && riskScore > 0.7) {
            log.warn("MFA required - high risk score {} for user: {}", riskScore, username);
            return true;
        }

        Boolean stepUpRequired = (Boolean) context.getAttribute("stepUpRequired");
        if (Boolean.TRUE.equals(stepUpRequired)) {
                        return true;
        }

        String securityLevel = (String) context.getAttribute("transactionSecurityLevel");
        if ("HIGH".equalsIgnoreCase(securityLevel) || "CRITICAL".equalsIgnoreCase(securityLevel)) {
                        return true;
        }

                return false;
    }

    private List<AuthType> determineRequiredFactors(
            Users user,
            FactorContext context,
            List<AuthType> availableFactors,
            int requiredCount) {

        if (CollectionUtils.isEmpty(availableFactors)) {
            return Collections.emptyList();
        }

        String preferredFactorStr = user.getPreferredMfaFactor();
        AuthType preferredFactor = null;

        if (preferredFactorStr != null && !preferredFactorStr.isEmpty()) {
            try {
                preferredFactor = AuthType.valueOf(preferredFactorStr.toUpperCase());
                
                if (!availableFactors.contains(preferredFactor)) {
                    log.warn("User preferred factor {} not available, ignoring preference for user: {}",
                            preferredFactor, user.getUsername());
                    preferredFactor = null;
                }
            } catch (IllegalArgumentException e) {
                log.warn("Invalid preferred MFA factor '{}' for user: {}", preferredFactorStr, user.getUsername());
            }
        }

        List<AuthType> prioritizedFactors = prioritizeFactors(availableFactors, user, context, preferredFactor);

        if (prioritizedFactors.size() <= requiredCount) {
            return prioritizedFactors;
        }

        return prioritizedFactors.subList(0, requiredCount);
    }

    private List<AuthType> prioritizeFactors(
            List<AuthType> factors,
            Users user,
            FactorContext context,
            AuthType preferredFactor) {

        List<AuthType> result = new ArrayList<>(factors);

        if (preferredFactor != null && result.contains(preferredFactor)) {
            result.remove(preferredFactor);
            result.addFirst(preferredFactor);
        }

        return result;
    }

    private MfaDecision.DecisionType determineDecisionType(
            Users user,
            FactorContext context,
            int requiredFactorCount) {

        if (isAdminUser(user) || requiredFactorCount >= 3) {
            return MfaDecision.DecisionType.STRONG_MFA;
        }

        if (requiredFactorCount == 2) {
            return MfaDecision.DecisionType.STANDARD_MFA;
        }

        return MfaDecision.DecisionType.STANDARD_MFA;
    }

    private Set<AuthType> getAvailableFactorsFromDsl(FactorContext context) {
        
        Set<AuthType> availableFactors = context.getSetAttribute(FactorContextAttributes.Policy.AVAILABLE_FACTORS);
        if (availableFactors != null && !availableFactors.isEmpty()) {
                        return availableFactors;
        }

        AuthenticationFlowConfig mfaFlowConfig = findMfaFlowConfigFromContext();
        if (mfaFlowConfig != null) {
            Set<AuthType> factors = extractFactorsFromConfig(mfaFlowConfig);
            if (!factors.isEmpty()) {
                
                context.setAttribute(FactorContextAttributes.Policy.AVAILABLE_FACTORS,
                                   new LinkedHashSet<>(factors));
                                return factors;
            }
        }

        log.warn("DSL에 정의된 팩터를 찾을 수 없습니다");
        return Collections.emptySet();
    }

    private AuthenticationFlowConfig findMfaFlowConfigFromContext() {
        try {
            
            PlatformConfig platformConfig = applicationContext.getBean(PlatformConfig.class);

            return platformConfig.getFlows().stream()
                    .filter(flow -> {
                        String typeName = flow.getTypeName();
                        return isMfaFlowType(typeName);
                    })
                    .findFirst()
                    .orElseGet(() -> {
                        log.warn("No MFA AuthenticationFlowConfig found in PlatformConfig");
                        return null;
                    });
        } catch (Exception e) {
            log.error("Error finding MFA FlowConfig from PlatformConfig", e);
        }

        return null;
    }

    private Set<AuthType> extractFactorsFromConfig(AuthenticationFlowConfig config) {
        if (config == null) {
            return Collections.emptySet();
        }

        Map<AuthType, ?> factorOptions = config.getRegisteredFactorOptions();
        if (factorOptions.isEmpty()) {
                        return Collections.emptySet();
        }

        return factorOptions.keySet();
    }

    private boolean isAdminUser(Users user) {
        if (user == null) {
            return false;
        }

        List<String> roles = user.getRoleNames();
        if (roles == null || roles.isEmpty()) {
            return false;
        }

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

    private int determineFactorCount(Users user, FactorContext context) {
        
        int baseCount = 1;

        if (isAdminUser(user)) {
            return Math.max(baseCount, 2);
        }

        Double riskScore = (Double) context.getAttribute("riskScore");
        if (riskScore != null && riskScore > 0.8) {
            return Math.max(baseCount, 2);
        }

        String securityLevel = (String) context.getAttribute("transactionSecurityLevel");
        if ("CRITICAL".equalsIgnoreCase(securityLevel)) {
            return Math.max(baseCount, 2);
        }

        return baseCount;
    }

    private String buildReason(Users user, FactorContext context, MfaDecision.DecisionType decisionType) {
        StringBuilder reason = new StringBuilder();

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

    private Map<String, Object> buildMetadata(Users user, FactorContext context,
                                              Set<AuthType> availableFactors,
                                              List<AuthType> requiredFactors) {
        Map<String, Object> metadata = new HashMap<>();

        metadata.put("availableFactors", availableFactors.stream()
                .map(AuthType::name)
                .collect(Collectors.toList()));

        metadata.put("requiredFactors", requiredFactors.stream()
                .map(AuthType::name)
                .collect(Collectors.toList()));

        Double riskScore = (Double) context.getAttribute(FactorContextAttributes.Policy.RISK_SCORE);
        if (riskScore != null) {
            metadata.put(FactorContextAttributes.Policy.RISK_SCORE, riskScore);
        }

        return metadata;
    }

    @Override
    public String getName() {
        return "DefaultMfaPolicyEvaluator";
    }
}