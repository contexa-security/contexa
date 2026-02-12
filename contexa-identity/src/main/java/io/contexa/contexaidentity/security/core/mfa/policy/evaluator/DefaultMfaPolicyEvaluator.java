package io.contexa.contexaidentity.security.core.mfa.policy.evaluator;

import io.contexa.contexacommon.enums.ZeroTrustAction;
import io.contexa.contexacore.autonomous.repository.ZeroTrustActionRedisRepository;
import io.contexa.contexaidentity.security.core.mfa.context.FactorContext;
import io.contexa.contexaidentity.security.core.mfa.context.FactorContextAttributes;
import io.contexa.contexaidentity.security.core.mfa.model.MfaDecision;
import io.contexa.contexaidentity.security.core.mfa.util.ZeroTrustActionMfaMapper;
import io.contexa.contexacommon.enums.AuthType;
import io.contexa.contexacommon.entity.Users;
import io.contexa.contexacommon.repository.UserRepository;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.ApplicationContext;
import org.springframework.lang.Nullable;
import org.springframework.util.CollectionUtils;

import java.util.*;
import java.util.stream.Collectors;

@Slf4j
public class DefaultMfaPolicyEvaluator extends AbstractMfaPolicyEvaluator {

    @Nullable
    private final ZeroTrustActionRedisRepository actionRedisRepository;

    public DefaultMfaPolicyEvaluator(
            UserRepository userRepository,
            ApplicationContext applicationContext,
            @Nullable ZeroTrustActionRedisRepository actionRedisRepository) {
        super(userRepository, applicationContext);
        this.actionRedisRepository = actionRedisRepository;
    }

    @Override
    public int getPriority() {
        return -100;
    }

    @Override
    protected MfaDecision doEvaluatePolicy(FactorContext context) {

        String username = context.getUsername();

        Optional<Users> userOptional = userRepository.findByUsernameWithGroupsRolesAndPermissions(username);
        if (userOptional.isEmpty()) {
            log.error("User not found for MFA evaluation: {}", username);
            return MfaDecision.noMfaRequired();
        }
        Users user = userOptional.get();
        boolean mfaRequired = evaluateMfaRequirement(user, context);

        if (!mfaRequired) {
            return MfaDecision.noMfaRequired();
        }

        Set<AuthType> availableFactors = getAvailableFactorsFromDsl(context);
        if (CollectionUtils.isEmpty(availableFactors)) {
            log.error("MFA required but no factors defined in DSL for user: {}", username);
            return MfaDecision.noMfaRequired();
        }

        int requiredFactorCount = determineFactorCount(user, context);
        MfaDecision.DecisionType decisionType = determineDecisionType(user, context);

        if (decisionType == MfaDecision.DecisionType.BLOCKED) {
            return MfaDecision.blocked(buildReason(user, context, decisionType));
        }
        if (decisionType == MfaDecision.DecisionType.ESCALATED) {
            return MfaDecision.escalated(buildReason(user, context, decisionType));
        }
        if (decisionType == MfaDecision.DecisionType.NO_MFA_REQUIRED) {
            return MfaDecision.noMfaRequired();
        }

        List<AuthType> availableFactorsList = new ArrayList<>(availableFactors);
        List<AuthType> requiredFactors = determineRequiredFactors(
                user,
                context,
                availableFactorsList,
                requiredFactorCount
        );

        String reason = buildReason(user, context, decisionType);
        Map<String, Object> metadata = buildMetadata(context, availableFactors, requiredFactors);

        return MfaDecision.builder()
                .required(true)
                .factorCount(requiredFactorCount)
                .type(decisionType)
                .requiredFactors(requiredFactors)
                .reason(reason)
                .metadata(metadata)
                .build();
    }

    private boolean evaluateMfaRequirement(Users user, FactorContext context) {
        String flowType = context.getFlowTypeName();
        boolean isMfaFlow = isMfaFlowType(flowType);

        if (!user.isMfaEnabled()) {
            if (!isMfaFlow) {
                return false;
            }
        }
        if (isMfaFlow) return true;
        return isAdminUser(user);
    }

    private MfaDecision.DecisionType determineDecisionType(Users user, FactorContext context) {
        String actionStr = (String) context.getAttribute(FactorContextAttributes.Policy.ZERO_TRUST_ACTION);
        ZeroTrustAction action = null;

        if (actionStr != null) {
            action = ZeroTrustAction.fromString(actionStr);
        } else if (actionRedisRepository != null) {
            try {
                action = actionRedisRepository.getActionFromHash(user.getUsername());
            } catch (Exception e) {
                log.error("Failed to read action from Redis for user: {}", user.getUsername(), e);
            }
        }

        if (action != null) {
            return ZeroTrustActionMfaMapper.toDecisionType(action);
        }

        return MfaDecision.DecisionType.CHALLENGED;
    }

    private String buildReason(Users user, FactorContext context, MfaDecision.DecisionType decisionType) {
        StringBuilder reason = new StringBuilder();

        switch (decisionType) {
            case CHALLENGED:
                reason.append("MFA authentication required");
                break;
            case BLOCKED:
                reason.append("Authentication blocked");
                break;
            case ESCALATED:
                reason.append("Authentication escalated - blocked");
                break;
            default:
                reason.append("MFA authentication required");
        }

        List<String> details = new ArrayList<>();

        String flowType = context.getFlowTypeName();
        if (isMfaFlowType(flowType)) {
            details.add("MFA flow type: " + flowType);
        }

        if (isAdminUser(user)) {
            details.add("Admin role");
        }

        if (!details.isEmpty()) {
            reason.append(" (").append(String.join(", ", details)).append(")");
        }

        return reason.toString();
    }

    private Map<String, Object> buildMetadata(FactorContext context,
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
