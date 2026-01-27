package io.contexa.contexaidentity.security.core.mfa.policy.evaluator;

import io.contexa.contexaidentity.security.core.mfa.context.FactorContext;
import io.contexa.contexaidentity.security.core.mfa.context.FactorContextAttributes;
import io.contexa.contexaidentity.security.core.mfa.model.MfaDecision;
import io.contexa.contexacommon.enums.AuthType;
import io.contexa.contexacommon.entity.Users;
import io.contexa.contexacommon.repository.UserRepository;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.ApplicationContext;
import org.springframework.util.CollectionUtils;

import java.util.*;
import java.util.stream.Collectors;

@Slf4j
public class DefaultMfaPolicyEvaluator extends AbstractMfaPolicyEvaluator {

    public DefaultMfaPolicyEvaluator(
            UserRepository userRepository,
            ApplicationContext applicationContext) {
        super(userRepository, applicationContext);
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
    protected MfaDecision doEvaluatePolicy(FactorContext context) {

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

        if (isMfaFlow) {
            return true;
        }

        if (isAdminUser(user)) {
            return true;
        }

        return false;
    }

    private MfaDecision.DecisionType determineDecisionType(
            Users user,
            FactorContext context,
            int requiredFactorCount) {

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
