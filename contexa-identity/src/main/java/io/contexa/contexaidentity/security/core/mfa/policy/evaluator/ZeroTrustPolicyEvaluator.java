package io.contexa.contexaidentity.security.core.mfa.policy.evaluator;

import io.contexa.contexaidentity.security.core.mfa.context.FactorContext;
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
public class ZeroTrustPolicyEvaluator extends AbstractMfaPolicyEvaluator {

    public ZeroTrustPolicyEvaluator(
            UserRepository userRepository,
            ApplicationContext applicationContext) {
        super(userRepository, applicationContext);
    }

    @Override
    public boolean supports(FactorContext context) {
        return isAvailable() && context != null && context.getAttribute("forceAI") == null;
    }

    @Override
    public int getPriority() {
        return 100;
    }

    @Override
    public String getName() {
        return "ZeroTrustPolicyEvaluator";
    }

    @Override
    protected MfaDecision doEvaluatePolicy(FactorContext context) {
        String action = getZeroTrustAction(context);

        return switch (action.toUpperCase()) {
            case "ALLOW" -> createAllowDecision();
            case "CHALLENGE" -> createChallengeDecision(context);
            case "BLOCK" -> createBlockDecision();
            case "ESCALATE" -> createEscalateDecision();
            default -> createAllowDecision();
        };
    }

    private MfaDecision createAllowDecision() {
        Map<String, Object> metadata = new HashMap<>();
        metadata.put("source", "ZeroTrust");
        metadata.put("action", "ALLOW");

        return MfaDecision.builder()
                .required(false)
                .factorCount(0)
                .type(MfaDecision.DecisionType.NO_MFA_REQUIRED)
                .reason("Zero Trust ALLOW action - no MFA required")
                .metadata(metadata)
                .build();
    }

    private MfaDecision createChallengeDecision(FactorContext context) {
        Map<String, Object> metadata = new HashMap<>();
        metadata.put("source", "ZeroTrust");
        metadata.put("action", "CHALLENGE");

        if (userRepository == null) {
            log.warn("UserRepository is not available for Zero Trust CHALLENGE");
            return MfaDecision.challenged("Zero Trust CHALLENGE - no user repository");
        }

        Optional<Users> userOptional = userRepository
                .findByUsernameWithGroupsRolesAndPermissions(context.getUsername());

        if (userOptional.isEmpty()) {
            log.warn("User not found for Zero Trust CHALLENGE: {}", context.getUsername());
            return MfaDecision.challenged("Zero Trust CHALLENGE - user not found");
        }

        Users user = userOptional.get();

        Set<AuthType> availableFactors = getAvailableFactorsFromDsl(context);
        if (CollectionUtils.isEmpty(availableFactors)) {
            log.warn("No available factors for Zero Trust CHALLENGE: {}", context.getUsername());
            return MfaDecision.challenged("Zero Trust CHALLENGE - no factors configured");
        }

        int factorCount = determineFactorCount(user, context);

        List<AuthType> requiredFactors = determineRequiredFactors(
                user,
                context,
                new ArrayList<>(availableFactors),
                factorCount
        );

        metadata.put("availableFactors", availableFactors.stream()
                .map(AuthType::name)
                .collect(Collectors.toList()));
        metadata.put("requiredFactors", requiredFactors.stream()
                .map(AuthType::name)
                .collect(Collectors.toList()));

        String reason = buildChallengeReason(user, context);

        return MfaDecision.builder()
                .required(true)
                .factorCount(factorCount)
                .type(MfaDecision.DecisionType.CHALLENGED)
                .requiredFactors(requiredFactors)
                .reason(reason)
                .metadata(metadata)
                .build();
    }

    private MfaDecision createBlockDecision() {
        Map<String, Object> metadata = new HashMap<>();
        metadata.put("source", "ZeroTrust");
        metadata.put("action", "BLOCK");
        metadata.put("blocked", true);
        metadata.put("blockReason", "Zero Trust BLOCK action");

        return MfaDecision.builder()
                .required(false)
                .factorCount(0)
                .type(MfaDecision.DecisionType.BLOCKED)
                .reason("Zero Trust BLOCK action - access denied")
                .metadata(metadata)
                .build();
    }

    private MfaDecision createEscalateDecision() {
        Map<String, Object> metadata = new HashMap<>();
        metadata.put("source", "ZeroTrust");
        metadata.put("action", "ESCALATE");
        metadata.put("escalated", true);
        metadata.put("blockReason", "Zero Trust ESCALATE action");

        return MfaDecision.builder()
                .required(false)
                .factorCount(0)
                .type(MfaDecision.DecisionType.ESCALATED)
                .reason("Zero Trust ESCALATE action - access blocked for security review")
                .metadata(metadata)
                .build();
    }

    private String getZeroTrustAction(FactorContext context) {
        Object actionAttribute = context.getAttribute("zeroTrustAction");
        if (actionAttribute != null) {
            return actionAttribute.toString();
        }
        return "ALLOW";
    }

    private String buildChallengeReason(Users user, FactorContext context) {
        StringBuilder reason = new StringBuilder("Zero Trust CHALLENGE action - MFA required");

        List<String> details = new ArrayList<>();

        if (isAdminUser(user)) {
            details.add("Admin role");
        }

        String securityLevel = (String) context.getAttribute("transactionSecurityLevel");
        if ("CRITICAL".equalsIgnoreCase(securityLevel)) {
            details.add("CRITICAL security level");
        }

        if (!details.isEmpty()) {
            reason.append(" (").append(String.join(", ", details)).append(")");
        }

        return reason.toString();
    }
}
