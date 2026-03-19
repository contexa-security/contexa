package io.contexa.contexaidentity.security.core.mfa.policy.evaluator;

import io.contexa.contexaidentity.security.core.config.AuthenticationFlowConfig;
import io.contexa.contexaidentity.security.core.config.PlatformConfig;
import io.contexa.contexaidentity.security.core.mfa.context.FactorContext;
import io.contexa.contexaidentity.security.core.mfa.util.MfaFlowTypeUtils;
import io.contexa.contexaidentity.security.core.mfa.context.FactorContextAttributes;
import io.contexa.contexaidentity.security.core.mfa.model.MfaDecision;
import io.contexa.contexacommon.enums.AuthType;
import io.contexa.contexacommon.entity.Users;
import io.contexa.contexacommon.repository.UserRepository;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.ApplicationContext;
import org.springframework.lang.Nullable;
import org.springframework.util.Assert;
import org.springframework.util.CollectionUtils;

import java.util.*;

@Slf4j
public abstract class AbstractMfaPolicyEvaluator implements MfaPolicyEvaluator {

    public static final Set<String> ADMIN_ROLES = Set.of(
            "ROLE_ADMIN", "ADMIN",
            "ROLE_SYSTEM_ADMIN", "SYSTEM_ADMIN",
            "ROLE_SUPER_ADMIN", "SUPER_ADMIN"
    );

    protected final UserRepository userRepository;
    protected final ApplicationContext applicationContext;

    protected AbstractMfaPolicyEvaluator(
            UserRepository userRepository,
            ApplicationContext applicationContext) {
        this.userRepository = userRepository;
        this.applicationContext = applicationContext;
    }

    @Override
    public final MfaDecision evaluatePolicy(FactorContext context) {
        Assert.notNull(context, "FactorContext cannot be null");
        try {
            MfaDecision decision = doEvaluatePolicy(context);
            return postEvaluate(context, decision);
        } catch (Exception e) {
            log.error("Error evaluating policy in {}: {}", getName(), e.getMessage());
            return handleEvaluationError(context, e);
        }
    }

    protected abstract MfaDecision doEvaluatePolicy(FactorContext context);

    protected MfaDecision postEvaluate(FactorContext context, MfaDecision decision) {
        Map<String, Object> metadata = new HashMap<>();
        if (decision.getMetadata() != null) {
            metadata.putAll(decision.getMetadata());
        }
        metadata.put("evaluator", getName());
        return decision.toBuilder().metadata(metadata).build();
    }

    protected MfaDecision handleEvaluationError(FactorContext context, Exception e) {
        return MfaDecision.challenged("Policy evaluation error - MFA required for safety");
    }

    @Nullable
    protected AuthenticationFlowConfig findMfaFlowConfigFromContext(@Nullable String flowTypeName) {
        if (applicationContext == null) {
            log.error("ApplicationContext is not available in {}", getName());
            return null;
        }

        try {
            PlatformConfig platformConfig = applicationContext.getBean(PlatformConfig.class);

            if (flowTypeName != null) {
                AuthenticationFlowConfig specificFlow = platformConfig.getFlows().stream()
                        .filter(flow -> flow.getTypeName().equalsIgnoreCase(flowTypeName))
                        .findFirst()
                        .orElse(null);
                if (specificFlow != null) {
                    return specificFlow;
                }
            }

            return platformConfig.getFlows().stream()
                    .filter(flow -> isMfaFlowType(flow.getTypeName()))
                    .findFirst()
                    .orElseGet(() -> {
                        log.error("No MFA AuthenticationFlowConfig found in PlatformConfig");
                        return null;
                    });
        } catch (Exception e) {
            log.error("Error finding MFA FlowConfig from PlatformConfig", e);
        }
        return null;
    }

    protected Set<AuthType> extractFactorsFromConfig(@Nullable AuthenticationFlowConfig config) {
        if (config == null) {
            return Collections.emptySet();
        }

        Map<AuthType, ?> factorOptions = config.getRegisteredFactorOptions();
        if (factorOptions.isEmpty()) {
            return Collections.emptySet();
        }
        return factorOptions.keySet();
    }

    protected boolean isMfaFlowType(@Nullable String flowType) {
        if (flowType == null || flowType.trim().isEmpty()) {
            return false;
        }
        return MfaFlowTypeUtils.isMfaFlow(flowType);
    }

    protected boolean isAdminUser(@Nullable Users user) {
        if (user == null) {
            return false;
        }

        List<String> roles = user.getRoleNames();
        if (roles == null || roles.isEmpty()) {
            return false;
        }

        return roles.stream()
                .filter(Objects::nonNull)
                .map(String::toUpperCase)
                .anyMatch(ADMIN_ROLES::contains);
    }

    protected Set<AuthType> getAvailableFactorsFromDsl(FactorContext context) {

        Set<AuthType> availableFactors = context.getSetAttribute(FactorContextAttributes.Policy.AVAILABLE_FACTORS);
        if (availableFactors != null && !availableFactors.isEmpty()) {
            return availableFactors;
        }

        AuthenticationFlowConfig mfaFlowConfig = findMfaFlowConfigFromContext(context.getFlowTypeName());
        if (mfaFlowConfig != null) {
            Set<AuthType> factors = extractFactorsFromConfig(mfaFlowConfig);
            if (!factors.isEmpty()) {

                context.setAttribute(FactorContextAttributes.Policy.AVAILABLE_FACTORS,
                        new LinkedHashSet<>(factors));
                return factors;
            }
        }

        log.error("No factors found in DSL for evaluator: {}", getName());
        return Collections.emptySet();
    }

    protected int determineFactorCount(@Nullable Users user, FactorContext context) {
        int baseCount = getBaseFactorCountFromConfig(context.getFlowTypeName());

        if (user != null && isAdminUser(user)) {
            baseCount = Math.max(baseCount, 2);
        }

        return baseCount;
    }

    private int getBaseFactorCountFromConfig(@Nullable String flowTypeName) {
        AuthenticationFlowConfig mfaFlowConfig = findMfaFlowConfigFromContext(flowTypeName);
        if (mfaFlowConfig == null) {
            return 1;
        }

        // DSL .requiredFactors(n) setting takes precedence
        if (mfaFlowConfig.getRequiredFactorCount() > 0) {
            return mfaFlowConfig.getRequiredFactorCount();
        }

        // Default: all registered factors
        long mfaStepCount = mfaFlowConfig.getStepConfigs().stream()
                .filter(step -> !step.isPrimary())
                .count();
        return mfaStepCount > 0 ? (int) mfaStepCount : 1;
    }

    protected List<AuthType> prioritizeFactors(
            List<AuthType> factors,
            @Nullable AuthType preferredFactor) {

        List<AuthType> result = new ArrayList<>(factors);

        if (preferredFactor != null && result.contains(preferredFactor)) {
            result.remove(preferredFactor);
            result.addFirst(preferredFactor);
        }
        return result;
    }

    protected List<AuthType> determineRequiredFactors(
            @Nullable Users user,
            FactorContext context,
            List<AuthType> availableFactors,
            int requiredCount) {

        if (CollectionUtils.isEmpty(availableFactors)) {
            return Collections.emptyList();
        }
        AuthType preferredFactor = null;

        if (user != null) {
            String preferredFactorStr = user.getPreferredMfaFactor();

            if (preferredFactorStr != null && !preferredFactorStr.isEmpty()) {
                try {
                    preferredFactor = AuthType.valueOf(preferredFactorStr.toUpperCase());

                    if (!availableFactors.contains(preferredFactor)) {
                        log.error("User preferred factor {} not available, ignoring preference for user: {}",
                                preferredFactor, user.getUsername());
                        preferredFactor = null;
                    }
                } catch (IllegalArgumentException e) {
                    log.error("Invalid preferred MFA factor '{}' for user: {}", preferredFactorStr, user.getUsername());
                }
            }
        }

        List<AuthType> prioritizedFactors = prioritizeFactors(availableFactors, preferredFactor);
        if (prioritizedFactors.size() <= requiredCount) {
            return prioritizedFactors;
        }

        return prioritizedFactors.subList(0, requiredCount);
    }

    @Override
    public boolean supports(FactorContext context) {
        return context != null;
    }

    @Override
    public abstract String getName();

    @Override
    public abstract int getPriority();
}
