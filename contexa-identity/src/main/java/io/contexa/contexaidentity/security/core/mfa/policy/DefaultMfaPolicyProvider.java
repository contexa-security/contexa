package io.contexa.contexaidentity.security.core.mfa.policy;

import io.contexa.contexaidentity.security.core.config.AuthenticationFlowConfig;
import io.contexa.contexaidentity.security.core.config.AuthenticationStepConfig;
import io.contexa.contexaidentity.security.core.config.PlatformConfig;
import io.contexa.contexaidentity.security.core.mfa.context.FactorContext;
import io.contexa.contexaidentity.security.core.mfa.model.MfaDecision;
import io.contexa.contexaidentity.security.core.mfa.policy.evaluator.AbstractMfaPolicyEvaluator;
import io.contexa.contexaidentity.security.core.mfa.policy.evaluator.MfaPolicyEvaluator;
import io.contexa.contexacommon.enums.AuthType;
import io.contexa.contexaidentity.security.core.mfa.util.MfaFlowTypeUtils;
import io.contexa.contexacommon.properties.AuthContextProperties;
import io.contexa.contexacommon.entity.Users;
import io.contexa.contexacommon.repository.UserRepository;
import jakarta.annotation.PostConstruct;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.ApplicationContext;
import org.springframework.lang.Nullable;
import org.springframework.util.Assert;
import org.springframework.util.CollectionUtils;

import java.util.*;
import java.util.stream.Collectors;

@Slf4j
public class DefaultMfaPolicyProvider implements MfaPolicyProvider {

    protected final UserRepository userRepository;
    protected final ApplicationContext applicationContext;
    protected final AuthContextProperties properties;
    protected final MfaPolicyEvaluator policyEvaluator;
    protected final PlatformConfig platformConfig;
    private final Map<String, AuthenticationFlowConfig> cachedMfaFlowConfigs = new java.util.concurrent.ConcurrentHashMap<>();

    public DefaultMfaPolicyProvider(
            UserRepository userRepository,
            ApplicationContext applicationContext,
            AuthContextProperties properties,
            MfaPolicyEvaluator policyEvaluator,
            PlatformConfig platformConfig) {
        this.userRepository = userRepository;
        this.applicationContext = applicationContext;
        this.properties = properties;
        this.policyEvaluator = policyEvaluator;
        this.platformConfig = platformConfig;
    }

    @PostConstruct
    public void initializeMfaFlowConfig() {
        try {
            if (platformConfig != null) {
                platformConfig.getFlows().stream()
                        .filter(flow -> MfaFlowTypeUtils.isMfaFlow(flow.getTypeName()))
                        .forEach(flow -> cachedMfaFlowConfigs.put(
                                flow.getTypeName().toLowerCase(), flow));

                if (cachedMfaFlowConfigs.isEmpty()) {
                    log.error("No MFA flow configuration found during initialization");
                }
            }
        } catch (Exception e) {
            log.error("Error initializing MFA flow configuration", e);
        }
    }

    @Override
    public MfaDecision evaluateInitialMfaRequirement(FactorContext ctx) {
        Assert.notNull(ctx, "FactorContext cannot be null.");
        return evaluatePolicy(ctx);
    }

    protected MfaDecision evaluatePolicy(FactorContext ctx) {
        return policyEvaluator.evaluatePolicy(ctx);
    }

    @Override
    public boolean isFactorAvailableForUser(String username, AuthType factorType, FactorContext ctx) {
        Assert.hasText(username, "Username cannot be empty.");
        Assert.notNull(factorType, "FactorType cannot be null.");

        if (ctx != null) {
            Set<AuthType> availableFactors = ctx.getAvailableFactors();
            if (availableFactors != null && !availableFactors.isEmpty()) {
                return availableFactors.contains(factorType);
            }
        }

        String flowType = ctx != null ? ctx.getFlowTypeName() : null;
        AuthenticationFlowConfig mfaFlowConfig = findMfaFlowConfig(flowType);
        if (mfaFlowConfig == null) {
            log.error("MFA flow config not found. Factor {} not available for user: {}", factorType, username);
            return false;
        }

        Map<AuthType, ?> factorOptions = mfaFlowConfig.getRegisteredFactorOptions();
        return factorOptions.containsKey(factorType);
    }

    @Override
    public long getRequiredFactorCount(String userId, String flowType) {
        AuthenticationFlowConfig mfaFlowConfig = findMfaFlowConfig(flowType);
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
        return mfaStepCount > 0 ? mfaStepCount : 1;
    }

    private Optional<AuthenticationStepConfig> findNextStepConfig(
            AuthenticationFlowConfig flowConfig, AuthType factorType, FactorContext ctx) {
        return flowConfig.getStepConfigs().stream()
                .filter(step -> factorType.name().equalsIgnoreCase(step.getType()) &&
                        !ctx.isFactorCompleted(step.getStepId()))
                .min(Comparator.comparingInt(AuthenticationStepConfig::getOrder));
    }

    @Nullable
    private AuthType determineNextFactorInternal(List<AuthType> availableFactors,
                                                 List<AuthenticationStepConfig> completedFactorSteps,
                                                 List<AuthenticationStepConfig> flowSteps) {
        if (CollectionUtils.isEmpty(availableFactors) || CollectionUtils.isEmpty(flowSteps)) {
            return null;
        }

        Set<String> completedStepIds = completedFactorSteps.stream()
                .map(AuthenticationStepConfig::getStepId)
                .collect(Collectors.toSet());

        Set<String> availableTypeNames = availableFactors.stream()
                .map(AuthType::name)
                .collect(Collectors.toSet());

        // Find next uncompleted step by order (not by factor type iteration)
        return flowSteps.stream()
                .filter(step -> !step.isPrimary())
                .filter(step -> availableTypeNames.contains(step.getType().toUpperCase()))
                .filter(step -> !completedStepIds.contains(step.getStepId()))
                .min(Comparator.comparingInt(AuthenticationStepConfig::getOrder))
                .map(step -> AuthType.valueOf(step.getType().toUpperCase()))
                .orElse(null);
    }

    @Nullable
    protected AuthenticationFlowConfig findMfaFlowConfig(String flowTypeName) {
        if (flowTypeName == null) {
            // Single MFA backward compatibility: return first cached flow
            return cachedMfaFlowConfigs.values().stream().findFirst().orElse(null);
        }
        return cachedMfaFlowConfigs.get(flowTypeName.toLowerCase());
    }

    @Override
    public NextFactorDecision evaluateNextFactor(FactorContext ctx) {
        Assert.notNull(ctx, "FactorContext cannot be null.");

        AuthenticationFlowConfig mfaFlowConfig = findMfaFlowConfig(ctx.getFlowTypeName());
        if (mfaFlowConfig == null) {
            log.error("MFA flow configuration not found");
            return NextFactorDecision.error("MFA flow configuration not found");
        }

        // Check if required number of factors already completed
        long requiredCount = getRequiredFactorCount(ctx.getUsername(), ctx.getFlowTypeName());
        int completedCount = ctx.getCompletedFactors() != null ? ctx.getCompletedFactors().size() : 0;
        if (completedCount >= requiredCount) {
            return NextFactorDecision.noMoreFactors();
        }

        Set<AuthType> remainingFactors = ctx.getRemainingFactors();
        if (remainingFactors == null || remainingFactors.isEmpty()) {
            return NextFactorDecision.noMoreFactors();
        }

        List<AuthType> factorsForProcessing = new ArrayList<>(remainingFactors);

        AuthType nextFactorType = determineNextFactorInternal(
                factorsForProcessing,
                ctx.getCompletedFactors(),
                mfaFlowConfig.getStepConfigs()
        );

        if (nextFactorType != null) {
            Optional<AuthenticationStepConfig> nextStepConfigOpt =
                    findNextStepConfig(mfaFlowConfig, nextFactorType, ctx);

            if (nextStepConfigOpt.isPresent()) {
                AuthenticationStepConfig nextStep = nextStepConfigOpt.get();
                return NextFactorDecision.nextFactor(nextFactorType, nextStep.getStepId());
            }
        }
        return NextFactorDecision.noMoreFactors();
    }
}
