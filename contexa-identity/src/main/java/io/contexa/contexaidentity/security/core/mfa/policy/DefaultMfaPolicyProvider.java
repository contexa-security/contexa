package io.contexa.contexaidentity.security.core.mfa.policy;

import io.contexa.contexaidentity.security.core.config.AuthenticationFlowConfig;
import io.contexa.contexaidentity.security.core.config.AuthenticationStepConfig;
import io.contexa.contexaidentity.security.core.config.PlatformConfig;
import io.contexa.contexaidentity.security.core.mfa.context.FactorContext;
import io.contexa.contexaidentity.security.core.mfa.model.MfaDecision;
import io.contexa.contexaidentity.security.core.mfa.policy.evaluator.MfaPolicyEvaluator;
import io.contexa.contexacommon.enums.AuthType;
import io.contexa.contexacommon.properties.AuthContextProperties;
import io.contexa.contexacommon.entity.Users;
import io.contexa.contexacommon.repository.UserRepository;
import jakarta.annotation.PostConstruct;
import jakarta.servlet.http.HttpServletRequest;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.ApplicationContext;
import org.springframework.lang.Nullable;
import org.springframework.util.Assert;
import org.springframework.util.CollectionUtils;
import org.springframework.util.StringUtils;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;

import java.util.*;
import java.util.stream.Collectors;

@Slf4j
public class DefaultMfaPolicyProvider implements MfaPolicyProvider {

    protected final UserRepository userRepository;
    protected final ApplicationContext applicationContext;
    protected final AuthContextProperties properties;
    protected final MfaPolicyEvaluator policyEvaluator;
    protected final PlatformConfig platformConfig;
    private AuthenticationFlowConfig cachedMfaFlowConfig;

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
                cachedMfaFlowConfig = platformConfig.getFlows().stream()
                        .filter(flow -> AuthType.MFA.name().equalsIgnoreCase(flow.getTypeName()))
                        .findFirst()
                        .orElse(null);

                if (cachedMfaFlowConfig != null) {
                } else {
                    log.warn("No MFA flow configuration found during initialization");
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
                boolean available = availableFactors.contains(factorType);
                return available;
            }
        }

        AuthenticationFlowConfig mfaFlowConfig = findMfaFlowConfig();
        if (mfaFlowConfig == null) {
            log.warn("MFA flow config not found. Factor {} not available for user: {}", factorType, username);
            return false;
        }

        Map<AuthType, ?> factorOptions = mfaFlowConfig.getRegisteredFactorOptions();
        if (!factorOptions.containsKey(factorType)) {
            return false;
        }

        return true;
    }

    @Override
    public Integer getRequiredFactorCount(String userId, String flowType) {
        Users user = userRepository.findByUsernameWithGroupsRolesAndPermissions(userId).orElse(null);

        if (user != null) {
            int baseCount = 1;
            return adjustRequiredFactorCount(baseCount, userId, flowType);
        }

        return switch (flowType.toLowerCase()) {
            case "mfa" -> 2;
            case "mfa-stepup" -> 1;
            case "mfa-transactional" -> 1;
            default -> 1;
        };
    }

    protected int adjustRequiredFactorCount(int baseCount, String userId, String flowType) {
        return baseCount;
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

        for (AuthType factor : availableFactors) {

            Optional<AuthenticationStepConfig> nextStep = flowSteps.stream()
                    .filter(step -> factor.name().equalsIgnoreCase(step.getType()))
                    .filter(step -> !completedStepIds.contains(step.getStepId()))
                    .min(Comparator.comparingInt(AuthenticationStepConfig::getOrder));

            if (nextStep.isPresent()) {
                return factor;
            }
        }
        return null;
    }

    @Nullable
    private AuthenticationFlowConfig findMfaFlowConfig() {
        return cachedMfaFlowConfig;
    }

    @Override
    public NextFactorDecision evaluateNextFactor(FactorContext ctx) {
        Assert.notNull(ctx, "FactorContext cannot be null.");

        AuthenticationFlowConfig mfaFlowConfig = findMfaFlowConfig();
        if (mfaFlowConfig == null) {
            log.error("MFA flow configuration not found");
            return NextFactorDecision.error("MFA flow configuration not found");
        }

        Set<AuthType> availableFactors = ctx.getAvailableFactors();
        if (availableFactors == null || availableFactors.isEmpty()) {
            log.warn("No available factors, all factors may be completed");
            return NextFactorDecision.noMoreFactors();
        }

        List<AuthType> factorsForProcessing = new ArrayList<>(availableFactors);

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
