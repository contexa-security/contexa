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

        String sessionId = ctx.getMfaSessionId();

        MfaDecision decision = evaluatePolicy(ctx);

        return decision;
    }

    protected MfaDecision evaluatePolicy(FactorContext ctx) {
        
        MfaDecision decision = policyEvaluator.evaluatePolicy(ctx);

        return decision;
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
        if (factorOptions == null || !factorOptions.containsKey(factorType)) {
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

    private List<AuthenticationStepConfig> getRequiredSteps(AuthenticationFlowConfig flowConfig) {
        return flowConfig.getStepConfigs().stream()
                .filter(AuthenticationStepConfig::isRequired)
                .collect(Collectors.toList());
    }

    private CompletionStatus evaluateCompletionStatus(FactorContext ctx,
                                                      List<AuthenticationStepConfig> requiredSteps) {
        Set<String> completedRequiredStepIds = new HashSet<>();
        List<String> missingRequiredStepIds = new ArrayList<>();

        for (AuthenticationStepConfig requiredStep : requiredSteps) {

            if(requiredStep.isPrimary()) continue; 

            String requiredStepId = requiredStep.getStepId();

            if (!StringUtils.hasText(requiredStepId)) {
                log.error("Required step with missing or empty stepId found");
                continue;
            }

            if (isStepCompleted(ctx, requiredStepId)) {
                completedRequiredStepIds.add(requiredStepId);
            } else {
                missingRequiredStepIds.add(requiredStepId);
            }
        }

        boolean allRequiredCompleted = missingRequiredStepIds.isEmpty();
        return new CompletionStatus(allRequiredCompleted, missingRequiredStepIds);
    }

    private boolean isStepCompleted(FactorContext ctx, String stepId) {
        return ctx.getCompletedFactors().stream()
                .anyMatch(completedFactor -> stepId.equals(completedFactor.getStepId()));
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
    private AuthType parseAuthType(String type) {
        try {
            return AuthType.valueOf(type.toUpperCase());
        } catch (IllegalArgumentException e) {
            log.warn("Invalid AuthType: {}", type);
            return null;
        }
    }

    public List<AuthType> getAvailableMfaFactorsForUser(String username) {
        if (!StringUtils.hasText(username)) {
            return Collections.emptyList();
        }

        AuthenticationFlowConfig mfaFlowConfig = findMfaFlowConfig();
        if (mfaFlowConfig != null) {
            Map<AuthType, ?> factorOptions = mfaFlowConfig.getRegisteredFactorOptions();
            if (factorOptions != null) {
                return new ArrayList<>(factorOptions.keySet());
            }
        }

                return Collections.emptyList();
    }

    @Nullable
    private AuthenticationFlowConfig findMfaFlowConfig() {
        return cachedMfaFlowConfig;
    }

    public void invalidateFlowConfigCache() {
        cachedMfaFlowConfig = null;
                initializeMfaFlowConfig();
    }

    private HttpServletRequest getCurrentRequest() {
        ServletRequestAttributes attrs = (ServletRequestAttributes)
                RequestContextHolder.getRequestAttributes();
        return attrs != null ? attrs.getRequest() : null;
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

    @Override
    public CompletionDecision evaluateCompletion(FactorContext ctx,
                                                 AuthenticationFlowConfig mfaFlowConfig) {
        Assert.notNull(ctx, "FactorContext cannot be null");
        Assert.notNull(mfaFlowConfig, "AuthenticationFlowConfig cannot be null");

        if (!AuthType.MFA.name().equalsIgnoreCase(mfaFlowConfig.getTypeName())) {
            log.warn("checkCompletion called with non-MFA flow config");
            return CompletionDecision.error("Non-MFA flow configuration");
        }

        List<AuthenticationStepConfig> requiredSteps = getRequiredSteps(mfaFlowConfig);

        if (requiredSteps.isEmpty()) {
                        return CompletionDecision.completed();
        }

        CompletionStatus status = evaluateCompletionStatus(ctx, requiredSteps);

        if (status.allRequiredCompleted && !ctx.getCompletedFactors().isEmpty()) {
                        return CompletionDecision.completed();
        }

        if (!ctx.getAvailableFactors().isEmpty() && ctx.getCompletedFactors().isEmpty()) {
            Integer selectFactorAttempts = (Integer) ctx.getAttribute("selectFactorAttemptCount");
            int attemptCount = (selectFactorAttempts == null) ? 1 : selectFactorAttempts + 1;

            if (attemptCount > 3) {
                log.error("Maximum factor selection attempts exceeded");
                return CompletionDecision.error("Maximum factor selection attempts exceeded");
            }

                        return CompletionDecision.needsFactorSelection(attemptCount);
        }

        if (ctx.getAvailableFactors().isEmpty()) {
            log.error("No available MFA factors");
            return CompletionDecision.error("No available MFA factors defined");
        }

                return CompletionDecision.incomplete(status.missingRequiredStepIds);
    }

    private static class CompletionStatus {
        final boolean allRequiredCompleted;
        final List<String> missingRequiredStepIds;

        CompletionStatus(boolean allRequiredCompleted, List<String> missingRequiredStepIds) {
            this.allRequiredCompleted = allRequiredCompleted;
            this.missingRequiredStepIds = missingRequiredStepIds;
        }
    }
}
