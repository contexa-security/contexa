/*
 * Copyright 2026 The Contexa Project
 *
 * The Contexa Project licenses this file to you under the Apache License,
 * version 2.0 (the "License"); you may not use this file except in compliance
 * with the License. You may obtain a copy of the License at:
 *
 *   https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
 * License for the specific language governing permissions and limitations
 * under the License.
 */
package io.contexa.contexaidentity.security.core.mfa.policy;

import io.contexa.contexacommon.entity.Users;
import io.contexa.contexacommon.enums.AuthType;
import io.contexa.contexacommon.properties.AuthContextProperties;
import io.contexa.contexacommon.repository.UserRepository;
import io.contexa.contexaidentity.security.core.config.AuthenticationFlowConfig;
import io.contexa.contexaidentity.security.core.config.AuthenticationStepConfig;
import io.contexa.contexaidentity.security.core.config.PlatformConfig;
import io.contexa.contexaidentity.security.core.mfa.context.FactorContext;
import io.contexa.contexaidentity.security.core.mfa.model.MfaDecision;
import io.contexa.contexaidentity.security.core.mfa.policy.evaluator.AbstractMfaPolicyEvaluator;
import io.contexa.contexaidentity.security.core.mfa.policy.evaluator.MfaPolicyEvaluator;
import io.contexa.contexaidentity.security.core.mfa.util.MfaFlowTypeUtils;
import jakarta.annotation.PostConstruct;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.function.Supplier;
import java.util.stream.Collectors;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.ApplicationContext;
import org.springframework.lang.Nullable;
import org.springframework.util.Assert;
import org.springframework.util.CollectionUtils;


@Slf4j
public class DefaultMfaPolicyProvider implements MfaPolicyProvider {

    protected final UserRepository userRepository;
    protected final ApplicationContext applicationContext;
    protected final AuthContextProperties properties;
    protected final MfaPolicyEvaluator policyEvaluator;
    protected final PlatformConfig platformConfig;
    private final Map<String, AuthenticationFlowConfig> cachedMfaFlowConfigs = new ConcurrentHashMap<>();
    /** Set while the provider a flow names is being asked: what it asks of this provider in turn is answered here. */
    private static final ThreadLocal<Boolean> ASKING_THE_FLOWS_PROVIDER = new ThreadLocal<>();

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
                                flow.getTypeName().toLowerCase(Locale.ROOT), flow));

                if (cachedMfaFlowConfigs.isEmpty()) {
                    log.debug("No MFA flow configured; form-only authentication remains valid");
                }
            }
        } catch (Exception e) {
            log.error("Error initializing MFA flow configuration", e);
        }
    }

    /**
     * The provider the flow's DSL names for itself ({@code mfa(mfa -> mfa.policyProvider(...))}), or {@code null} where
     * it names none, or names this one. The DSL took the provider and nothing asked it: every decision of every flow
     * came from the provider bean. A flow that names one is decided by it.
     *
     * <p>{@code null} too while that provider is being asked: one written around the provider bean (ask it, then
     * tighten the answer) gets the bean's own answer, and is not handed its own question again.
     */
    @Nullable
    protected MfaPolicyProvider providerOfFlow(@Nullable String flowTypeName) {
        if (flowTypeName == null || ASKING_THE_FLOWS_PROVIDER.get() != null) {
            return null;
        }
        AuthenticationFlowConfig flow = cachedMfaFlowConfigs.get(flowTypeName.toLowerCase(Locale.ROOT));
        MfaPolicyProvider named = flow != null ? flow.getMfaPolicyProvider() : null;
        return named != null && named != this ? named : null;
    }

    /** Asks the provider a flow names, with what it asks of this provider in turn answered by this provider itself. */
    protected <T> T askFlowsProvider(Supplier<T> question) {
        ASKING_THE_FLOWS_PROVIDER.set(Boolean.TRUE);
        try {
            return question.get();
        } finally {
            ASKING_THE_FLOWS_PROVIDER.remove();
        }
    }

    @Override
    public MfaDecision evaluateInitialMfaRequirement(FactorContext ctx) {
        Assert.notNull(ctx, "FactorContext cannot be null.");
        MfaPolicyProvider ofFlow = providerOfFlow(ctx.getFlowTypeName());
        if (ofFlow != null) {
            return askFlowsProvider(() -> ofFlow.evaluateInitialMfaRequirement(ctx));
        }
        return evaluatePolicy(ctx);
    }

    protected MfaDecision evaluatePolicy(FactorContext ctx) {
        return policyEvaluator.evaluatePolicy(ctx);
    }

    @Override
    public boolean isFactorAvailableForUser(String username, AuthType factorType, FactorContext ctx) {
        Assert.hasText(username, "Username cannot be empty.");
        Assert.notNull(factorType, "FactorType cannot be null.");

        MfaPolicyProvider ofFlow = ctx != null ? providerOfFlow(ctx.getFlowTypeName()) : null;
        if (ofFlow != null) {
            return askFlowsProvider(() -> ofFlow.isFactorAvailableForUser(username, factorType, ctx));
        }

        if (ctx != null) {
            Set<AuthType> availableFactors = ctx.getAvailableFactors();
            if (!availableFactors.isEmpty()) {
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
        MfaPolicyProvider ofFlow = providerOfFlow(flowType);
        if (ofFlow != null) {
            return askFlowsProvider(() -> ofFlow.getRequiredFactorCount(userId, flowType));
        }
        AuthenticationFlowConfig mfaFlowConfig = findMfaFlowConfig(flowType);
        if (mfaFlowConfig == null) {
            return 1;
        }

        if (mfaFlowConfig.getRequiredFactorCount() > 0) {
            return mfaFlowConfig.getRequiredFactorCount();
        }

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

        return flowSteps.stream()
                .filter(step -> !step.isPrimary())
                .filter(step -> availableTypeNames.contains(step.getType().toUpperCase(Locale.ROOT)))
                .filter(step -> !completedStepIds.contains(step.getStepId()))
                .min(Comparator.comparingInt(AuthenticationStepConfig::getOrder))
                .map(step -> AuthType.valueOf(step.getType().toUpperCase(Locale.ROOT)))
                .orElse(null);
    }

    @Nullable
    protected AuthenticationFlowConfig findMfaFlowConfig(String flowTypeName) {
        if (flowTypeName == null) {
            return cachedMfaFlowConfigs.values().stream().findFirst().orElse(null);
        }
        return cachedMfaFlowConfigs.get(flowTypeName.toLowerCase(Locale.ROOT));
    }

    @Override
    public NextFactorDecision evaluateNextFactor(FactorContext ctx) {
        Assert.notNull(ctx, "FactorContext cannot be null.");

        MfaPolicyProvider ofFlow = providerOfFlow(ctx.getFlowTypeName());
        if (ofFlow != null) {
            return askFlowsProvider(() -> ofFlow.evaluateNextFactor(ctx));
        }

        AuthenticationFlowConfig mfaFlowConfig = findMfaFlowConfig(ctx.getFlowTypeName());
        if (mfaFlowConfig == null) {
            log.error("MFA flow configuration not found");
            return NextFactorDecision.error("MFA flow configuration not found");
        }

        long requiredCount = getRequiredFactorCount(ctx.getUsername(), ctx.getFlowTypeName());
        int completedCount = ctx.getCompletedFactors() != null ? ctx.getCompletedFactors().size() : 0;
        if (completedCount >= requiredCount) {
            return NextFactorDecision.noMoreFactors();
        }

        Set<AuthType> availableFactors = ctx.getAvailableFactors();
        if (availableFactors.isEmpty()) {
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
