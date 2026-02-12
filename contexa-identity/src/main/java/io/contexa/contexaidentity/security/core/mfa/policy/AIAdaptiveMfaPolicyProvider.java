package io.contexa.contexaidentity.security.core.mfa.policy;

import io.contexa.contexacore.std.operations.AICoreOperations;
import io.contexa.contexaidentity.security.core.config.PlatformConfig;
import io.contexa.contexaidentity.security.core.mfa.context.FactorContext;
import io.contexa.contexaidentity.security.core.mfa.model.MfaDecision;
import io.contexa.contexaidentity.security.core.mfa.policy.evaluator.CompositeMfaPolicyEvaluator;
import io.contexa.contexacommon.properties.AuthContextProperties;
import io.contexa.contexacommon.repository.UserRepository;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.ApplicationContext;
import org.springframework.util.Assert;

@Slf4j
public class AIAdaptiveMfaPolicyProvider extends DefaultMfaPolicyProvider {
    
    private final CompositeMfaPolicyEvaluator compositePolicyEvaluator;
    private final AICoreOperations aiCoreOperations;

    public AIAdaptiveMfaPolicyProvider(
            UserRepository userRepository,
            ApplicationContext applicationContext,
            AuthContextProperties properties,
            CompositeMfaPolicyEvaluator compositePolicyEvaluator,
            PlatformConfig platformConfig,
            AICoreOperations aiCoreOperations) {

        super(userRepository, applicationContext, properties, compositePolicyEvaluator, platformConfig);
        this.compositePolicyEvaluator = compositePolicyEvaluator;
        this.aiCoreOperations = aiCoreOperations;

        if (aiCoreOperations == null) {
            log.warn("AI Core Operations not available. AI adaptive authentication will be disabled.");
        }
    }

    @Override
    protected MfaDecision evaluatePolicy(FactorContext ctx) {
        return compositePolicyEvaluator.evaluatePolicy(ctx);
    }

    @Override
    public MfaDecision evaluateInitialMfaRequirement(FactorContext ctx) {
        Assert.notNull(ctx, "FactorContext cannot be null");
        MfaDecision decision = super.evaluateInitialMfaRequirement(ctx);

        if (isAIAvailable()) {
            enrichContextWithAIMetadata(ctx);
        }
        return decision;
    }

    private void enrichContextWithAIMetadata(FactorContext ctx) {

        Object riskScore = ctx.getAttribute("riskScore");
        if (riskScore != null) {
            ctx.setAttribute("aiRiskScore", riskScore);
                    }

        Object aiAttributes = ctx.getAttribute("aiAttributes");
        if (aiAttributes != null) {
            ctx.setAttribute("aiAssessmentDetails", aiAttributes);
        }

        Boolean blocked = (Boolean) ctx.getAttribute("blocked");
        if (Boolean.TRUE.equals(blocked)) {
            String blockReason = (String) ctx.getAttribute("blockReason");
            log.warn("AI blocked authentication for user: {} - Reason: {}",
                    ctx.getUsername(), blockReason != null ? blockReason : "UNKNOWN");
        }

        String decisionType = (String) ctx.getAttribute("mfaDecisionType");
        if (decisionType != null) {
                    }
    }

    private boolean isAIAvailable() {
        return aiCoreOperations != null;
    }
}