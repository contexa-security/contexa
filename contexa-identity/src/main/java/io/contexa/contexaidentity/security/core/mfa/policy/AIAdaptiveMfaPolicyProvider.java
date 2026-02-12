package io.contexa.contexaidentity.security.core.mfa.policy;

import io.contexa.contexacore.std.operations.AICoreOperations;
import io.contexa.contexaidentity.security.core.config.PlatformConfig;
import io.contexa.contexaidentity.security.core.mfa.context.FactorContext;
import io.contexa.contexaidentity.security.core.mfa.context.FactorContextAttributes;
import io.contexa.contexaidentity.security.core.mfa.model.MfaDecision;
import io.contexa.contexaidentity.security.core.mfa.policy.evaluator.CompositeMfaPolicyEvaluator;
import io.contexa.contexacommon.properties.AuthContextProperties;
import io.contexa.contexacommon.repository.UserRepository;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.ApplicationContext;
import org.springframework.util.Assert;

import java.util.HashMap;
import java.util.Map;

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
            log.error("AI Core Operations not available. AI adaptive authentication will be disabled.");
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
            decision = applyAIAdaptation(ctx, decision);
        }
        return decision;
    }

    private MfaDecision applyAIAdaptation(FactorContext ctx, MfaDecision decision) {
        // Action-based: blocked=true overrides to BLOCKED decision
        Boolean blocked = (Boolean) ctx.getAttribute(FactorContextAttributes.StateControl.BLOCKED);
        if (Boolean.TRUE.equals(blocked)) {
            String blockReason = (String) ctx.getAttribute(FactorContextAttributes.MessageAndReason.BLOCK_REASON);
            log.error("AI blocked authentication for user: {} - Reason: {}",
                    ctx.getUsername(), blockReason != null ? blockReason : "UNKNOWN");
            return MfaDecision.blocked(blockReason != null ? blockReason : "AI blocked authentication");
        }

        // Action-based: mfaDecisionType overrides decision type
        String decisionType = (String) ctx.getAttribute(FactorContextAttributes.StateControl.MFA_DECISION_TYPE);
        if (decisionType != null) {
            MfaDecision.DecisionType resolvedType = resolveDecisionType(decisionType);
            if (resolvedType != null && resolvedType != decision.getType()) {
                return buildAdaptedDecision(decision, resolvedType);
            }
        }

        // Audit-only: AI riskScore recorded in metadata (does not affect factorCount)
        Double aiRiskScore = (Double) ctx.getAttribute(FactorContextAttributes.Policy.AI_RISK_SCORE);
        if (aiRiskScore != null) {
            Map<String, Object> metadata = new HashMap<>();
            if (decision.getMetadata() != null) {
                metadata.putAll(decision.getMetadata());
            }
            metadata.put("aiRiskScore", aiRiskScore);
            return decision.toBuilder().metadata(metadata).build();
        }

        return decision;
    }

    private MfaDecision.DecisionType resolveDecisionType(String decisionType) {
        return switch (decisionType.toUpperCase()) {
            case "BLOCKED" -> MfaDecision.DecisionType.BLOCKED;
            case "ESCALATED" -> MfaDecision.DecisionType.ESCALATED;
            case "NO_MFA_REQUIRED" -> MfaDecision.DecisionType.NO_MFA_REQUIRED;
            case "CHALLENGED" -> MfaDecision.DecisionType.CHALLENGED;
            default -> null;
        };
    }

    private MfaDecision buildAdaptedDecision(MfaDecision original, MfaDecision.DecisionType newType) {
        return switch (newType) {
            case BLOCKED -> MfaDecision.blocked("AI decision type override: BLOCKED");
            case ESCALATED -> MfaDecision.escalated("AI decision type override: ESCALATED");
            case NO_MFA_REQUIRED -> original.toBuilder()
                    .required(false)
                    .factorCount(0)
                    .type(MfaDecision.DecisionType.NO_MFA_REQUIRED)
                    .reason("AI decision type override: NO_MFA_REQUIRED")
                    .build();
            case CHALLENGED -> original.toBuilder()
                    .type(MfaDecision.DecisionType.CHALLENGED)
                    .reason("AI decision type override: CHALLENGED")
                    .build();
        };
    }

    private boolean isAIAvailable() {
        return aiCoreOperations != null;
    }
}
