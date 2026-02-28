package io.contexa.contexaidentity.security.core.mfa.policy.evaluator;

import io.contexa.contexacommon.enums.ZeroTrustAction;
import io.contexa.contexacore.autonomous.repository.ZeroTrustActionRepository;
import io.contexa.contexacore.autonomous.repository.ZeroTrustActionRepository.ZeroTrustAnalysisData;
import io.contexa.contexacore.properties.HcadProperties;
import io.contexa.contexaidentity.security.core.mfa.context.FactorContext;
import io.contexa.contexaidentity.security.core.mfa.context.FactorContextAttributes;
import io.contexa.contexaidentity.security.core.mfa.model.MfaDecision;
import io.contexa.contexacommon.enums.AuthType;
import io.contexa.contexacommon.entity.Users;
import io.contexa.contexacommon.repository.UserRepository;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.ApplicationContext;
import org.springframework.util.CollectionUtils;

import java.time.Instant;
import java.util.*;
import java.util.stream.Collectors;

@Slf4j
public class ZeroTrustPolicyEvaluator extends AbstractMfaPolicyEvaluator {

    private final ZeroTrustActionRepository actionRedisRepository;
    private final HcadProperties hcadProperties;

    public ZeroTrustPolicyEvaluator(
            UserRepository userRepository,
            ApplicationContext applicationContext,
            ZeroTrustActionRepository actionRedisRepository,
            HcadProperties hcadProperties) {
        super(userRepository, applicationContext);
        this.actionRedisRepository = actionRedisRepository;
        this.hcadProperties = hcadProperties;
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
        ZeroTrustAnalysisData analysis = getZeroTrustAnalysis(context);
        ZeroTrustAction action = ZeroTrustAction.fromString(analysis.action());

        context.setAttribute(FactorContextAttributes.Policy.ZERO_TRUST_ACTION, action.name());

        return switch (action) {
            case ALLOW -> createAllowDecision(analysis);
            case CHALLENGE -> createChallengeDecision(context, analysis);
            case BLOCK -> createBlockDecision(analysis);
            case ESCALATE -> createEscalateDecision(analysis);
            case PENDING_ANALYSIS -> createPendingAnalysisDecision(context, analysis);
        };
    }

    private MfaDecision createAllowDecision(ZeroTrustAnalysisData analysis) {
        Map<String, Object> metadata = buildAuditMetadata(ZeroTrustAction.ALLOW.name(), analysis);

        return MfaDecision.builder()
                .required(false)
                .factorCount(0)
                .type(MfaDecision.DecisionType.NO_MFA_REQUIRED)
                .reason("Zero Trust ALLOW action - no MFA required")
                .metadata(metadata)
                .build();
    }

    private MfaDecision createChallengeDecision(FactorContext context, ZeroTrustAnalysisData analysis) {
        Map<String, Object> metadata = buildAuditMetadata(analysis.action(), analysis);

        if (userRepository == null) {
            log.error("UserRepository is not available for Zero Trust CHALLENGE");
            return MfaDecision.challenged("Zero Trust CHALLENGE - no user repository");
        }

        Optional<Users> userOptional = userRepository
                .findByUsernameWithGroupsRolesAndPermissions(context.getUsername());

        if (userOptional.isEmpty()) {
            log.error("User not found for Zero Trust CHALLENGE: {}", context.getUsername());
            return MfaDecision.challenged("Zero Trust CHALLENGE - user not found");
        }

        Users user = userOptional.get();

        Set<AuthType> availableFactors = getAvailableFactorsFromDsl(context);
        if (CollectionUtils.isEmpty(availableFactors)) {
            log.error("No available factors for Zero Trust CHALLENGE: {}", context.getUsername());
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

        String reason = buildChallengeReason(user, analysis);

        return MfaDecision.builder()
                .required(true)
                .factorCount(factorCount)
                .type(MfaDecision.DecisionType.CHALLENGED)
                .requiredFactors(requiredFactors)
                .reason(reason)
                .metadata(metadata)
                .build();
    }

    private MfaDecision createBlockDecision(ZeroTrustAnalysisData analysis) {
        Map<String, Object> metadata = buildAuditMetadata(ZeroTrustAction.BLOCK.name(), analysis);
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

    private MfaDecision createEscalateDecision(ZeroTrustAnalysisData analysis) {
        Map<String, Object> metadata = buildAuditMetadata(ZeroTrustAction.ESCALATE.name(), analysis);
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

    private MfaDecision createPendingAnalysisDecision(FactorContext context, ZeroTrustAnalysisData analysis) {
        ZeroTrustAction lastAction = getLastVerifiedAction(context.getUsername());

        if (lastAction == ZeroTrustAction.ALLOW) {
            Map<String, Object> metadata = buildAuditMetadata(ZeroTrustAction.PENDING_ANALYSIS.name(), analysis);
            metadata.put("pendingAnalysis", true);
            metadata.put("lastVerifiedAction", ZeroTrustAction.ALLOW.name());

            return MfaDecision.builder()
                    .required(false)
                    .factorCount(0)
                    .type(MfaDecision.DecisionType.NO_MFA_REQUIRED)
                    .reason("Zero Trust PENDING_ANALYSIS - last verified action was ALLOW")
                    .metadata(metadata)
                    .build();
        }

        MfaDecision challengeDecision = createChallengeDecision(context, analysis);

        Map<String, Object> enrichedMetadata = new HashMap<>();
        if (challengeDecision.getMetadata() != null) {
            enrichedMetadata.putAll(challengeDecision.getMetadata());
        }
        enrichedMetadata.put("pendingAnalysis", true);
        enrichedMetadata.put("lastVerifiedAction", lastAction != null ? lastAction.name() : "NONE");

        return challengeDecision.toBuilder()
                .reason("Zero Trust PENDING_ANALYSIS - MFA required (no prior ALLOW)")
                .metadata(enrichedMetadata)
                .build();
    }

    private ZeroTrustAnalysisData getZeroTrustAnalysis(FactorContext context) {
        String userId = context.getUsername();
        if (userId == null || userId.isBlank()) {
            return ZeroTrustAnalysisData.pending();
        }

        if (actionRedisRepository == null) {
            log.error("ZeroTrustActionRepository is not available for Zero Trust action lookup");
            return ZeroTrustAnalysisData.pending();
        }

        try {
            ZeroTrustAnalysisData data = actionRedisRepository.getAnalysisData(userId);
            if (data.action() == null) {
                return ZeroTrustAnalysisData.pending();
            }

            if (isStaleAnalysis(data.updatedAt())) {
                return ZeroTrustAnalysisData.pending();
            }

            return data;
        } catch (Exception e) {
            log.error("Failed to get Zero Trust analysis for user: {}", userId, e);
            return ZeroTrustAnalysisData.pending();
        }
    }

    private ZeroTrustAction getLastVerifiedAction(String userId) {
        if (userId == null || userId.isBlank() || actionRedisRepository == null) {
            return null;
        }

        try {
            return actionRedisRepository.getLastVerifiedAction(userId);
        } catch (Exception e) {
            log.error("Failed to get last verified action for user: {}", userId, e);
            return null;
        }
    }

    private boolean isStaleAnalysis(String updatedAt) {
        if (updatedAt == null || updatedAt.isBlank()) {
            return false;
        }

        try {
            long maxAgeMs = hcadProperties != null
                    ? hcadProperties.getAnalysis().getMaxAgeMs() : 3600000L;
            Instant updatedInstant = Instant.parse(updatedAt);
            return Instant.now().toEpochMilli() - updatedInstant.toEpochMilli() > maxAgeMs;
        } catch (Exception e) {
            log.error("Failed to parse updatedAt timestamp: {}", updatedAt, e);
            return false;
        }
    }

    private Map<String, Object> buildAuditMetadata(String action, ZeroTrustAnalysisData analysis) {
        Map<String, Object> metadata = new HashMap<>();
        metadata.put("source", "ZeroTrust");
        metadata.put("action", action);

        if (analysis.riskScore() != null) {
            metadata.put("riskScore", analysis.riskScore());
        }
        if (analysis.confidence() != null) {
            metadata.put("confidence", analysis.confidence());
        }
        if (analysis.threatEvidence() != null) {
            metadata.put("threatEvidence", analysis.threatEvidence());
        }
        if (analysis.analysisDepth() != null) {
            metadata.put("analysisDepth", analysis.analysisDepth());
        }
        return metadata;
    }

    private String buildChallengeReason(Users user, ZeroTrustAnalysisData analysis) {
        StringBuilder reason = new StringBuilder("Zero Trust CHALLENGE action - MFA required");
        List<String> details = new ArrayList<>();

        if (isAdminUser(user)) {
            details.add("Admin role");
        }
        if (analysis.threatEvidence() != null && !analysis.threatEvidence().isBlank()) {
            details.add("Threat: " + analysis.threatEvidence());
        }

        if (!details.isEmpty()) {
            reason.append(" (").append(String.join(", ", details)).append(")");
        }
        return reason.toString();
    }

}
