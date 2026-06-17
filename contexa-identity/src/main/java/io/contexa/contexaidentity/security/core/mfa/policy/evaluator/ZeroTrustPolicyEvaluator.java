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
            return MfaDecision.blocked("Zero Trust CHALLENGE cannot verify user repository");
        }

        log.error("[ZeroTrustPolicyEvaluator] findByUsernameWithGroupsRolesAndPermissions username={}", context.getUsername());
        Optional<Users> userOptional = userRepository
                .findByUsernameWithGroupsRolesAndPermissions(context.getUsername());

        if (userOptional.isEmpty()) {
            log.error("User not found for Zero Trust CHALLENGE: {}", context.getUsername());
            return MfaDecision.blocked("Zero Trust CHALLENGE cannot verify user");
        }

        Users user = userOptional.get();

        Set<AuthType> availableFactors = getAvailableFactorsFromDsl(context);
        if (CollectionUtils.isEmpty(availableFactors)) {
            log.error("No available factors for Zero Trust CHALLENGE: {}", context.getUsername());
            return MfaDecision.blocked("Zero Trust CHALLENGE cannot proceed because no MFA factors are configured");
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
            return challengeAnalysis("Zero Trust analysis unavailable - missing user id");
        }

        if (actionRedisRepository == null) {
            log.error("ZeroTrustActionRepository is not available for Zero Trust action lookup");
            return challengeAnalysis("Zero Trust analysis unavailable - repository missing");
        }

        try {
            ZeroTrustAnalysisData data = actionRedisRepository.getAnalysisData(userId);
            if (data.action() == null) {
                return challengeAnalysis(data, "Zero Trust analysis unavailable - action missing");
            }

            if (isStaleAnalysis(data.updatedAt())) {
                return challengeAnalysis(data, "Zero Trust analysis stale or timestamp invalid");
            }

            return data;
        } catch (Exception e) {
            log.error("Failed to get Zero Trust analysis for user: {}", userId, e);
            return challengeAnalysis("Zero Trust analysis unavailable - lookup failed");
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
            return true;
        }

        try {
            long maxAgeMs = hcadProperties != null
                    && hcadProperties.getAnalysis() != null
                    ? hcadProperties.getAnalysis().getMaxAgeMs() : 3600000L;
            Instant updatedInstant = Instant.parse(updatedAt);
            return Instant.now().toEpochMilli() - updatedInstant.toEpochMilli() > maxAgeMs;
        } catch (Exception e) {
            log.error("Failed to parse updatedAt timestamp: {}", updatedAt, e);
            return true;
        }
    }

    private ZeroTrustAnalysisData challengeAnalysis(String reason) {
        return challengeAnalysis(null, reason);
    }

    private ZeroTrustAnalysisData challengeAnalysis(ZeroTrustAnalysisData source, String reason) {
        String threatEvidence = reason;
        if (source != null && source.threatEvidence() != null && !source.threatEvidence().isBlank()) {
            threatEvidence = source.threatEvidence() + "; " + reason;
        }

        return new ZeroTrustAnalysisData(
                ZeroTrustAction.CHALLENGE.name(),
                source != null ? source.riskScore() : null,
                source != null ? source.confidence() : null,
                threatEvidence,
                source != null ? source.analysisDepth() : null,
                Instant.now().toString(),
                source != null ? source.reasoning() : reason,
                source != null ? source.reasoningSummary() : reason,
                source != null ? source.requestId() : null,
                source != null ? source.contextBindingHash() : null,
                source != null ? source.llmProposedAction() : null
        );
    }

    private Map<String, Object> buildAuditMetadata(String action, ZeroTrustAnalysisData analysis) {
        Map<String, Object> metadata = new HashMap<>();
        metadata.put("source", "ZeroTrust");
        metadata.put("action", action);

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
