package io.contexa.contexacore.autonomous.saas.mapper;

import io.contexa.contexacommon.enums.ZeroTrustAction;
import io.contexa.contexacore.autonomous.domain.AdminOverride;
import io.contexa.contexacore.autonomous.domain.SecurityEvent;
import io.contexa.contexacore.autonomous.saas.dto.ThreatOutcomePayload;
import io.contexa.contexacore.autonomous.saas.security.TenantScopedPseudonymizationService;

import java.time.LocalDateTime;
import java.time.ZoneOffset;
import java.util.LinkedHashMap;
import java.util.Map;

public class ThreatOutcomePayloadMapper {

    private static final String DEFAULT_TENANT_SCOPE = "default";

    private final TenantScopedPseudonymizationService pseudonymizationService;

    public ThreatOutcomePayloadMapper(TenantScopedPseudonymizationService pseudonymizationService) {
        this.pseudonymizationService = pseudonymizationService;
    }

    public ThreatOutcomePayload map(AdminOverride adminOverride, SecurityEvent originalEvent) {
        String tenantScope = resolveTenantScope(originalEvent);
        return ThreatOutcomePayload.builder()
                .outcomeId(adminOverride.getOverrideId())
                .correlationId(adminOverride.getRequestId())
                .outcomeType(resolveOutcomeType(adminOverride))
                .finalDisposition(resolveFinalDisposition(adminOverride))
                .resolutionSource("ADMIN_OVERRIDE")
                .originalAction(adminOverride.getOriginalAction())
                .finalAction(adminOverride.getOverriddenAction())
                .hashedUserId(pseudonymizationService.hash(tenantScope, adminOverride.getUserId()))
                .summary(buildSummary(adminOverride))
                .outcomeTimestamp(LocalDateTime.ofInstant(adminOverride.getTimestamp(), ZoneOffset.UTC))
                .attributes(buildAttributes(adminOverride, originalEvent))
                .build();
    }

    public String resolveTenantExternalRef(SecurityEvent originalEvent) {
        return resolveTenantScope(originalEvent);
    }

    private String resolveOutcomeType(AdminOverride adminOverride) {
        String original = normalizeAction(adminOverride.getOriginalAction());
        String overridden = normalizeAction(adminOverride.getOverriddenAction());
        if (isBlocking(original) && ZeroTrustAction.ALLOW.name().equals(overridden)) {
            return "FALSE_POSITIVE";
        }
        if (ZeroTrustAction.ALLOW.name().equals(original) && isBlocking(overridden)) {
            return "FALSE_NEGATIVE";
        }
        if (isBlocking(original) && isBlocking(overridden)) {
            return "CONFIRMED_ATTACK";
        }
        if (ZeroTrustAction.CHALLENGE.name().equals(overridden) || ZeroTrustAction.ESCALATE.name().equals(overridden)) {
            return "REQUIRES_INVESTIGATION";
        }
        return "OPERATOR_REVIEW";
    }

    private String resolveFinalDisposition(AdminOverride adminOverride) {
        String original = normalizeAction(adminOverride.getOriginalAction());
        String overridden = normalizeAction(adminOverride.getOverriddenAction());
        if (isBlocking(original) && ZeroTrustAction.ALLOW.name().equals(overridden)) {
            return "BENIGN";
        }
        if (isBlocking(overridden)) {
            return "MALICIOUS";
        }
        if (ZeroTrustAction.ALLOW.name().equals(overridden)) {
            return "BENIGN";
        }
        return "SUSPICIOUS";
    }

    private Map<String, Object> buildAttributes(AdminOverride adminOverride, SecurityEvent originalEvent) {
        Map<String, Object> attributes = new LinkedHashMap<>();
        attributes.put("approved", adminOverride.isApproved());
        if (originalEvent != null && originalEvent.getMetadata() != null) {
            copyIfPresent(originalEvent.getMetadata(), attributes, "requestPath");
            copyIfPresent(originalEvent.getMetadata(), attributes, "geoCountry");
            copyIfPresent(originalEvent.getMetadata(), attributes, "isSensitiveResource");
            copyIfPresent(originalEvent.getMetadata(), attributes, "failedLoginAttempts");
            copyIfPresent(originalEvent.getMetadata(), attributes, "auth.failure_count");
            copyIfPresent(originalEvent.getMetadata(), attributes, "isImpossibleTravel");
            copyIfPresent(originalEvent.getMetadata(), attributes, "isNewDevice");
            copyIfPresent(originalEvent.getMetadata(), attributes, "threatKnowledgeApplied");
            copyIfPresent(originalEvent.getMetadata(), attributes, "reasoningMemoryApplied");
            copyIfPresent(originalEvent.getMetadata(), attributes, "baselineSeedApplied");
            copyIfPresent(originalEvent.getMetadata(), attributes, "personalBaselineEstablished");
            copyIfPresent(originalEvent.getMetadata(), attributes, "organizationBaselineEstablished");
            copyIfPresent(originalEvent.getMetadata(), attributes, "threatKnowledgeExperimentGroup");
            copyIfPresent(originalEvent.getMetadata(), attributes, "threatKnowledgeCaseCount");
            copyIfPresent(originalEvent.getMetadata(), attributes, "threatKnowledgePrimaryKey");
            copyIfPresent(originalEvent.getMetadata(), attributes, "threatKnowledgeKeys");
            copyIfPresent(originalEvent.getMetadata(), attributes, "threatKnowledgeSignalKeys");
            copyIfPresent(originalEvent.getMetadata(), attributes, "threatKnowledgeMatchedFacts");
        }
        if (adminOverride.getReason() != null && !adminOverride.getReason().isBlank()) {
            attributes.put("operatorReasonCategory", summarizeReason(adminOverride.getReason()));
        }
        return Map.copyOf(attributes);
    }

    private void copyIfPresent(Map<String, Object> source, Map<String, Object> target, String key) {
        Object value = source.get(key);
        if (value != null) {
            target.put(key, value);
        }
    }

    private String buildSummary(AdminOverride adminOverride) {
        String outcomeType = resolveOutcomeType(adminOverride);
        String original = normalizeAction(adminOverride.getOriginalAction());
        String overridden = normalizeAction(adminOverride.getOverriddenAction());
        return switch (outcomeType) {
            case "FALSE_POSITIVE" -> "Operator review concluded that the previously blocked or challenged request should be treated as benign.";
            case "FALSE_NEGATIVE" -> "Operator review concluded that a request previously treated as benign should be escalated to a blocking decision.";
            case "CONFIRMED_ATTACK" -> "Operator review confirmed that the blocking decision should remain in place because the request is malicious.";
            case "REQUIRES_INVESTIGATION" -> "Operator review kept the request in a suspicious state that still requires investigation.";
            default -> "Operator review changed the final action from " + original + " to " + overridden + ".";
        };
    }

    private String summarizeReason(String reason) {
        String normalized = reason == null ? "" : reason.toLowerCase();
        if (normalized.contains("mfa")) {
            return "mfa_followup";
        }
        if (normalized.contains("device")) {
            return "device_context";
        }
        if (normalized.contains("travel")) {
            return "travel_context";
        }
        if (normalized.contains("admin")) {
            return "administrator_judgement";
        }
        return "operator_review";
    }

    private String resolveTenantScope(SecurityEvent originalEvent) {
        if (originalEvent == null || originalEvent.getMetadata() == null) {
            return DEFAULT_TENANT_SCOPE;
        }
        Object tenantId = originalEvent.getMetadata().get("tenantId");
        if (tenantId instanceof String tenant && !tenant.isBlank()) {
            return tenant.trim();
        }
        Object organizationId = originalEvent.getMetadata().get("organizationId");
        if (organizationId instanceof String organization && !organization.isBlank()) {
            return organization.trim();
        }
        return DEFAULT_TENANT_SCOPE;
    }

    private boolean isBlocking(String action) {
        return ZeroTrustAction.BLOCK.name().equals(action)
                || ZeroTrustAction.CHALLENGE.name().equals(action)
                || ZeroTrustAction.ESCALATE.name().equals(action);
    }

    private String normalizeAction(String action) {
        if (action == null || action.isBlank()) {
            return ZeroTrustAction.ALLOW.name();
        }
        return ZeroTrustAction.fromString(action).name();
    }
}
