package io.contexa.contexacore.autonomous.saas.mapper;

import io.contexa.contexacommon.enums.ZeroTrustAction;
import io.contexa.contexacore.autonomous.domain.AdminOverride;
import io.contexa.contexacore.autonomous.domain.SecurityEvent;
import io.contexa.contexacore.autonomous.saas.dto.DecisionFeedbackPayload;
import io.contexa.contexacore.autonomous.saas.security.TenantScopedPseudonymizationService;

import java.time.LocalDateTime;
import java.time.ZoneOffset;
import java.util.LinkedHashMap;
import java.util.Locale;
import java.util.Map;

public class DecisionFeedbackPayloadMapper {

    private static final String DEFAULT_TENANT_SCOPE = "default";

    private final TenantScopedPseudonymizationService pseudonymizationService;

    public DecisionFeedbackPayloadMapper(TenantScopedPseudonymizationService pseudonymizationService) {
        this.pseudonymizationService = pseudonymizationService;
    }

    public DecisionFeedbackPayload map(AdminOverride adminOverride, SecurityEvent originalEvent) {
        if (adminOverride == null) {
            throw new IllegalArgumentException("AdminOverride is required for decision feedback forwarding");
        }
        String tenantScope = resolveTenantScope(originalEvent);
        Map<String, Object> attributes = new LinkedHashMap<>();
        if (originalEvent != null) {
            if (originalEvent.getSource() != null) {
                attributes.put("eventSource", originalEvent.getSource().name());
            }
            if (originalEvent.getSeverity() != null) {
                attributes.put("severity", originalEvent.getSeverity().name());
            }
            copyIfPresent(originalEvent.getMetadata(), attributes, "requestPath");
            copyIfPresent(originalEvent.getMetadata(), attributes, "requestUri");
            copyIfPresent(originalEvent.getMetadata(), attributes, "tenantId");
            copyIfPresent(originalEvent.getMetadata(), attributes, "organizationId");
        }
        Integer aiAnalysisLevel = resolveInteger(originalEvent != null ? originalEvent.getMetadata() : null, "aiAnalysisLevel");
        attributes.put("reasonCategory", classifyReason(adminOverride.getReason()));
        return DecisionFeedbackPayload.builder()
                .feedbackId(adminOverride.getOverrideId())
                .correlationId(adminOverride.getRequestId())
                .feedbackType(resolveFeedbackType(adminOverride))
                .adminAction(resolveAdminAction(adminOverride))
                .aiAnalysisLevel(aiAnalysisLevel)
                .originalAction(normalizeAction(adminOverride.getOriginalAction()))
                .overriddenAction(normalizeAction(adminOverride.getOverriddenAction()))
                .feedbackTimestamp(LocalDateTime.ofInstant(adminOverride.getTimestamp(), ZoneOffset.UTC))
                .hashedUserId(pseudonymizationService.hash(tenantScope, adminOverride.getUserId()))
                .attributes(Map.copyOf(attributes))
                .build();
    }

    public String resolveTenantExternalRef(SecurityEvent originalEvent) {
        if (originalEvent != null && originalEvent.getMetadata() != null) {
            Object tenantId = originalEvent.getMetadata().get("tenantId");
            if (tenantId instanceof String value && !value.isBlank()) {
                return value.trim();
            }
            Object organizationId = originalEvent.getMetadata().get("organizationId");
            if (organizationId instanceof String value && !value.isBlank()) {
                return value.trim();
            }
        }
        return DEFAULT_TENANT_SCOPE;
    }

    private String resolveFeedbackType(AdminOverride adminOverride) {
        String originalAction = normalizeAction(adminOverride.getOriginalAction());
        String overriddenAction = normalizeAction(adminOverride.getOverriddenAction());
        if (isBlocking(originalAction) && ZeroTrustAction.ALLOW.name().equals(overriddenAction)) {
            return "FALSE_POSITIVE";
        }
        if (!isBlocking(originalAction) && isBlocking(overriddenAction)) {
            return "FALSE_NEGATIVE";
        }
        return "CORRECT";
    }

    private String resolveAdminAction(AdminOverride adminOverride) {
        String originalAction = normalizeAction(adminOverride.getOriginalAction());
        String overriddenAction = normalizeAction(adminOverride.getOverriddenAction());
        if (isBlocking(originalAction) && ZeroTrustAction.ALLOW.name().equals(overriddenAction)) {
            return "OVERRIDDEN_TO_ALLOW";
        }
        if (isBlocking(overriddenAction)) {
            return "APPROVED_BLOCK";
        }
        if (ZeroTrustAction.ESCALATE.name().equals(overriddenAction) || ZeroTrustAction.CHALLENGE.name().equals(overriddenAction)) {
            return "ESCALATED";
        }
        return "REVIEWED";
    }

    private String resolveTenantScope(SecurityEvent originalEvent) {
        String tenantExternalRef = resolveTenantExternalRef(originalEvent);
        return tenantExternalRef != null && !tenantExternalRef.isBlank() ? tenantExternalRef : DEFAULT_TENANT_SCOPE;
    }

    private Integer resolveInteger(Map<String, Object> source, String key) {
        if (source == null) {
            return null;
        }
        Object value = source.get(key);
        if (value instanceof Number number) {
            return number.intValue();
        }
        if (value instanceof String text && !text.isBlank()) {
            try {
                return Integer.parseInt(text.trim());
            }
            catch (NumberFormatException ignored) {
                return null;
            }
        }
        return null;
    }

    private void copyIfPresent(Map<String, Object> source, Map<String, Object> target, String key) {
        if (source == null) {
            return;
        }
        Object value = source.get(key);
        if (value != null) {
            target.put(key, value);
        }
    }

    private String classifyReason(String reason) {
        if (reason == null || reason.isBlank()) {
            return "UNSPECIFIED";
        }
        String normalized = reason.trim().toLowerCase(Locale.ROOT);
        if (normalized.contains("mfa")) {
            return "MFA_VERIFIED";
        }
        if (normalized.contains("false") || normalized.contains("오탐")) {
            return "FALSE_POSITIVE_CONFIRMED";
        }
        if (normalized.contains("legitimate") || normalized.contains("정상")) {
            return "LEGITIMATE_ACTIVITY";
        }
        if (normalized.contains("escalat") || normalized.contains("승인")) {
            return "ADMIN_REVIEW";
        }
        return "ADMIN_OVERRIDE";
    }

    private boolean isBlocking(String action) {
        if (action == null || action.isBlank()) {
            return false;
        }
        String normalized = action.trim().toUpperCase(Locale.ROOT);
        return normalized.contains("BLOCK") || normalized.contains("DENY");
    }

    private String normalizeAction(String action) {
        return action != null && !action.isBlank() ? action.trim().toUpperCase(Locale.ROOT) : null;
    }
}
