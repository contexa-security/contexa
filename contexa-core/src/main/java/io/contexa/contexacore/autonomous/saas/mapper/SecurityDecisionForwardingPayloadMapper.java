package io.contexa.contexacore.autonomous.saas.mapper;

import io.contexa.contexacore.autonomous.context.CanonicalSecurityContext;
import io.contexa.contexacore.autonomous.context.CanonicalSecurityContextProvider;
import io.contexa.contexacore.autonomous.domain.SecurityEvent;
import io.contexa.contexacore.autonomous.domain.SecurityEventContext;
import io.contexa.contexacore.autonomous.saas.dto.SecurityDecisionForwardingPayload;
import io.contexa.contexacore.autonomous.saas.security.TenantScopedPseudonymizationService;
import io.contexa.contexacore.autonomous.saas.threat.ThreatSignalNormalizationService;
import io.contexa.contexacore.autonomous.processor.ProcessingResult;
import io.contexa.contexacore.properties.SaasForwardingProperties;
import org.springframework.util.StringUtils;

import java.time.LocalDateTime;
import java.util.*;

public class SecurityDecisionForwardingPayloadMapper {

    private static final String DEFAULT_TENANT_SCOPE = "default";
    private static final String OPERATIONAL_EVIDENCE_SOURCE = "operationalEvidenceSource";
    private static final String OPERATIONAL_EVIDENCE_SOURCE_ANALYSIS_DATA = "ANALYSIS_DATA";
    private static final String OPERATIONAL_EVIDENCE_SOURCE_THREAT_INDICATORS = "THREAT_INDICATORS";
    private static final String OPERATIONAL_EVIDENCE_SOURCE_NONE = "NONE";

    private final TenantScopedPseudonymizationService pseudonymizationService;
    private final ThreatSignalNormalizationService threatSignalNormalizationService;
    private final SaasForwardingProperties properties;
    private final CanonicalSecurityContextProvider canonicalSecurityContextProvider;

    public SecurityDecisionForwardingPayloadMapper(
            TenantScopedPseudonymizationService pseudonymizationService,
            ThreatSignalNormalizationService threatSignalNormalizationService,
            SaasForwardingProperties properties) {
        this(pseudonymizationService, threatSignalNormalizationService, properties, null);
    }

    public SecurityDecisionForwardingPayloadMapper(
            TenantScopedPseudonymizationService pseudonymizationService,
            ThreatSignalNormalizationService threatSignalNormalizationService,
            SaasForwardingProperties properties,
            CanonicalSecurityContextProvider canonicalSecurityContextProvider) {
        this.pseudonymizationService = pseudonymizationService;
        this.threatSignalNormalizationService = threatSignalNormalizationService;
        this.properties = properties;
        this.canonicalSecurityContextProvider = canonicalSecurityContextProvider;
    }

    public SecurityDecisionForwardingPayload map(SecurityEventContext context) {
        SecurityEvent event = context.getSecurityEvent();
        ProcessingResult result = requireResult(context);
        Map<String, Object> eventMetadata = event.getMetadata() != null ? event.getMetadata() : Map.of();
        Map<String, Object> analysisData = result.getAnalysisData() != null ? result.getAnalysisData() : Map.of();
        CanonicalSecurityContext canonicalSecurityContext = resolveCanonicalSecurityContext(event);
        String workProfileSummary = resolveWorkProfileSummary(canonicalSecurityContext, eventMetadata);
        String roleDriftSummary = resolveRoleDriftSummary(canonicalSecurityContext, eventMetadata);
        String approvalSummary = resolveApprovalSummary(canonicalSecurityContext, eventMetadata);
        String objectiveDriftSummary = resolveObjectiveDriftSummary(canonicalSecurityContext, eventMetadata);
        String tenantScope = resolveTenantScope(eventMetadata);
        ThreatSignalNormalizationService.NormalizedThreatSignal threatSignal =
                threatSignalNormalizationService.normalize(event, result);

        return SecurityDecisionForwardingPayload.builder()
                .correlationId(resolveCorrelationId(event, context))
                .decision(result.getAction())
                .llmProposedAction(resolveLlmProposedAction(result))
                .autonomousEnforcementAction(resolveAutonomousEnforcementAction(result))
                .aiAnalysisLevel(result.getAiAnalysisLevel())
                .processingTimeMs(result.getProcessingTimeMs())
                .llmAuditRiskScore(result.resolveAuditRiskScore())
                .effectiveConfidence(result.getConfidence())
                .llmAuditConfidence(result.resolveAuditConfidence())
                .reasoning(properties.isIncludeReasoning() ? result.getReasoning() : null)
                .autonomyConstraintApplied(result.getAutonomyConstraintApplied())
                .autonomyConstraintSummary(result.getAutonomyConstraintSummary())
                .autonomyConstraintReasons(copyList(result.getAutonomyConstraintReasons()))
                .severityLevel(event.getSeverity() != null ? event.getSeverity().name() : null)
                .eventSource(event.getSource() != null ? event.getSource().name() : null)
                .eventTimestamp(event.getTimestamp())
                .hashedUserId(pseudonymizationService.hash(tenantScope, event.getUserId()))
                .hashedSessionId(pseudonymizationService.hash(tenantScope, event.getSessionId()))
                .hashedSourceIp(pseudonymizationService.hash(tenantScope, event.getSourceIp()))
                .globalSourceKey(pseudonymizationService.hashGlobal(event.getSourceIp()))
                .behaviorPatterns(extractStringList(analysisData.get("behaviorPatterns")))
                .threatCategory(threatSignal.rawThreatCategory())
                .canonicalThreatClass(threatSignal.canonicalThreatClass())
                .evidenceList(extractOperationalEvidence(result, analysisData))
                .mitreTacticHints(threatSignal.mitreTacticHints())
                .targetSurfaceCategory(threatSignal.targetSurfaceCategory())
                .signalTags(threatSignal.signalTags())
                .workProfileSummary(workProfileSummary)
                .roleDriftSummary(roleDriftSummary)
                .approvalSummary(approvalSummary)
                .objectiveDriftSummary(objectiveDriftSummary)
                .promptKey(extractText(eventMetadata, "promptKey"))
                .promptTemplateKey(extractText(eventMetadata, "templateKey"))
                .promptVersion(extractText(eventMetadata, "promptVersion"))
                .promptContractVersion(extractText(eventMetadata, "contractVersion"))
                .promptReleaseStatus(extractText(eventMetadata, "promptReleaseStatus"))
                .promptHash(extractText(eventMetadata, "promptHash"))
                .systemPromptHash(extractText(eventMetadata, "systemPromptHash"))
                .userPromptHash(extractText(eventMetadata, "userPromptHash"))
                .budgetProfile(extractText(eventMetadata, "budgetProfile"))
                .promptEvidenceCompleteness(extractText(eventMetadata, "promptEvidenceCompleteness"))
                .promptSectionSet(extractStringList(eventMetadata.get("promptSectionSet")))
                .omittedSections(extractStringList(eventMetadata.get("omittedSections")))
                .promptOmissionCount(extractInteger(eventMetadata, "promptOmissionCount"))
                .promptGeneratedAtEpochMs(extractLong(eventMetadata, "promptGeneratedAtEpochMs"))
                .requestPath(extractRequestPath(eventMetadata))
                .geoCountry(extractText(eventMetadata, "geoCountry"))
                .geoCity(extractText(eventMetadata, "geoCity"))
                .newDevice(extractBoolean(eventMetadata, "isNewDevice"))
                .impossibleTravel(extractBoolean(eventMetadata, "isImpossibleTravel"))
                .travelDistanceKm(extractDouble(eventMetadata, "travelDistanceKm"))
                .layer1Assessment(extractMap(analysisData.get("layer1Assessment")))
                .layer2Assessment(extractMap(analysisData.get("layer2Assessment")))
                .attributes(extractAttributes(
                        eventMetadata,
                        analysisData,
                        result,
                        workProfileSummary,
                        roleDriftSummary,
                        approvalSummary,
                        objectiveDriftSummary))
                .forwardedAt(LocalDateTime.now())
                .build();
    }

    private ProcessingResult requireResult(SecurityEventContext context) {
        Object resultObject = context.getMetadata().get("processingResult");
        if (!(resultObject instanceof ProcessingResult result) || !result.isSuccess()) {
            throw new IllegalArgumentException("Successful processing result is required for SaaS forwarding");
        }
        return result;
    }

    private String resolveCorrelationId(SecurityEvent event, SecurityEventContext context) {
        Object correlationId = context.getMetadata().get("correlationId");
        if (correlationId instanceof String value && !value.isBlank()) {
            return value.trim();
        }
        if (event.getEventId() != null && !event.getEventId().isBlank()) {
            return event.getEventId().trim();
        }
        return UUID.randomUUID().toString();
    }

    private String resolveTenantScope(Map<String, Object> eventMetadata) {
        String tenantId = extractText(eventMetadata, "tenantId");
        if (tenantId != null && !tenantId.isBlank()) {
            return tenantId;
        }
        String organizationId = extractText(eventMetadata, "organizationId");
        if (organizationId != null && !organizationId.isBlank()) {
            return organizationId;
        }
        return DEFAULT_TENANT_SCOPE;
    }

    private List<String> extractOperationalEvidence(ProcessingResult result, Map<String, Object> analysisData) {
        List<String> fromAnalysis = extractStringList(analysisData.get("evidenceList"));
        if (!fromAnalysis.isEmpty()) {
            return fromAnalysis;
        }
        if (result.getThreatIndicators() == null) {
            return List.of();
        }
        return result.getThreatIndicators().stream()
                .filter(Objects::nonNull)
                .map(String::trim)
                .filter(value -> !value.isBlank())
                .distinct()
                .toList();
    }

    private String resolveOperationalEvidenceSource(ProcessingResult result, Map<String, Object> analysisData) {
        if (!extractStringList(analysisData.get("evidenceList")).isEmpty()) {
            return OPERATIONAL_EVIDENCE_SOURCE_ANALYSIS_DATA;
        }
        if (result.getThreatIndicators() != null && !result.getThreatIndicators().isEmpty()) {
            return OPERATIONAL_EVIDENCE_SOURCE_THREAT_INDICATORS;
        }
        return OPERATIONAL_EVIDENCE_SOURCE_NONE;
    }

    private String extractRequestPath(Map<String, Object> eventMetadata) {
        String direct = extractText(eventMetadata, "requestPath");
        if (direct != null && !direct.isBlank()) {
            return direct;
        }
        return extractText(eventMetadata, "requestUri");
    }

    private Map<String, Object> extractAttributes(
            Map<String, Object> eventMetadata,
            Map<String, Object> analysisData,
            ProcessingResult result,
            String workProfileSummary,
            String roleDriftSummary,
            String approvalSummary,
            String objectiveDriftSummary) {
        Map<String, Object> attributes = new LinkedHashMap<>();
        if (properties.isIncludeRawAnalysisData()) {
            attributes.putAll(analysisData);
        }
        copyIfPresent(eventMetadata, attributes, "geoCountry");
        copyIfPresent(eventMetadata, attributes, "geoCity");
        copyIfPresent(eventMetadata, attributes, "isNewDevice");
        copyIfPresent(eventMetadata, attributes, "isImpossibleTravel");
        copyIfPresent(eventMetadata, attributes, "travelDistanceKm");
        copyIfPresent(eventMetadata, attributes, "failedLoginAttempts");
        copyIfPresent(eventMetadata, attributes, "auth.failure_count");
        copyIfPresent(eventMetadata, attributes, "isSensitiveResource");
        copyIfPresent(eventMetadata, attributes, "userRoles");
        copyIfPresent(eventMetadata, attributes, "bridgeCoverageLevel");
        copyIfPresent(eventMetadata, attributes, "bridgeCoverageScore");
        copyIfPresent(eventMetadata, attributes, "bridgeCoverageSummary");
        copyIfPresent(eventMetadata, attributes, "bridgeMissingContexts");
        copyIfPresent(eventMetadata, attributes, "bridgeRemediationHints");
        copyIfPresent(eventMetadata, attributes, "bridgeAuthenticationSource");
        copyIfPresent(eventMetadata, attributes, "bridgeAuthorizationSource");
        copyIfPresent(eventMetadata, attributes, "bridgeDelegationSource");
        copyIfPresent(eventMetadata, attributes, "threatKnowledgeApplied");
        copyIfPresent(eventMetadata, attributes, "reasoningMemoryApplied");
        copyIfPresent(eventMetadata, attributes, "baselineSeedApplied");
        copyIfPresent(eventMetadata, attributes, "personalBaselineEstablished");
        copyIfPresent(eventMetadata, attributes, "organizationBaselineEstablished");
        copyIfPresent(eventMetadata, attributes, "threatKnowledgeExperimentGroup");
        copyIfPresent(eventMetadata, attributes, "threatKnowledgeCaseCount");
        copyIfPresent(eventMetadata, attributes, "threatKnowledgePrimaryKey");
        copyIfPresent(eventMetadata, attributes, "threatKnowledgeKeys");
        copyIfPresent(eventMetadata, attributes, "threatKnowledgeSignalKeys");
        copyIfPresent(eventMetadata, attributes, "threatKnowledgeMatchedFacts");
        copyIfPresent(eventMetadata, attributes, "parameterRiskFlags");
        copyIfPresent(eventMetadata, attributes, "promptRiskFlags");
        copyIfPresent(eventMetadata, attributes, "toolArgumentsSummary");
        if (result.resolveAuditRiskScore() != null) {
            attributes.put("llmAuditRiskScore", result.resolveAuditRiskScore());
        }
        if (result.getConfidence() != null) {
            attributes.put("effectiveConfidence", result.getConfidence());
        }
        if (result.resolveAuditConfidence() != null) {
            attributes.put("llmAuditConfidence", result.resolveAuditConfidence());
        }
        if (result.getProposedAction() != null && !result.getProposedAction().isBlank()) {
            attributes.put("llmProposedAction", result.getProposedAction());
        }
        if (result.getAction() != null && !result.getAction().isBlank()) {
            attributes.put("autonomousEnforcementAction", result.getAction());
        }
        if (Boolean.TRUE.equals(result.getAutonomyConstraintApplied())) {
            attributes.put("autonomyConstraintApplied", true);
            if (result.getAutonomyConstraintSummary() != null) {
                attributes.put("autonomyConstraintSummary", result.getAutonomyConstraintSummary());
            }
            if (result.getAutonomyConstraintReasons() != null && !result.getAutonomyConstraintReasons().isEmpty()) {
                attributes.put("autonomyConstraintReasons", result.getAutonomyConstraintReasons());
            }
        }
        attributes.put(OPERATIONAL_EVIDENCE_SOURCE, resolveOperationalEvidenceSource(result, analysisData));
        copyIfPresent(eventMetadata, attributes, "parameter_risk_flags");
        copyIfPresent(eventMetadata, attributes, "prompt_risk_flags");
        copyIfPresent(eventMetadata, attributes, "tool_arguments_summary");
        copyIfPresent(analysisData, attributes, "parameterRiskFlags");
        copyIfPresent(analysisData, attributes, "promptRiskFlags");
        copyIfPresent(analysisData, attributes, "toolArgumentsSummary");
        copyIfPresent(attributes, "workProfileSummary", workProfileSummary);
        copyIfPresent(attributes, "roleDriftSummary", roleDriftSummary);
        copyIfPresent(attributes, "approvalSummary", approvalSummary);
        copyIfPresent(attributes, "objectiveDriftSummary", objectiveDriftSummary);
        copyIfPresent(eventMetadata, attributes, "promptKey");
        copyIfPresent(eventMetadata, attributes, "templateKey");
        copyIfPresent(eventMetadata, attributes, "promptVersion");
        copyIfPresent(eventMetadata, attributes, "contractVersion");
        copyIfPresent(eventMetadata, attributes, "promptReleaseStatus");
        copyIfPresent(eventMetadata, attributes, "promptHash");
        copyIfPresent(eventMetadata, attributes, "systemPromptHash");
        copyIfPresent(eventMetadata, attributes, "userPromptHash");
        copyIfPresent(eventMetadata, attributes, "budgetProfile");
        copyIfPresent(eventMetadata, attributes, "promptEvidenceCompleteness");
        copyIfPresent(eventMetadata, attributes, "promptSectionSet");
        copyIfPresent(eventMetadata, attributes, "omittedSections");
        copyIfPresent(eventMetadata, attributes, "promptOmissionCount");
        copyIfPresent(eventMetadata, attributes, "promptGeneratedAtEpochMs");
        copyIfPresent(eventMetadata, attributes, "promptRuntimeTelemetryLinked");
        copyIfPresent(eventMetadata, attributes, "promptRuntimeTelemetryLayer");
        return attributes.isEmpty() ? Map.of() : Map.copyOf(attributes);
    }

    private void copyIfPresent(Map<String, Object> target, String key, Object value) {
        if (value != null) {
            target.put(key, value);
        }
    }

    private void copyIfPresent(Map<String, Object> source, Map<String, Object> target, String key) {
        Object value = source.get(key);
        if (value != null) {
            target.put(key, value);
        }
    }

    private String resolveLlmProposedAction(ProcessingResult result) {
        if (result.getProposedAction() != null && !result.getProposedAction().isBlank()) {
            return result.getProposedAction();
        }
        return result.getAction();
    }

    private String resolveAutonomousEnforcementAction(ProcessingResult result) {
        if (result.getAction() != null && !result.getAction().isBlank()) {
            return result.getAction();
        }
        return result.getProposedAction();
    }

    private CanonicalSecurityContext resolveCanonicalSecurityContext(SecurityEvent event) {
        if (canonicalSecurityContextProvider == null || event == null) {
            return null;
        }
        try {
            return canonicalSecurityContextProvider.resolve(event).orElse(null);
        }
        catch (RuntimeException ignored) {
            return null;
        }
    }

    private String resolveWorkProfileSummary(CanonicalSecurityContext canonicalSecurityContext, Map<String, Object> eventMetadata) {
        if (canonicalSecurityContext != null
                && canonicalSecurityContext.getWorkProfile() != null
                && StringUtils.hasText(canonicalSecurityContext.getWorkProfile().getSummary())) {
            return canonicalSecurityContext.getWorkProfile().getSummary();
        }
        return extractText(eventMetadata, "workProfileSummary");
    }

    private String resolveRoleDriftSummary(CanonicalSecurityContext canonicalSecurityContext, Map<String, Object> eventMetadata) {
        if (canonicalSecurityContext != null && canonicalSecurityContext.getRoleScopeProfile() != null) {
            CanonicalSecurityContext.RoleScopeProfile roleScopeProfile = canonicalSecurityContext.getRoleScopeProfile();
            List<String> facts = new ArrayList<>();
            if (StringUtils.hasText(roleScopeProfile.getCurrentResourceFamily())) {
                facts.add("Current resource family: " + roleScopeProfile.getCurrentResourceFamily());
            }
            if (StringUtils.hasText(roleScopeProfile.getCurrentActionFamily())) {
                facts.add("Current action family: " + roleScopeProfile.getCurrentActionFamily());
            }
            if (!roleScopeProfile.getExpectedResourceFamilies().isEmpty()) {
                facts.add("Expected resource families: " + String.join(", ", roleScopeProfile.getExpectedResourceFamilies()));
            }
            if (!roleScopeProfile.getExpectedActionFamilies().isEmpty()) {
                facts.add("Expected action families: " + String.join(", ", roleScopeProfile.getExpectedActionFamilies()));
            }
            if (!roleScopeProfile.getForbiddenResourceFamilies().isEmpty()) {
                facts.add("Denied resource families: " + String.join(", ", roleScopeProfile.getForbiddenResourceFamilies()));
            }
            if (!roleScopeProfile.getForbiddenActionFamilies().isEmpty()) {
                facts.add("Denied action families: " + String.join(", ", roleScopeProfile.getForbiddenActionFamilies()));
            }
            if (StringUtils.hasText(roleScopeProfile.getCurrentResourceFamily()) && !roleScopeProfile.getExpectedResourceFamilies().isEmpty()) {
                facts.add("Current resource family present in expected role-scope evidence: "
                        + containsIgnoreCase(roleScopeProfile.getExpectedResourceFamilies(), roleScopeProfile.getCurrentResourceFamily()));
            }
            if (StringUtils.hasText(roleScopeProfile.getCurrentActionFamily()) && !roleScopeProfile.getExpectedActionFamilies().isEmpty()) {
                facts.add("Current action family present in expected role-scope evidence: "
                        + containsIgnoreCase(roleScopeProfile.getExpectedActionFamilies(), roleScopeProfile.getCurrentActionFamily()));
            }
            if (Boolean.TRUE.equals(roleScopeProfile.getTemporaryElevation())) {
                facts.add("Temporary elevation is active");
            }
            if (StringUtils.hasText(roleScopeProfile.getElevationWindowSummary())) {
                facts.add(roleScopeProfile.getElevationWindowSummary());
            }
            if (!facts.isEmpty()) {
                return String.join(" | ", facts);
            }
            if (StringUtils.hasText(roleScopeProfile.getSummary())) {
                return roleScopeProfile.getSummary();
            }
        }
        return firstNonBlank(extractText(eventMetadata, "roleDriftSummary"), extractText(eventMetadata, "roleScopeSummary"));
    }

    private String resolveApprovalSummary(CanonicalSecurityContext canonicalSecurityContext, Map<String, Object> eventMetadata) {
        if (canonicalSecurityContext != null && canonicalSecurityContext.getFrictionProfile() != null) {
            CanonicalSecurityContext.FrictionProfile frictionProfile = canonicalSecurityContext.getFrictionProfile();
            if (StringUtils.hasText(frictionProfile.getSummary())) {
                return frictionProfile.getSummary();
            }
            List<String> facts = new ArrayList<>();
            if (frictionProfile.getApprovalRequired() != null) {
                facts.add("Approval required: " + frictionProfile.getApprovalRequired());
            }
            if (StringUtils.hasText(frictionProfile.getApprovalStatus())) {
                facts.add("Approval status: " + frictionProfile.getApprovalStatus());
            }
            if (frictionProfile.getApprovalMissing() != null) {
                facts.add("Approval missing: " + frictionProfile.getApprovalMissing());
            }
            if (!frictionProfile.getApprovalLineage().isEmpty()) {
                facts.add("Approval lineage: " + String.join(", ", frictionProfile.getApprovalLineage()));
            }
            if (StringUtils.hasText(frictionProfile.getApprovalTicketId())) {
                facts.add("Approval ticket: " + frictionProfile.getApprovalTicketId());
            }
            if (!facts.isEmpty()) {
                return String.join(" | ", facts);
            }
        }
        return firstNonBlank(extractText(eventMetadata, "approvalSummary"), extractText(eventMetadata, "frictionProfileSummary"));
    }

    private String resolveObjectiveDriftSummary(CanonicalSecurityContext canonicalSecurityContext, Map<String, Object> eventMetadata) {
        if (canonicalSecurityContext != null
                && canonicalSecurityContext.getDelegation() != null
                && StringUtils.hasText(canonicalSecurityContext.getDelegation().getObjectiveDriftSummary())) {
            return canonicalSecurityContext.getDelegation().getObjectiveDriftSummary();
        }
        return firstNonBlank(
                extractText(eventMetadata, "objectiveDriftSummary"),
                extractText(eventMetadata, "delegationObjectiveDriftSummary"));
    }

    private String firstNonBlank(String... values) {
        if (values == null) {
            return null;
        }
        for (String value : values) {
            if (StringUtils.hasText(value)) {
                return value.trim();
            }
        }
        return null;
    }

    private String extractText(Map<String, Object> source, String key) {
        Object value = source.get(key);
        if (value == null) {
            return null;
        }
        String text = String.valueOf(value).trim();
        return text.isBlank() ? null : text;
    }

    private boolean extractBoolean(Map<String, Object> source, String key) {
        Object value = source.get(key);
        if (value instanceof Boolean bool) {
            return bool;
        }
        if (value instanceof String text) {
            return Boolean.parseBoolean(text);
        }
        return false;
    }

    private double extractDouble(Map<String, Object> source, String key) {
        Object value = source.get(key);
        if (value instanceof Number number) {
            return number.doubleValue();
        }
        if (value instanceof String text && !text.isBlank()) {
            try {
                return Double.parseDouble(text.trim());
            }
            catch (NumberFormatException ignored) {
                return 0.0d;
            }
        }
        return 0.0d;
    }

    private Integer extractInteger(Map<String, Object> source, String key) {
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

    private Long extractLong(Map<String, Object> source, String key) {
        Object value = source.get(key);
        if (value instanceof Number number) {
            return number.longValue();
        }
        if (value instanceof String text && !text.isBlank()) {
            try {
                return Long.parseLong(text.trim());
            }
            catch (NumberFormatException ignored) {
                return null;
            }
        }
        return null;
    }

    @SuppressWarnings("unchecked")
    private Map<String, Object> extractMap(Object value) {
        if (value instanceof Map<?, ?> map) {
            Map<String, Object> copied = new LinkedHashMap<>();
            map.forEach((key, mapValue) -> copied.put(String.valueOf(key), mapValue));
            return Map.copyOf(copied);
        }
        return Map.of();
    }

    @SuppressWarnings("unchecked")
    private List<String> extractStringList(Object value) {
        if (value instanceof List<?> list) {
            return list.stream()
                    .filter(Objects::nonNull)
                    .map(String::valueOf)
                    .map(String::trim)
                    .filter(text -> !text.isBlank())
                    .distinct()
                    .toList();
        }
        return List.of();
    }

    private List<String> copyList(List<String> values) {
        if (values == null || values.isEmpty()) {
            return List.of();
        }
        return List.copyOf(values);
    }

    private boolean containsIgnoreCase(List<String> values, String target) {
        if (!StringUtils.hasText(target) || values == null || values.isEmpty()) {
            return false;
        }
        for (String value : values) {
            if (StringUtils.hasText(value) && target.equalsIgnoreCase(value.trim())) {
                return true;
            }
        }
        return false;
    }
}


