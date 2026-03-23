package io.contexa.contexacore.autonomous.saas.mapper;

import io.contexa.contexacore.autonomous.domain.SecurityEvent;
import io.contexa.contexacore.autonomous.domain.SecurityEventContext;
import io.contexa.contexacore.autonomous.processor.ProcessingResult;
import io.contexa.contexacore.autonomous.saas.dto.SecurityDecisionForwardingPayload;
import io.contexa.contexacore.autonomous.saas.security.TenantScopedPseudonymizationService;
import io.contexa.contexacore.autonomous.saas.threat.ThreatSignalNormalizationService;
import io.contexa.contexacore.properties.SaasForwardingProperties;

import java.time.LocalDateTime;
import java.util.*;

public class SecurityDecisionForwardingPayloadMapper {

    private static final String DEFAULT_TENANT_SCOPE = "default";

    private final TenantScopedPseudonymizationService pseudonymizationService;
    private final ThreatSignalNormalizationService threatSignalNormalizationService;
    private final SaasForwardingProperties properties;

    public SecurityDecisionForwardingPayloadMapper(
            TenantScopedPseudonymizationService pseudonymizationService,
            ThreatSignalNormalizationService threatSignalNormalizationService,
            SaasForwardingProperties properties) {
        this.pseudonymizationService = pseudonymizationService;
        this.threatSignalNormalizationService = threatSignalNormalizationService;
        this.properties = properties;
    }

    public SecurityDecisionForwardingPayload map(SecurityEventContext context) {
        SecurityEvent event = context.getSecurityEvent();
        ProcessingResult result = requireResult(context);
        Map<String, Object> eventMetadata = event.getMetadata() != null ? event.getMetadata() : Map.of();
        Map<String, Object> analysisData = result.getAnalysisData() != null ? result.getAnalysisData() : Map.of();
        String tenantScope = resolveTenantScope(eventMetadata);
        ThreatSignalNormalizationService.NormalizedThreatSignal threatSignal =
                threatSignalNormalizationService.normalize(event, result);

        return SecurityDecisionForwardingPayload.builder()
                .correlationId(resolveCorrelationId(event, context))
                .decision(result.getAction())
                .aiAnalysisLevel(result.getAiAnalysisLevel())
                .processingTimeMs(result.getProcessingTimeMs())
                .reasoning(properties.isIncludeReasoning() ? result.getReasoning() : null)
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
                .evidenceList(extractEvidence(result, analysisData))
                .mitreTacticHints(threatSignal.mitreTacticHints())
                .targetSurfaceCategory(threatSignal.targetSurfaceCategory())
                .signalTags(threatSignal.signalTags())
                .legitimateHypothesis(extractText(analysisData, "legitimateHypothesis"))
                .suspiciousHypothesis(extractText(analysisData, "suspiciousHypothesis"))
                .requestPath(extractRequestPath(eventMetadata))
                .geoCountry(extractText(eventMetadata, "geoCountry"))
                .geoCity(extractText(eventMetadata, "geoCity"))
                .newDevice(extractBoolean(eventMetadata, "isNewDevice"))
                .impossibleTravel(extractBoolean(eventMetadata, "isImpossibleTravel"))
                .travelDistanceKm(extractDouble(eventMetadata, "travelDistanceKm"))
                .layer1Assessment(extractMap(analysisData.get("layer1Assessment")))
                .layer2Assessment(extractMap(analysisData.get("layer2Assessment")))
                .attributes(extractAttributes(eventMetadata, analysisData))
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

    private List<String> extractEvidence(ProcessingResult result, Map<String, Object> analysisData) {
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

    private String extractRequestPath(Map<String, Object> eventMetadata) {
        String direct = extractText(eventMetadata, "requestPath");
        if (direct != null && !direct.isBlank()) {
            return direct;
        }
        return extractText(eventMetadata, "requestUri");
    }

    private Map<String, Object> extractAttributes(Map<String, Object> eventMetadata, Map<String, Object> analysisData) {
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
        copyIfPresent(eventMetadata, attributes, "parameter_risk_flags");
        copyIfPresent(eventMetadata, attributes, "prompt_risk_flags");
        copyIfPresent(eventMetadata, attributes, "tool_arguments_summary");
        copyIfPresent(analysisData, attributes, "parameterRiskFlags");
        copyIfPresent(analysisData, attributes, "promptRiskFlags");
        copyIfPresent(analysisData, attributes, "toolArgumentsSummary");
        return attributes.isEmpty() ? Map.of() : Map.copyOf(attributes);
    }

    private void copyIfPresent(Map<String, Object> source, Map<String, Object> target, String key) {
        Object value = source.get(key);
        if (value != null) {
            target.put(key, value);
        }
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
}
