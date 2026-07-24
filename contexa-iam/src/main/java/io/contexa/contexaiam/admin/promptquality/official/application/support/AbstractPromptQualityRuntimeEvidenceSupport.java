package io.contexa.contexaiam.admin.promptquality.official.application.support;

import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.core.JsonToken;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.contexa.contexacore.verification.evidence.SealedEvidencePackage;
import io.contexa.contexaiam.admin.promptquality.official.common.PromptQualityMessageResolver;
import io.contexa.contexaiam.admin.promptquality.official.model.RuntimeEvidenceMissingKnowledgeSignal;
import org.springframework.util.StringUtils;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.stream.Collectors;

public abstract class AbstractPromptQualityRuntimeEvidenceSupport {

    private static final TypeReference<Map<String, Object>> MAP_TYPE = new TypeReference<>() {};
    private static final int PROMPT_PREVIEW_LIMIT = 900;
    private static final Set<String> PROMPT_EXECUTION_METADATA_HEADER_KEYS = Set.of(
            "requestId",
            "correlationId",
            "promptHash",
            "systemPromptHash",
            "userPromptHash",
            "contextHash",
            "protectableResourceId",
            "resourceId",
            "endpointKey",
            "governanceDescriptor",
            "promptContractVersion",
            "modelProfile",
            "promptCompressionApplied",
            "compressionApplied",
            "promptCompressionLedger",
            "promptSourceContextLedgerStoragePolicy",
            "promptFieldStateLedgerStoragePolicy",
            "promptRawUserFieldLedgerStoragePolicy",
            "promptFinalUserFieldLedgerStoragePolicy",
            "promptUserFieldDiffLedgerStoragePolicy",
            "promptSourceContextLedgerOmittedCount",
            "promptFieldStateLedgerOmittedCount",
            "promptRawUserFieldLedgerOmittedCount",
            "promptFinalUserFieldLedgerOmittedCount",
            "promptUserFieldDiffLedgerOmittedCount");

    protected final ObjectMapper objectMapper;
    protected final PromptQualityMessageResolver messageResolver;

    protected AbstractPromptQualityRuntimeEvidenceSupport(
            ObjectMapper objectMapper,
            PromptQualityMessageResolver messageResolver) {
        this.objectMapper = Objects.requireNonNull(objectMapper, "objectMapper");
        this.messageResolver = Objects.requireNonNull(messageResolver, "messageResolver");
    }

    protected Map<String, Object> parseJson(String json) {
        if (!StringUtils.hasText(json)) {
            return Map.of();
        }
        try {
            Map<String, Object> parsed = objectMapper.readValue(json, MAP_TYPE);
            return parsed == null ? Map.of() : parsed;
        }
        catch (Exception ignored) {
            return Map.of();
        }
    }


    protected Map<String, Object> parsePromptExecutionMetadataHeader(String json) {
        if (!StringUtils.hasText(json)) {
            return Map.of();
        }
        Map<String, Object> result = new LinkedHashMap<>();
        try (JsonParser parser = objectMapper.getFactory().createParser(json)) {
            if (parser.nextToken() != JsonToken.START_OBJECT) {
                return Map.of();
            }
            while (parser.nextToken() != JsonToken.END_OBJECT) {
                if (parser.currentToken() != JsonToken.FIELD_NAME) {
                    parser.skipChildren();
                    continue;
                }
                String key = parser.currentName();
                JsonToken valueToken = parser.nextToken();
                if (!PROMPT_EXECUTION_METADATA_HEADER_KEYS.contains(key)) {
                    parser.skipChildren();
                    continue;
                }
                if (valueToken == JsonToken.VALUE_STRING) {
                    result.put(key, parser.getValueAsString());
                }
                else if (valueToken == JsonToken.VALUE_NUMBER_INT || valueToken == JsonToken.VALUE_NUMBER_FLOAT) {
                    result.put(key, parser.getNumberValue());
                }
                else if (valueToken == JsonToken.VALUE_TRUE || valueToken == JsonToken.VALUE_FALSE) {
                    result.put(key, parser.getBooleanValue());
                }
                else if (valueToken == JsonToken.VALUE_NULL) {
                    result.put(key, null);
                }
                else if ("promptCompressionLedger".equals(key) && valueToken == JsonToken.START_ARRAY) {
                    result.put(key, objectMapper.readValue(parser, List.class));
                }
                else if ("governanceDescriptor".equals(key) && valueToken == JsonToken.START_OBJECT) {
                    result.put(key, objectMapper.readValue(parser, Map.class));
                }
                else {
                    parser.skipChildren();
                }
            }
            return result;
        }
        catch (Exception ignored) {
            return Map.of();
        }
    }
    protected Map<String, String> stringMap(Map<String, Object> source) {
        Map<String, String> result = new LinkedHashMap<>();
        if (source == null) {
            return result;
        }
        source.forEach((key, value) -> result.put(key, value == null ? "" : String.valueOf(value)));
        return result;
    }

    protected String text(Map<String, Object> map, String key) {
        if (map == null || !map.containsKey(key)) {
            return null;
        }
        Object value = map.get(key);
        if (value == null) {
            return null;
        }
        String normalized = String.valueOf(value).trim();
        return normalized.isEmpty() ? null : normalized;
    }

    protected Double doubleValue(Map<String, Object> map, String key) {
        if (map == null || !map.containsKey(key)) {
            return null;
        }
        Object value = map.get(key);
        if (value instanceof Number number) {
            return number.doubleValue();
        }
        try {
            return value == null ? null : Double.parseDouble(String.valueOf(value));
        }
        catch (NumberFormatException ignored) {
            return null;
        }
    }

    protected String firstNonBlank(String... values) {
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

    protected String requestPath(SealedEvidencePackage pkg, Map<String, Object> requestFacts) {
        return firstNonBlank(
                text(requestFacts, "requestPath"),
                text(requestFacts, "resourceUrl"),
                text(requestFacts, "path"),
                text(requestFacts, "uri"));
    }

    protected String resourceId(SealedEvidencePackage pkg, Map<String, Object> requestFacts, Map<String, Object> promptMetadata) {
        return firstNonBlank(
                text(requestFacts, "protectableResourceId"),
                text(promptMetadata, "protectableResourceId"),
                text(requestFacts, "resourceId"),
                text(requestFacts, "endpointKey"),
                text(promptMetadata, "resourceId"),
                text(promptMetadata, "endpointKey"),
                pkg != null ? pkg.getPackageId() : null);
    }

    protected String httpMethod(Map<String, Object> requestFacts) {
        return normalizeHttpMethod(firstNonBlank(text(requestFacts, "httpMethod"), text(requestFacts, "method"), "GET"));
    }

    private String normalizeHttpMethod(String value) {
        return StringUtils.hasText(value) ? value.trim().toUpperCase(Locale.ROOT) : "GET";
    }

    protected String decisionAction(Map<String, Object> decision) {
        return firstNonBlank(text(decision, "action"), text(decision, "decisionAction"));
    }

    protected Double decisionConfidence(Map<String, Object> decision) {
        Double confidence = doubleValue(decision, "confidence");
        return confidence != null ? confidence : doubleValue(decision, "decisionConfidence");
    }

    protected String promptPreview(String value) {
        if (!StringUtils.hasText(value)) {
            return "";
        }
        String normalized = value.trim();
        return normalized.length() <= PROMPT_PREVIEW_LIMIT
                ? normalized
                : normalized.substring(0, PROMPT_PREVIEW_LIMIT) + "\n...";
    }

    protected int promptTextLength(SealedEvidencePackage pkg) {
        if (pkg == null) {
            return 0;
        }
        int systemLength = pkg.getSystemPromptText() == null ? 0 : pkg.getSystemPromptText().length();
        int userLength = pkg.getUserPromptText() == null ? 0 : pkg.getUserPromptText().length();
        return systemLength + userLength;
    }

    protected boolean hasText(String value) {
        return StringUtils.hasText(value);
    }

    protected List<String> missingKnowledgeSignals(SealedEvidencePackage pkg) {
        return missingKnowledgeSignalDetails(pkg).stream()
                .map(RuntimeEvidenceMissingKnowledgeSignal::title)
                .distinct()
                .toList();
    }

    protected List<RuntimeEvidenceMissingKnowledgeSignal> missingKnowledgeSignalDetails(SealedEvidencePackage pkg) {
        String prompt = pkg == null ? "" : firstNonBlank(pkg.getUserPromptText(), pkg.getRawUserPrompt(), "");
        prompt = prompt == null ? "" : prompt;
        String upper = prompt.toUpperCase(Locale.ROOT);
        List<RuntimeEvidenceMissingKnowledgeSignal> signals = new ArrayList<>();
        if (upper.contains("=== EXPLICIT MISSING KNOWLEDGE")) {
            signals.add(missingSignal(
                    "EXPLICIT_MISSING_KNOWLEDGE_SECTION",
                    "enterprise.pqa.runtimeEvidence.signal.explicitMissingKnowledge",
                    "enterprise.pqa.runtimeEvidence.signal.explicitMissingKnowledge.rule",
                    "enterprise.pqa.runtimeEvidence.signal.explicitMissingKnowledge.evidence",
                    "enterprise.pqa.runtimeEvidence.signal.explicitMissingKnowledge.explanation",
                    "enterprise.pqa.runtimeEvidence.signal.explicitMissingKnowledge.impact",
                    "enterprise.pqa.runtimeEvidence.signal.explicitMissingKnowledge.next",
                    "userPromptText"));
        }
        if (upper.contains("MISSINGCRITICALFACTS") && !upper.contains("MISSINGCRITICALFACTS: []")) {
            signals.add(missingSignal(
                    "MISSING_CRITICAL_FACTS_DECLARED",
                    "enterprise.pqa.runtimeEvidence.signal.missingCriticalFacts",
                    "enterprise.pqa.runtimeEvidence.signal.missingCriticalFacts.rule",
                    "enterprise.pqa.runtimeEvidence.signal.missingCriticalFacts.evidence",
                    "enterprise.pqa.runtimeEvidence.signal.missingCriticalFacts.explanation",
                    "enterprise.pqa.runtimeEvidence.signal.missingCriticalFacts.impact",
                    "enterprise.pqa.runtimeEvidence.signal.missingCriticalFacts.next",
                    "userPromptText"));
        }
        if (upper.contains("CURRENTACCESSHOURPRESENTINOBSERVEDHOURS: FALSE")) {
            signals.add(missingSignal(
                    "ACCESS_HOUR_OUTSIDE_OBSERVED_HOURS",
                    "enterprise.pqa.runtimeEvidence.signal.accessHourOutsideObserved",
                    "enterprise.pqa.runtimeEvidence.signal.accessHourOutsideObserved.rule",
                    "enterprise.pqa.runtimeEvidence.signal.accessHourOutsideObserved.evidence",
                    "enterprise.pqa.runtimeEvidence.signal.accessHourOutsideObserved.explanation",
                    "enterprise.pqa.runtimeEvidence.signal.accessHourOutsideObserved.impact",
                    "enterprise.pqa.runtimeEvidence.signal.accessHourOutsideObserved.next",
                    "userPromptText"));
        }
        if (upper.contains("CURRENTNETWORKPRESENTINOBSERVEDNETWORKS: FALSE")) {
            signals.add(missingSignal(
                    "NETWORK_OUTSIDE_OBSERVED_NETWORKS",
                    "enterprise.pqa.runtimeEvidence.signal.networkOutsideObserved",
                    "enterprise.pqa.runtimeEvidence.signal.networkOutsideObserved.rule",
                    "enterprise.pqa.runtimeEvidence.signal.networkOutsideObserved.evidence",
                    "enterprise.pqa.runtimeEvidence.signal.networkOutsideObserved.explanation",
                    "enterprise.pqa.runtimeEvidence.signal.networkOutsideObserved.impact",
                    "enterprise.pqa.runtimeEvidence.signal.networkOutsideObserved.next",
                    "userPromptText"));
        }
        if (upper.contains("CURRENTBROWSERPRESENTINOBSERVEDBROWSERS: FALSE")) {
            signals.add(missingSignal(
                    "BROWSER_OUTSIDE_OBSERVED_BROWSERS",
                    "enterprise.pqa.runtimeEvidence.signal.browserOutsideObserved",
                    "enterprise.pqa.runtimeEvidence.signal.browserOutsideObserved.rule",
                    "enterprise.pqa.runtimeEvidence.signal.browserOutsideObserved.evidence",
                    "enterprise.pqa.runtimeEvidence.signal.browserOutsideObserved.explanation",
                    "enterprise.pqa.runtimeEvidence.signal.browserOutsideObserved.impact",
                    "enterprise.pqa.runtimeEvidence.signal.browserOutsideObserved.next",
                    "userPromptText"));
        }
        if (upper.contains("CURRENTREQUESTCOMBINATIONEVIDENCESCOPE: NO_DIRECT_PERSONAL_COMPARABLE")) {
            signals.add(missingSignal(
                    "NO_DIRECT_PERSONAL_COMPARABLE",
                    "enterprise.pqa.runtimeEvidence.signal.noDirectPersonalComparable",
                    "enterprise.pqa.runtimeEvidence.signal.noDirectPersonalComparable.rule",
                    "enterprise.pqa.runtimeEvidence.signal.noDirectPersonalComparable.evidence",
                    "enterprise.pqa.runtimeEvidence.signal.noDirectPersonalComparable.explanation",
                    "enterprise.pqa.runtimeEvidence.signal.noDirectPersonalComparable.impact",
                    "enterprise.pqa.runtimeEvidence.signal.noDirectPersonalComparable.next",
                    "userPromptText"));
        }
        if (upper.contains("WORKPROFILEEVIDENCESTATE: PROVISIONAL")) {
            signals.add(missingSignal(
                    "WORK_PROFILE_EVIDENCE_PROVISIONAL",
                    "enterprise.pqa.runtimeEvidence.signal.workProfileProvisional",
                    "enterprise.pqa.runtimeEvidence.signal.workProfileProvisional.rule",
                    "enterprise.pqa.runtimeEvidence.signal.workProfileProvisional.evidence",
                    "enterprise.pqa.runtimeEvidence.signal.workProfileProvisional.explanation",
                    "enterprise.pqa.runtimeEvidence.signal.workProfileProvisional.impact",
                    "enterprise.pqa.runtimeEvidence.signal.workProfileProvisional.next",
                    "userPromptText"));
        }
        if (upper.contains("ROLESCOPEEVIDENCESTATE: PROVISIONAL")) {
            signals.add(missingSignal(
                    "ROLE_SCOPE_EVIDENCE_PROVISIONAL",
                    "enterprise.pqa.runtimeEvidence.signal.roleScopeProvisional",
                    "enterprise.pqa.runtimeEvidence.signal.roleScopeProvisional.rule",
                    "enterprise.pqa.runtimeEvidence.signal.roleScopeProvisional.evidence",
                    "enterprise.pqa.runtimeEvidence.signal.roleScopeProvisional.explanation",
                    "enterprise.pqa.runtimeEvidence.signal.roleScopeProvisional.impact",
                    "enterprise.pqa.runtimeEvidence.signal.roleScopeProvisional.next",
                    "userPromptText"));
        }
        if (upper.contains("UNKNOWN") || upper.contains("INSUFFICIENT")) {
            signals.add(missingSignal(
                    "UNKNOWN_OR_INSUFFICIENT_EVIDENCE",
                    "enterprise.pqa.runtimeEvidence.signal.unknownOrInsufficient",
                    "enterprise.pqa.runtimeEvidence.signal.unknownOrInsufficient.rule",
                    "enterprise.pqa.runtimeEvidence.signal.unknownOrInsufficient.evidence",
                    "enterprise.pqa.runtimeEvidence.signal.unknownOrInsufficient.explanation",
                    "enterprise.pqa.runtimeEvidence.signal.unknownOrInsufficient.impact",
                    "enterprise.pqa.runtimeEvidence.signal.unknownOrInsufficient.next",
                    "userPromptText"));
        }
        return signals.stream()
                .collect(Collectors.collectingAndThen(
                        Collectors.toMap(
                                RuntimeEvidenceMissingKnowledgeSignal::code,
                                signal -> signal,
                                (existing, ignored) -> existing,
                                LinkedHashMap::new),
                        map -> List.copyOf(map.values())));
    }

    private RuntimeEvidenceMissingKnowledgeSignal missingSignal(
            String code,
            String titleKey,
            String ruleKey,
            String evidenceKey,
            String explanationKey,
            String impactKey,
            String nextActionKey,
            String source) {
        String category = signalCategory(code);
        return new RuntimeEvidenceMissingKnowledgeSignal(
                code,
                category,
                message("enterprise.pqa.runtimeEvidence.signal.category." + category),
                message("enterprise.pqa.runtimeEvidence.signal.category." + category + ".description"),
                message(titleKey),
                message(ruleKey),
                message(evidenceKey),
                message(explanationKey),
                message(impactKey),
                message(nextActionKey),
                source);
    }

    private String signalCategory(String code) {
        return switch (code) {
            case "EXPLICIT_MISSING_KNOWLEDGE_SECTION", "MISSING_CRITICAL_FACTS_DECLARED" -> "MISSING_CONTEXT";
            case "ACCESS_HOUR_OUTSIDE_OBSERVED_HOURS",
                 "NETWORK_OUTSIDE_OBSERVED_NETWORKS",
                 "BROWSER_OUTSIDE_OBSERVED_BROWSERS",
                 "NO_DIRECT_PERSONAL_COMPARABLE" -> "BASELINE_MISMATCH";
            case "WORK_PROFILE_EVIDENCE_PROVISIONAL", "ROLE_SCOPE_EVIDENCE_PROVISIONAL" -> "PROVISIONAL_EVIDENCE";
            case "UNKNOWN_OR_INSUFFICIENT_EVIDENCE" -> "UNCERTAINTY_MARKER";
            default -> "OTHER";
        };
    }

    protected boolean highConfidenceAllow(Map<String, Object> decision) {
        String action = decisionAction(decision);
        Double confidence = decisionConfidence(decision);
        return action != null
                && "ALLOW".equalsIgnoreCase(action)
                && confidence != null
                && confidence >= 0.80d;
    }

    protected String normalizePath(String value) {
        if (!StringUtils.hasText(value)) {
            return "";
        }
        String normalized = value.trim();
        int queryIndex = normalized.indexOf('?');
        if (queryIndex >= 0) {
            normalized = normalized.substring(0, queryIndex);
        }
        while (normalized.endsWith("/") && normalized.length() > 1) {
            normalized = normalized.substring(0, normalized.length() - 1);
        }
        return normalized;
    }

    protected String message(String key, Object... args) {
        String resolved = messageResolver.resolve(key, args);
        if (!StringUtils.hasText(resolved) || key.equals(resolved)) {
            throw new IllegalStateException("Missing prompt-quality message key: " + key);
        }
        return resolved;
    }
}

