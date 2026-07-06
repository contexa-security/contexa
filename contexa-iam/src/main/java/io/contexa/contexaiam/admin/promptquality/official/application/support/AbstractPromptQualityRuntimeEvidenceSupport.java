package io.contexa.contexaiam.admin.promptquality.official.application.support;

import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.core.JsonToken;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.contexa.contexacore.verification.evidence.SealedEvidencePackage;
import io.contexa.contexaiam.admin.promptquality.official.common.PromptQualityMessageResolver;
import io.contexa.contexaiam.admin.promptquality.official.model.RuntimeEvidenceMissingKnowledgeSignal;
import org.springframework.util.StringUtils;

import java.text.MessageFormat;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
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
            "promptContractVersion",
            "modelProfile",
            "promptCompressionApplied",
            "compressionApplied",
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

    protected AbstractPromptQualityRuntimeEvidenceSupport(ObjectMapper objectMapper) {
        this(objectMapper, null);
    }

    protected AbstractPromptQualityRuntimeEvidenceSupport(
            ObjectMapper objectMapper,
            PromptQualityMessageResolver messageResolver) {
        this.objectMapper = objectMapper;
        this.messageResolver = messageResolver;
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
                    "Explicit missing knowledge section is present.",
                    "enterprise.pqa.runtimeEvidence.signal.explicitMissingKnowledge.rule",
                    "The LLM user prompt contains the section marker ''=== EXPLICIT MISSING KNOWLEDGE''.",
                    "enterprise.pqa.runtimeEvidence.signal.explicitMissingKnowledge.evidence",
                    "Matched marker: === EXPLICIT MISSING KNOWLEDGE",
                    "enterprise.pqa.runtimeEvidence.signal.explicitMissingKnowledge.explanation",
                    "The prompt itself declares that some context required for judgment is missing.",
                    "enterprise.pqa.runtimeEvidence.signal.explicitMissingKnowledge.impact",
                    "The request can still be inspected, but a confident allow decision must not ignore this declared uncertainty.",
                    "enterprise.pqa.runtimeEvidence.signal.explicitMissingKnowledge.next",
                    "Open official quality inspection, confirm which context producer omitted the facts, then fix the request or learning context source.",
                    "userPromptText"));
        }
        if (upper.contains("MISSINGCRITICALFACTS") && !upper.contains("MISSINGCRITICALFACTS: []")) {
            signals.add(missingSignal(
                    "MISSING_CRITICAL_FACTS_DECLARED",
                    "enterprise.pqa.runtimeEvidence.signal.missingCriticalFacts",
                    "Critical missing facts are declared.",
                    "enterprise.pqa.runtimeEvidence.signal.missingCriticalFacts.rule",
                    "The prompt contains missingCriticalFacts and the value is not an empty list.",
                    "enterprise.pqa.runtimeEvidence.signal.missingCriticalFacts.evidence",
                    "Matched field: missingCriticalFacts is not empty",
                    "enterprise.pqa.runtimeEvidence.signal.missingCriticalFacts.explanation",
                    "The prompt names facts that are important for the LLM decision but were not supplied.",
                    "enterprise.pqa.runtimeEvidence.signal.missingCriticalFacts.impact",
                    "The official inspection must identify whether the missing facts belong to request context, RAG, baseline, or authorization data.",
                    "enterprise.pqa.runtimeEvidence.signal.missingCriticalFacts.next",
                    "Use the prompt comparison and official metric detail to map each missing fact to its producer and remediation action.",
                    "userPromptText"));
        }
        if (upper.contains("CURRENTACCESSHOURPRESENTINOBSERVEDHOURS: FALSE")) {
            signals.add(missingSignal(
                    "ACCESS_HOUR_OUTSIDE_OBSERVED_HOURS",
                    "enterprise.pqa.runtimeEvidence.signal.accessHourOutsideObserved",
                    "Current access hour is outside observed working hours.",
                    "enterprise.pqa.runtimeEvidence.signal.accessHourOutsideObserved.rule",
                    "The prompt contains currentAccessHourPresentInObservedHours: false.",
                    "enterprise.pqa.runtimeEvidence.signal.accessHourOutsideObserved.evidence",
                    "Matched field: currentAccessHourPresentInObservedHours=false",
                    "enterprise.pqa.runtimeEvidence.signal.accessHourOutsideObserved.explanation",
                    "The current request time does not match the user's observed normal access-hour baseline.",
                    "enterprise.pqa.runtimeEvidence.signal.accessHourOutsideObserved.impact",
                    "This is not automatically malicious, but the LLM must treat it as a context gap or anomaly until the baseline is confirmed.",
                    "enterprise.pqa.runtimeEvidence.signal.accessHourOutsideObserved.next",
                    "Check whether the baseline is incomplete, the user has a valid exception, or the request should require challenge.",
                    "userPromptText"));
        }
        if (upper.contains("CURRENTNETWORKPRESENTINOBSERVEDNETWORKS: FALSE")) {
            signals.add(missingSignal(
                    "NETWORK_OUTSIDE_OBSERVED_NETWORKS",
                    "enterprise.pqa.runtimeEvidence.signal.networkOutsideObserved",
                    "Current network is outside observed networks.",
                    "enterprise.pqa.runtimeEvidence.signal.networkOutsideObserved.rule",
                    "The prompt contains currentNetworkPresentInObservedNetworks: false.",
                    "enterprise.pqa.runtimeEvidence.signal.networkOutsideObserved.evidence",
                    "Matched field: currentNetworkPresentInObservedNetworks=false",
                    "enterprise.pqa.runtimeEvidence.signal.networkOutsideObserved.explanation",
                    "The current request network does not match the user's observed network baseline.",
                    "enterprise.pqa.runtimeEvidence.signal.networkOutsideObserved.impact",
                    "This is a baseline mismatch signal, not a missing-fact conclusion; official inspection must decide whether the baseline or request context needs reinforcement.",
                    "enterprise.pqa.runtimeEvidence.signal.networkOutsideObserved.next",
                    "Confirm observed-network coverage, trusted network classification, and whether a legitimate exception should be recorded.",
                    "userPromptText"));
        }
        if (upper.contains("CURRENTBROWSERPRESENTINOBSERVEDBROWSERS: FALSE")) {
            signals.add(missingSignal(
                    "BROWSER_OUTSIDE_OBSERVED_BROWSERS",
                    "enterprise.pqa.runtimeEvidence.signal.browserOutsideObserved",
                    "Current browser is outside observed browsers.",
                    "enterprise.pqa.runtimeEvidence.signal.browserOutsideObserved.rule",
                    "The prompt contains currentBrowserPresentInObservedBrowsers: false.",
                    "enterprise.pqa.runtimeEvidence.signal.browserOutsideObserved.evidence",
                    "Matched field: currentBrowserPresentInObservedBrowsers=false",
                    "enterprise.pqa.runtimeEvidence.signal.browserOutsideObserved.explanation",
                    "The browser evidence does not match the user's observed browser baseline.",
                    "enterprise.pqa.runtimeEvidence.signal.browserOutsideObserved.impact",
                    "This indicates baseline drift or incomplete learning context; it is not a standalone authorization defect.",
                    "enterprise.pqa.runtimeEvidence.signal.browserOutsideObserved.next",
                    "Check browser baseline collection, device fingerprint continuity, and whether the observed profile should be updated.",
                    "userPromptText"));
        }
        if (upper.contains("CURRENTREQUESTCOMBINATIONEVIDENCESCOPE: NO_DIRECT_PERSONAL_COMPARABLE")) {
            signals.add(missingSignal(
                    "NO_DIRECT_PERSONAL_COMPARABLE",
                    "enterprise.pqa.runtimeEvidence.signal.noDirectPersonalComparable",
                    "No direct personal comparable request exists.",
                    "enterprise.pqa.runtimeEvidence.signal.noDirectPersonalComparable.rule",
                    "The prompt contains currentRequestCombinationEvidenceScope: NO_DIRECT_PERSONAL_COMPARABLE.",
                    "enterprise.pqa.runtimeEvidence.signal.noDirectPersonalComparable.evidence",
                    "Matched field: currentRequestCombinationEvidenceScope=NO_DIRECT_PERSONAL_COMPARABLE",
                    "enterprise.pqa.runtimeEvidence.signal.noDirectPersonalComparable.explanation",
                    "The exact request combination was not found in the user's personal comparable history.",
                    "enterprise.pqa.runtimeEvidence.signal.noDirectPersonalComparable.impact",
                    "The prompt can still be inspected, but the baseline cannot prove that this specific combination is normal.",
                    "enterprise.pqa.runtimeEvidence.signal.noDirectPersonalComparable.next",
                    "Confirm whether comparable-history collection is immature or whether this request requires a new approved baseline sample.",
                    "userPromptText"));
        }
        if (upper.contains("WORKPROFILEEVIDENCESTATE: PROVISIONAL")) {
            signals.add(missingSignal(
                    "WORK_PROFILE_EVIDENCE_PROVISIONAL",
                    "enterprise.pqa.runtimeEvidence.signal.workProfileProvisional",
                    "Work profile evidence is marked provisional.",
                    "enterprise.pqa.runtimeEvidence.signal.workProfileProvisional.rule",
                    "The prompt contains workProfileEvidenceState: PROVISIONAL.",
                    "enterprise.pqa.runtimeEvidence.signal.workProfileProvisional.evidence",
                    "Matched field: workProfileEvidenceState=PROVISIONAL",
                    "enterprise.pqa.runtimeEvidence.signal.workProfileProvisional.explanation",
                    "The personal work profile was assembled from a learning or not-yet-final baseline.",
                    "enterprise.pqa.runtimeEvidence.signal.workProfileProvisional.impact",
                    "Official inspection must separate acceptable learning-state uncertainty from a prompt quality defect.",
                    "enterprise.pqa.runtimeEvidence.signal.workProfileProvisional.next",
                    "Check baseline observation count, days covered, fallback ratio, and whether more learning samples are required.",
                    "userPromptText"));
        }
        if (upper.contains("ROLESCOPEEVIDENCESTATE: PROVISIONAL")) {
            signals.add(missingSignal(
                    "ROLE_SCOPE_EVIDENCE_PROVISIONAL",
                    "enterprise.pqa.runtimeEvidence.signal.roleScopeProvisional",
                    "Role scope evidence is marked provisional.",
                    "enterprise.pqa.runtimeEvidence.signal.roleScopeProvisional.rule",
                    "The prompt contains roleScopeEvidenceState: PROVISIONAL.",
                    "enterprise.pqa.runtimeEvidence.signal.roleScopeProvisional.evidence",
                    "Matched field: roleScopeEvidenceState=PROVISIONAL",
                    "enterprise.pqa.runtimeEvidence.signal.roleScopeProvisional.explanation",
                    "Role and permission scope evidence was assembled with a temporary or not-yet-confirmed basis.",
                    "enterprise.pqa.runtimeEvidence.signal.roleScopeProvisional.impact",
                    "If the LLM treats provisional role evidence as final authority, authorization reasoning can be overstated.",
                    "enterprise.pqa.runtimeEvidence.signal.roleScopeProvisional.next",
                    "Confirm IAM role, permission, and delegation evidence capture before promoting this resource.",
                    "userPromptText"));
        }
        if (upper.contains("UNKNOWN") || upper.contains("INSUFFICIENT")) {
            signals.add(missingSignal(
                    "UNKNOWN_OR_INSUFFICIENT_EVIDENCE",
                    "enterprise.pqa.runtimeEvidence.signal.unknownOrInsufficient",
                    "Unknown or insufficient evidence signal is present.",
                    "enterprise.pqa.runtimeEvidence.signal.unknownOrInsufficient.rule",
                    "The prompt contains UNKNOWN or INSUFFICIENT, which are reserved uncertainty markers.",
                    "enterprise.pqa.runtimeEvidence.signal.unknownOrInsufficient.evidence",
                    upper.contains("UNKNOWN") ? "Matched marker: UNKNOWN" : "Matched marker: INSUFFICIENT",
                    "enterprise.pqa.runtimeEvidence.signal.unknownOrInsufficient.explanation",
                    "At least one prompt section says the evidence is unknown or not enough for a fully grounded decision.",
                    "enterprise.pqa.runtimeEvidence.signal.unknownOrInsufficient.impact",
                    "The quality process must verify that this uncertainty is reflected in decision confidence and action.",
                    "enterprise.pqa.runtimeEvidence.signal.unknownOrInsufficient.next",
                    "Compare the prompt, sealed evidence, and official metric result to determine whether the missing source must be fixed.",
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
            String titleFallback,
            String ruleKey,
            String ruleFallback,
            String evidenceKey,
            String evidenceFallback,
            String explanationKey,
            String explanationFallback,
            String impactKey,
            String impactFallback,
            String nextActionKey,
            String nextActionFallback,
            String source) {
        String category = signalCategory(code);
        return new RuntimeEvidenceMissingKnowledgeSignal(
                code,
                category,
                message("enterprise.pqa.runtimeEvidence.signal.category." + category, category),
                message("enterprise.pqa.runtimeEvidence.signal.category." + category + ".description", ""),
                message(titleKey, titleFallback),
                message(ruleKey, ruleFallback),
                message(evidenceKey, evidenceFallback),
                message(explanationKey, explanationFallback),
                message(impactKey, impactFallback),
                message(nextActionKey, nextActionFallback),
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

    protected String message(String key, String fallback, Object... args) {
        if (messageResolver == null) {
            return args == null || args.length == 0 ? fallback : MessageFormat.format(fallback, args);
        }
        String resolved = messageResolver.resolve(key, args);
        if (!StringUtils.hasText(resolved) || key.equals(resolved)) {
            return args == null || args.length == 0 ? fallback : MessageFormat.format(fallback, args);
        }
        return resolved;
    }
}

