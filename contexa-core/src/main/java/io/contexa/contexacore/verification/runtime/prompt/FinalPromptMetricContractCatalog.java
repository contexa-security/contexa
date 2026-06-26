package io.contexa.contexacore.verification.runtime.prompt;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.util.StringUtils;

import java.io.IOException;
import java.io.InputStream;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;

public final class FinalPromptMetricContractCatalog {

    private static final String RESOURCE = "/pqa/final-prompt-metric-contracts.json";
    private static final String SIGNAL_RESOURCE = "/pqa/final-prompt-signal-contracts.json";
    private static final TypeReference<List<FinalPromptMetricContract>> CONTRACT_LIST = new TypeReference<>() {};
    private static final TypeReference<List<Map<String, String>>> SIGNAL_LIST = new TypeReference<>() {};
    private static final Set<String> RAW_PRESENCE_OPERATORS = Set.of(
            "SECTIONS_PRESENT",
            "FIELDS_PRESENT",
            "ANY_FIELD_PRESENT",
            "MIN_FIELDS_PRESENT");
    private static final Set<String> CUSTOMER_VISIBLE_FORBIDDEN_TERMS = Set.of(
            "컨텍스트 생산자",
            "생산자",
            "조립기",
            "정규화",
            "판단 한계",
            "확정 근거",
            "위임 목적",
            "승인·마찰",
            "final prompt",
            "final userPrompt",
            "prompt artifact",
            "canonical",
            "action sequence",
            "retrieved document",
            "evidence only");

    private final List<FinalPromptMetricContract> metrics;
    private final Map<String, FinalPromptMetricContract> metricsByCode;
    private final Map<String, FinalPromptMetricCheckContract> checksByCode;
    private final Map<String, String> promptLocationByLabel;
    private final Map<String, FinalPromptSignalDescriptor> signalDescriptorByLabel;
    private final List<PromptSignalContract> promptSignalContracts;
    private final Set<String> knownLabels;
    private final Set<String> knownSections;

    private FinalPromptMetricContractCatalog(
            List<FinalPromptMetricContract> metrics,
            Map<String, PromptSignalContract> signalContractsByLabel) {
        this.metrics = List.copyOf(metrics);
        this.metricsByCode = new LinkedHashMap<>();
        this.checksByCode = new LinkedHashMap<>();
        Map<String, String> locationsByLabel = new LinkedHashMap<>();
        Map<String, FinalPromptSignalDescriptor> descriptorsByLabel = new LinkedHashMap<>();
        Set<String> labels = new LinkedHashSet<>();
        Set<String> sections = new LinkedHashSet<>();
        for (FinalPromptMetricContract metric : this.metrics) {
            String metricCode = normalize(metric.metricCode());
            if (!StringUtils.hasText(metricCode)) {
                throw new IllegalStateException("Final prompt metric contract has an empty metricCode.");
            }
            if (metricsByCode.putIfAbsent(metricCode, metric) != null) {
                throw new IllegalStateException("Duplicate final prompt metric contract: " + metricCode);
            }
            validateMetricPurposeContract(metric, metricCode);
            for (FinalPromptMetricCheckContract check : metric.checks()) {
                String checkName = normalize(check.checkName());
                String key = key(metricCode, checkName);
                if (!StringUtils.hasText(checkName) || check.rule() == null
                        || !StringUtils.hasText(check.rule().operator())) {
                    throw new IllegalStateException("Final prompt metric check contract is incomplete: " + key);
                }
                validateRule(check.rule(), key);
                if (check.inputReadinessRule() != null) {
                    validateRule(check.inputReadinessRule(), key + ":inputReadinessRule");
                }
                if (check.applicabilityRule() != null) {
                    validateRule(check.applicabilityRule(), key + ":applicabilityRule");
                    if (!StringUtils.hasText(check.notApplicableMessage())) {
                        throw new IllegalStateException("Final prompt metric check notApplicableMessage is required when applicabilityRule exists: " + key);
                    }
                }
                collectPromptFacts(
                        check.rule(),
                        labels,
                        sections,
                        locationsByLabel,
                        descriptorsByLabel,
                        check.source(),
                        metric.metricRole(),
                        check.failureType(),
                        check.checkName());
                collectPromptFacts(
                        check.inputReadinessRule(),
                        labels,
                        sections,
                        locationsByLabel,
                        descriptorsByLabel,
                        check.source(),
                        metric.metricRole(),
                        check.failureType(),
                        check.checkName());
                collectPromptFacts(
                        check.applicabilityRule(),
                        labels,
                        sections,
                        locationsByLabel,
                        descriptorsByLabel,
                        check.source(),
                        metric.metricRole(),
                        "APPLICABILITY",
                        check.checkName());
                if (!StringUtils.hasText(check.source())) {
                    throw new IllegalStateException("Final prompt metric check source is required: " + key);
                }
                validatePromptLocation(check.source(), "source", key);
                if (!StringUtils.hasText(check.issueKey())) {
                    throw new IllegalStateException("Final prompt metric check issueKey is required: " + key);
                }
                validatePromptLocation(check.issueKey(), "issueKey", key);
                if (!StringUtils.hasText(check.remediationOwner())) {
                    throw new IllegalStateException("Final prompt metric check remediationOwner is required: " + key);
                }
                if (!StringUtils.hasText(check.severity())) {
                    throw new IllegalStateException("Final prompt metric check severity is required: " + key);
                }
                if (!StringUtils.hasText(check.failureType())) {
                    throw new IllegalStateException("Final prompt metric check failureType is required: " + key);
                }
                if (!StringUtils.hasText(check.readinessScope())) {
                    throw new IllegalStateException("Final prompt metric check readinessScope is required: " + key);
                }
                validateCustomerMessageContract(check, key);
                if (check.customerVisible() && !check.source().startsWith("finalUserPrompt.")
                        && !check.source().startsWith("finalSystemPrompt.")) {
                    throw new IllegalStateException("Customer-visible final prompt metric check must reference final prompt: " + key);
                }
                if (check.customerVisible()) {
                    validateCustomerVisibleRule(check.rule(), key);
                }
                if (!check.customerVisible() && (!check.source().startsWith("internalGate.")
                        || !check.issueKey().startsWith("internalGate."))) {
                    throw new IllegalStateException("Internal final prompt metric check source and issueKey must use internalGate.*: " + key);
                }
                if (checksByCode.putIfAbsent(key, check) != null) {
                    throw new IllegalStateException("Duplicate final prompt metric check contract: " + key);
                }
            }
        }
        if (metricsByCode.size() != 12) {
            throw new IllegalStateException("Final prompt metric contract must define exactly 12 metrics. actual="
                    + metricsByCode.size());
        }
        registerSignalContracts(labels, locationsByLabel, descriptorsByLabel, signalContractsByLabel);
        addStandardPromptSections(sections);
        this.promptLocationByLabel = Map.copyOf(locationsByLabel);
        this.signalDescriptorByLabel = Map.copyOf(descriptorsByLabel);
        this.promptSignalContracts = List.copyOf(signalContractsByLabel.values());
        this.knownLabels = Set.copyOf(labels);
        this.knownSections = Set.copyOf(sections);
    }

    public static FinalPromptMetricContractCatalog load(ObjectMapper objectMapper) {
        ObjectMapper mapper = objectMapper == null ? new ObjectMapper() : objectMapper;
        try (InputStream stream = FinalPromptMetricContractCatalog.class.getResourceAsStream(RESOURCE)) {
            if (stream == null) {
                throw new IllegalStateException("Final prompt metric contract resource is missing: " + RESOURCE);
            }
            List<FinalPromptMetricContract> loaded = mapper.readValue(stream, CONTRACT_LIST);
            if (loaded == null || loaded.isEmpty()) {
                throw new IllegalStateException("Final prompt metric contract resource is empty: " + RESOURCE);
            }
            return new FinalPromptMetricContractCatalog(loaded, loadSignalContracts(mapper));
        }
        catch (IOException exception) {
            throw new IllegalStateException("Final prompt metric contract resource cannot be read: " + RESOURCE, exception);
        }
    }

    private static Map<String, PromptSignalContract> loadSignalContracts(ObjectMapper mapper) {
        try (InputStream stream = FinalPromptMetricContractCatalog.class.getResourceAsStream(SIGNAL_RESOURCE)) {
            if (stream == null) {
                throw new IllegalStateException("Final prompt signal contract resource is missing: " + SIGNAL_RESOURCE);
            }
            List<Map<String, String>> rows = mapper.readValue(stream, SIGNAL_LIST);
            if (rows == null || rows.isEmpty()) {
                throw new IllegalStateException("Final prompt signal contract resource is empty: " + SIGNAL_RESOURCE);
            }
            Map<String, PromptSignalContract> result = new LinkedHashMap<>();
            for (Map<String, String> row : rows) {
                String label = row == null ? "" : row.get("label");
                String promptLocation = row == null ? "" : row.get("promptLocation");
                if (!StringUtils.hasText(label)) {
                    throw new IllegalStateException("Final prompt signal contract label is required.");
                }
                if (!StringUtils.hasText(promptLocation)) {
                    throw new IllegalStateException("Final prompt signal contract promptLocation is required: " + label);
                }
                validatePromptLocation(promptLocation, "promptLocation", "SIGNAL:" + label);
                String normalizedLabel = FinalPromptSnapshot.normalizeLabel(label);
                result.put(normalizedLabel, new PromptSignalContract(
                        label.trim(),
                        label.trim(),
                        promptLocation.trim(),
                        "CONTRACTED_PROMPT_SIGNAL",
                        "CONTRACTED_PROMPT_SIGNAL",
                        "PROMPT_SIGNAL_REGISTRY"));
            }
            return Map.copyOf(result);
        }
        catch (IOException exception) {
            throw new IllegalStateException("Final prompt signal contract resource cannot be read: "
                    + SIGNAL_RESOURCE, exception);
        }
    }

    public List<String> metricCodesInOrder() {
        return metrics.stream().map(metric -> normalize(metric.metricCode())).toList();
    }

    public String contractVersion() {
        String version = null;
        for (FinalPromptMetricContract metric : metrics) {
            String next = metric.version();
            if (!StringUtils.hasText(next)) {
                throw new IllegalStateException("Final prompt metric contract version is required. metricCode="
                        + metric.metricCode());
            }
            if (version == null) {
                version = next.trim();
            } else if (!version.equals(next.trim())) {
                throw new IllegalStateException("Final prompt metric contracts must use one active version."
                        + " expected=" + version + ", actual=" + next + ", metricCode=" + metric.metricCode());
            }
        }
        if (!StringUtils.hasText(version)) {
            throw new IllegalStateException("Final prompt metric contract catalog is empty.");
        }
        return version;
    }

    public FinalPromptMetricContract metric(String metricCode) {
        FinalPromptMetricContract metric = metricsByCode.get(normalize(metricCode));
        if (metric == null) {
            throw new IllegalStateException("Unknown final prompt metric contract: " + metricCode);
        }
        return metric;
    }

    public FinalPromptMetricCheckContract check(String metricCode, String checkName) {
        String normalizedMetricCode = normalize(metricCode);
        String normalizedCheckName = canonicalCheckName(normalizedMetricCode, normalize(checkName));
        FinalPromptMetricCheckContract check = checksByCode.get(key(normalizedMetricCode, normalizedCheckName));
        if (check == null) {
            throw new IllegalStateException("Final prompt metric check is not registered in contract. metric="
                    + normalizedMetricCode + ", check=" + normalize(checkName));
        }
        return check;
    }

    public List<PromptSignalContract> promptSignalContracts() {
        return promptSignalContracts;
    }

    private static String canonicalCheckName(String metricCode, String checkName) {
        if (!StringUtils.hasText(metricCode) || !StringUtils.hasText(checkName)) {
            return checkName;
        }
        String prefix = metricCode + "_";
        if (checkName.startsWith(prefix) && checkName.length() > prefix.length()) {
            return checkName.substring(prefix.length());
        }
        return checkName;
    }

    public boolean isKnownPromptFact(String section, String label) {
        if (!StringUtils.hasText(label)) {
            return true;
        }
        return knownLabels.contains(FinalPromptSnapshot.normalizeLabel(label));
    }

    public String promptLocation(String section, String label) {
        String mapped = promptLocationByLabel.get(FinalPromptSnapshot.normalizeLabel(label));
        if (StringUtils.hasText(mapped)) {
            return mapped;
        }
        return FinalPromptSemanticModel.semanticKey(section, label);
    }

    public String canonicalGroup(String section, String label) {
        FinalPromptSignalDescriptor descriptor = signalDescriptor(section, label);
        if (descriptor != null && StringUtils.hasText(descriptor.promptLocation())) {
            return descriptor.promptLocation();
        }
        return promptLocation(section, label);
    }

    public String securityRelevance(String section, String label) {
        FinalPromptSignalDescriptor descriptor = signalDescriptor(section, label);
        if (descriptor != null && StringUtils.hasText(descriptor.metricRole())) {
            return descriptor.metricRole();
        }
        return isKnownPromptFact(section, label) ? "CONTRACTED_PROMPT_SIGNAL" : "INTERNAL_GATE";
    }

    public String attackSignalRole(String section, String label, String value) {
        FinalPromptSignalDescriptor descriptor = signalDescriptor(section, label);
        if (descriptor != null && StringUtils.hasText(descriptor.interpretationRole())) {
            return descriptor.interpretationRole();
        }
        return isKnownPromptFact(section, label) ? "CONTRACTED_PROMPT_SIGNAL" : "UNMAPPED_PROMPT_FACT";
    }

    public String signalKey(String section, String label) {
        FinalPromptSignalDescriptor descriptor = signalDescriptor(section, label);
        if (descriptor != null && StringUtils.hasText(descriptor.signalKey())) {
            return descriptor.signalKey();
        }
        return isKnownPromptFact(section, label)
                ? promptLocation(section, label)
                : "unmapped:" + FinalPromptSnapshot.normalizeLabel(label);
    }

    private FinalPromptSignalDescriptor signalDescriptor(String section, String label) {
        if (!StringUtils.hasText(label)) {
            return null;
        }
        return signalDescriptorByLabel.get(FinalPromptSnapshot.normalizeLabel(label));
    }

    private static void validateMetricPurposeContract(FinalPromptMetricContract metric, String metricCode) {
        if (!StringUtils.hasText(metric.version())) {
            throw new IllegalStateException("Final prompt metric contract version is required: " + metricCode);
        }
        if (!StringUtils.hasText(metric.purpose())) {
            throw new IllegalStateException("Final prompt metric contract purpose is required: " + metricCode);
        }
        if (!StringUtils.hasText(metric.qualityQuestion())) {
            throw new IllegalStateException("Final prompt metric contract qualityQuestion is required: " + metricCode);
        }
        if (!StringUtils.hasText(metric.metricRole())) {
            throw new IllegalStateException("Final prompt metric contract metricRole is required: " + metricCode);
        }
        String role = normalize(metric.metricRole());
        if (!Set.of("ATTACK_DETECTION", "PROMPT_FIDELITY", "CONDITIONAL_RAG", "INTERNAL_GATE").contains(role)) {
            throw new IllegalStateException("Final prompt metric contract metricRole is invalid: "
                    + metricCode + ", role=" + metric.metricRole());
        }
    }

    private static void validateCustomerMessageContract(FinalPromptMetricCheckContract check, String key) {
        if (!StringUtils.hasText(check.qualityQuestion())) {
            throw new IllegalStateException("Final prompt metric check qualityQuestion is required: " + key);
        }
        if (!StringUtils.hasText(check.problemTitle())) {
            throw new IllegalStateException("Final prompt metric check problemTitle is required: " + key);
        }
        if (!StringUtils.hasText(check.shortProblem())) {
            throw new IllegalStateException("Final prompt metric check shortProblem is required: " + key);
        }
        if (!StringUtils.hasText(check.expectedMessage())) {
            throw new IllegalStateException("Final prompt metric check expectedMessage is required: " + key);
        }
        if (!StringUtils.hasText(check.passMessage())) {
            throw new IllegalStateException("Final prompt metric check passMessage is required: " + key);
        }
        if (!StringUtils.hasText(check.failureMessage())) {
            throw new IllegalStateException("Final prompt metric check failureMessage is required: " + key);
        }
        if (!StringUtils.hasText(check.whyItMatters())) {
            throw new IllegalStateException("Final prompt metric check whyItMatters is required: " + key);
        }
        if (!StringUtils.hasText(check.nextAction())) {
            throw new IllegalStateException("Final prompt metric check nextAction is required: " + key);
        }
        if (!StringUtils.hasText(check.reverifyCriterion())) {
            throw new IllegalStateException("Final prompt metric check reverifyCriterion is required: " + key);
        }
        if (check.customerVisible()) {
            if (!StringUtils.hasText(check.passEvidenceTemplate())) {
                throw new IllegalStateException("Customer-visible final prompt metric check passEvidenceTemplate is required: " + key);
            }
            if (!StringUtils.hasText(check.failureEvidenceTemplate())) {
                throw new IllegalStateException("Customer-visible final prompt metric check failureEvidenceTemplate is required: " + key);
            }
            if (check.evidenceBindings() == null || check.evidenceBindings().isEmpty()) {
                throw new IllegalStateException("Customer-visible final prompt metric check evidenceBindings are required: " + key);
            }
            validateCustomerVisibleTextQuality(check, key);
        }
    }

    private static void validateCustomerVisibleTextQuality(FinalPromptMetricCheckContract check, String key) {
        Map<String, String> texts = Map.ofEntries(
                Map.entry("qualityQuestion", check.qualityQuestion()),
                Map.entry("problemTitle", check.problemTitle()),
                Map.entry("shortProblem", check.shortProblem()),
                Map.entry("expectedMessage", check.expectedMessage()),
                Map.entry("passMessage", check.passMessage()),
                Map.entry("failureMessage", check.failureMessage()),
                Map.entry("whyItMatters", check.whyItMatters()),
                Map.entry("nextAction", check.nextAction()),
                Map.entry("reverifyCriterion", check.reverifyCriterion()),
                Map.entry("passEvidenceTemplate", check.passEvidenceTemplate()),
                Map.entry("failureEvidenceTemplate", check.failureEvidenceTemplate()));
        for (Map.Entry<String, String> entry : texts.entrySet()) {
            String value = entry.getValue();
            if (!StringUtils.hasText(value)) {
                continue;
            }
            String lowerValue = value.toLowerCase(Locale.ROOT);
            for (String forbidden : CUSTOMER_VISIBLE_FORBIDDEN_TERMS) {
                if (lowerValue.contains(forbidden.toLowerCase(Locale.ROOT))) {
                    throw new IllegalStateException("Customer-visible final prompt metric text contains an internal term: "
                            + key + ", field=" + entry.getKey() + ", term=" + forbidden);
                }
            }
        }
        if (sameText(check.passEvidenceTemplate(), check.passMessage())
                || sameText(check.passEvidenceTemplate(), check.expectedMessage())
                || sameText(check.passEvidenceTemplate(), check.whyItMatters())) {
            throw new IllegalStateException("Customer-visible final prompt metric evidence repeats display text: " + key);
        }
    }

    private static boolean sameText(String left, String right) {
        if (!StringUtils.hasText(left) || !StringUtils.hasText(right)) {
            return false;
        }
        return left.replaceAll("\\s+", " ").trim()
                .equals(right.replaceAll("\\s+", " ").trim());
    }

    private static String key(String metricCode, String checkName) {
        return normalize(metricCode) + ":" + normalize(checkName);
    }

    private static String normalize(String value) {
        return value == null ? "" : value.trim().toUpperCase(Locale.ROOT);
    }

    private static void validatePromptLocation(String value, String fieldName, String key) {
        if (value.contains("officialVerification.check") || value.contains("finalUserPrompt.metric")) {
            throw new IllegalStateException("Final prompt metric check " + fieldName
                    + " uses a synthetic prompt location: " + key);
        }
        if (!value.startsWith("finalUserPrompt.") && !value.startsWith("finalSystemPrompt.")
                && !value.startsWith("internalGate.")) {
            throw new IllegalStateException("Final prompt metric check " + fieldName
                    + " must reference final prompt or internal gate: " + key);
        }
    }

    private static void validateRule(FinalPromptMetricRule rule, String key) {
        if (rule == null) {
            throw new IllegalStateException("Final prompt metric rule is missing: " + key);
        }
        if ("ALWAYS_PASS".equalsIgnoreCase(rule.operator())) {
            throw new IllegalStateException("Final prompt metric check must not use ALWAYS_PASS: " + key);
        }
        for (FinalPromptMetricRule child : rule.all()) {
            validateRule(child, key);
        }
        for (FinalPromptMetricRule child : rule.any()) {
            validateRule(child, key);
        }
    }

    private static void validateCustomerVisibleRule(FinalPromptMetricRule rule, String key) {
        if (rule == null) {
            throw new IllegalStateException("Customer-visible final prompt metric rule is missing: " + key);
        }
        String operator = normalize(rule.operator());
        if (RAW_PRESENCE_OPERATORS.contains(operator)) {
            throw new IllegalStateException("Customer-visible final prompt metric check must judge decidability or purpose, not raw value presence: " + key);
        }
        for (FinalPromptMetricRule child : rule.all()) {
            validateCustomerVisibleRule(child, key);
        }
        for (FinalPromptMetricRule child : rule.any()) {
            validateCustomerVisibleRule(child, key);
        }
    }

    private static void collectPromptFacts(
            FinalPromptMetricRule rule,
            Set<String> labels,
            Set<String> sections,
            Map<String, String> locationsByLabel,
            Map<String, FinalPromptSignalDescriptor> descriptorsByLabel,
            String promptLocation,
            String metricRole,
            String interpretationRole,
            String checkName) {
        if (rule == null) {
            return;
        }
        rule.labels().stream()
                .filter(StringUtils::hasText)
                .map(FinalPromptSnapshot::normalizeLabel)
                .forEach(label -> registerPromptFact(
                        label,
                        "label:" + label,
                        labels,
                        locationsByLabel,
                        descriptorsByLabel,
                        promptLocation,
                        metricRole,
                        interpretationRole,
                        checkName));
        if (StringUtils.hasText(rule.field())) {
            registerPromptFact(
                    FinalPromptSnapshot.normalizeLabel(rule.field()),
                    "field:" + FinalPromptSnapshot.normalizeLabel(rule.field()),
                    labels,
                    locationsByLabel,
                    descriptorsByLabel,
                    promptLocation,
                    metricRole,
                    interpretationRole,
                    checkName);
        }
        rule.thenLabels().stream()
                .filter(StringUtils::hasText)
                .map(FinalPromptSnapshot::normalizeLabel)
                .forEach(label -> registerPromptFact(
                        label,
                        "thenLabel:" + label,
                        labels,
                        locationsByLabel,
                        descriptorsByLabel,
                        promptLocation,
                        metricRole,
                        interpretationRole,
                        checkName));
        rule.sections().stream()
                .filter(StringUtils::hasText)
                .map(FinalPromptSnapshot::normalizeSection)
                .forEach(sections::add);
        for (FinalPromptMetricRule child : rule.all()) {
            collectPromptFacts(
                    child,
                    labels,
                    sections,
                    locationsByLabel,
                    descriptorsByLabel,
                    promptLocation,
                    metricRole,
                    interpretationRole,
                    checkName);
        }
        for (FinalPromptMetricRule child : rule.any()) {
            collectPromptFacts(
                    child,
                    labels,
                    sections,
                    locationsByLabel,
                    descriptorsByLabel,
                    promptLocation,
                    metricRole,
                    interpretationRole,
                    checkName);
        }
    }

    private static void registerPromptFact(
            String normalizedLabel,
            String signalKey,
            Set<String> labels,
            Map<String, String> locationsByLabel,
            Map<String, FinalPromptSignalDescriptor> descriptorsByLabel,
            String promptLocation,
            String metricRole,
            String interpretationRole,
            String checkName) {
        if (!StringUtils.hasText(normalizedLabel)) {
            return;
        }
        labels.add(normalizedLabel);
        if (StringUtils.hasText(promptLocation)
                && (promptLocation.startsWith("finalUserPrompt.") || promptLocation.startsWith("finalSystemPrompt."))) {
            locationsByLabel.putIfAbsent(normalizedLabel, promptLocation);
            descriptorsByLabel.putIfAbsent(
                    normalizedLabel,
                    new FinalPromptSignalDescriptor(
                            normalizedLabel,
                            signalKey,
                            promptLocation,
                            metricRole,
                            interpretationRole,
                            checkName));
        }
    }

    private static void registerSignalContracts(
            Set<String> labels,
            Map<String, String> locationsByLabel,
            Map<String, FinalPromptSignalDescriptor> descriptorsByLabel,
            Map<String, PromptSignalContract> signalContractsByLabel) {
        if (signalContractsByLabel == null || signalContractsByLabel.isEmpty()) {
            return;
        }
        signalContractsByLabel.forEach((normalizedLabel, contract) -> {
            if (contract == null || !StringUtils.hasText(normalizedLabel)
                    || !StringUtils.hasText(contract.promptLocation())) {
                return;
            }
            labels.add(normalizedLabel);
            locationsByLabel.putIfAbsent(normalizedLabel, contract.promptLocation());
            descriptorsByLabel.putIfAbsent(
                    normalizedLabel,
                    new FinalPromptSignalDescriptor(
                            normalizedLabel,
                            contract.signalKey(),
                            contract.promptLocation(),
                            contract.requiredRole(),
                            contract.interpretationRole(),
                            contract.checkCode()));
        });
    }

    private static void addStandardPromptSections(Set<String> sections) {
        List.of(
                "ROOT",
                "CURRENT REQUEST AND EVENT",
                "BRIDGE RESOLUTION CONTEXT",
                "CONTEXT COVERAGE",
                "IDENTITY AND ROLE CONTEXT",
                "AUTHENTICATION AND ASSURANCE CONTEXT",
                "DEVICE CONTEXT",
                "LOCATION CONTEXT",
                "REQUEST INTENT SIGNAL CONTEXT",
                "RESOURCE AND ACTION CONTEXT",
                "SESSION NARRATIVE CONTEXT",
                "PERSONAL WORK PROFILE",
                "ROLE AND WORK SCOPE CONTEXT",
                "FRICTION AND APPROVAL HISTORY",
                "DELEGATED OBJECTIVE CONTEXT",
                "EXPLICIT MISSING KNOWLEDGE",
                "RAG",
                "RAG EVIDENCE",
                "RETRIEVED CONTEXT",
                "RELATED DOCUMENTS",
                "LEARNING SEARCH",
                "KNOWLEDGE CONTEXT",
                "THREAT MEMORY")
                .stream()
                .map(FinalPromptSnapshot::normalizeSection)
                .forEach(sections::add);
    }

    public record PromptSignalContract(
            String label,
            String signalKey,
            String promptLocation,
            String requiredRole,
            String interpretationRole,
            String checkCode
    ) {
    }

    private record FinalPromptSignalDescriptor(
            String normalizedLabel,
            String signalKey,
            String promptLocation,
            String metricRole,
            String interpretationRole,
            String checkName
    ) {
    }
}
