package io.contexa.contexaiam.admin.promptquality.official.application;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.contexa.contexacore.verification.runtime.prompt.FinalPromptMetricCheckContract;
import io.contexa.contexaiam.admin.promptquality.official.model.RuntimeEvidenceCheckResult;
import org.springframework.util.StringUtils;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.regex.Pattern;

final class OfficialCustomerPurposeEvidenceParser {

    private final ObjectMapper objectMapper;
    private final OfficialPromptEvidenceFormatter evidenceFormatter;
    private final OfficialCustomerPurposeEvidenceValidator validator;
    private final OfficialRuntimeEvidenceCheckInterpreter checkInterpreter;

    OfficialCustomerPurposeEvidenceParser(
            ObjectMapper objectMapper,
            OfficialPromptEvidenceFormatter evidenceFormatter,
            OfficialCustomerPurposeEvidenceValidator validator,
            OfficialRuntimeEvidenceCheckInterpreter checkInterpreter) {
        this.objectMapper = objectMapper;
        this.evidenceFormatter = evidenceFormatter;
        this.validator = validator;
        this.checkInterpreter = checkInterpreter;
    }

    List<String> scopedRuntimeFacts(CustomerPurposeEvidenceDisplay display) {
        if (display == null || display.runtimeFacts().isEmpty()) {
            return List.of();
        }
        List<String> scoped = new ArrayList<>();
        for (String runtimeFact : display.runtimeFacts()) {
            if (!StringUtils.hasText(runtimeFact)) {
                continue;
            }
            String fact = runtimeFact.trim();
            String value = StringUtils.hasText(display.signalKey())
                    && !validator.sameText(display.signalKey(), fact)
                    ? evidenceFormatter.message(
                            "enterprise.pqa.runtimeVerification.customerPurpose.confirmedValue",
                            display.signalKey().trim(),
                            fact)
                    : fact;
            validator.addUnique(scoped, value);
        }
        return List.copyOf(scoped);
    }

    List<String> visibleSignals(
            List<String> signals,
            RuntimeEvidenceCheckResult check,
            boolean customerVisible) {
        if (!customerVisible || signals == null || signals.isEmpty()) {
            return signals == null ? List.of() : signals;
        }
        if (check != null && StringUtils.hasText(check.purposeVersion())) {
            List<String> structuredSignals = signals.stream()
                    .filter(StringUtils::hasText)
                    .map(String::trim)
                    .filter(this::structuredSignal)
                    .distinct()
                    .toList();
            if (structuredSignals.isEmpty()) {
                throw contractError("Customer-visible purpose evidence must be generated as structured payload.", check);
            }
            return structuredSignals;
        }
        boolean purposePassed = "PURPOSE_PASSED".equals(checkInterpreter.purposeResult(check));
        return signals.stream()
                .filter(StringUtils::hasText)
                .map(String::trim)
                .filter(signal -> visibleLegacySignal(signal, purposePassed))
                .distinct()
                .toList();
    }

    CustomerPurposeEvidenceDisplay display(String signal, RuntimeEvidenceCheckResult check) {
        return display(signal, check, null);
    }

    CustomerPurposeEvidenceDisplay display(
            String signal,
            RuntimeEvidenceCheckResult check,
            FinalPromptMetricCheckContract checkContract) {
        CustomerPurposeEvidenceDisplay structured = split(signal, check, checkContract);
        if (structured != null) {
            return structured;
        }
        if (check != null && StringUtils.hasText(check.purposeVersion())) {
            throw contractError("Customer-visible purpose evidence is not a structured payload.", check);
        }
        if (StringUtils.hasText(signal) && evidenceFormatter.technicalText(signal)) {
            List<String> fragments = evidenceFormatter.evidenceFragments(signal);
            if (!fragments.isEmpty()) {
                String signalKey = firstNonBlank(
                        check == null ? null : check.label(), check == null ? null : check.expectedValue(),
                        check == null ? null : check.decisionUtility(), check == null ? null : check.whyItMatters());
                return new CustomerPurposeEvidenceDisplay(
                        validator.requireText(signalKey, check, "purpose.signal_key"),
                        validator.requireText(evidenceFormatter.joinFragments(fragments), check, "purpose.evidence_value"));
            }
        }
        String signalKey = validator.signalKey(signal, check);
        String rawValue = firstNonBlank(
                signal, check == null ? null : check.actualValue(), check == null ? null : check.expectedValue());
        return new CustomerPurposeEvidenceDisplay(signalKey, validator.evidenceValue(rawValue, check, signalKey));
    }

    private CustomerPurposeEvidenceDisplay split(
            String signal,
            RuntimeEvidenceCheckResult check,
            FinalPromptMetricCheckContract checkContract) {
        if (!StringUtils.hasText(signal)) {
            return null;
        }
        String text = signal.trim();
        if (text.startsWith("{") && text.endsWith("}")) {
            CustomerPurposeEvidenceDisplay structured = structuredDisplay(text, check, checkContract);
            if (structured != null) {
                return structured;
            }
        }
        if (text.contains(OfficialCustomerPurposeEvidenceValidator.SEPARATOR)
                && check != null && StringUtils.hasText(check.purposeVersion())) {
            throw contractError("Customer-visible purpose evidence uses deprecated separator.", check);
        }
        if (!text.contains(OfficialCustomerPurposeEvidenceValidator.SEPARATOR)) {
            return null;
        }
        String[] parts = text.split(Pattern.quote(OfficialCustomerPurposeEvidenceValidator.SEPARATOR), 2);
        return parts.length != 2 ? null : new CustomerPurposeEvidenceDisplay(
                validator.requireText(parts[0], check, "purpose.signal_key"),
                validator.requireText(parts[1], check, "purpose.evidence_value"));
    }

    private CustomerPurposeEvidenceDisplay structuredDisplay(
            String json,
            RuntimeEvidenceCheckResult check,
            FinalPromptMetricCheckContract checkContract) {
        Map<String, Object> structured = jsonMap(json);
        String rawSignalKey = objectText(structured.get("signalKey"));
        String rawEvidenceValue = objectText(structured.get("evidenceValue"));
        if (!StringUtils.hasText(rawSignalKey) && !StringUtils.hasText(rawEvidenceValue)) {
            return null;
        }
        String signalKey = displaySignalKey(rawSignalKey, check, checkContract);
        return new CustomerPurposeEvidenceDisplay(
                signalKey,
                displayEvidenceValue(rawEvidenceValue, check, checkContract, signalKey),
                displayItems(structured.get("runtimeFacts"), true),
                displayItems(structured.get("contextItems"), false),
                true);
    }

    private String displaySignalKey(
            String rawSignalKey,
            RuntimeEvidenceCheckResult check,
            FinalPromptMetricCheckContract contract) {
        if (StringUtils.hasText(rawSignalKey)
                && !evidenceFormatter.technicalText(rawSignalKey)
                && !validator.containsRawSymbol(rawSignalKey)) {
            return validator.requireText(rawSignalKey, check, "purpose.signal_key");
        }
        String contractText = contractDisplayTitle(check, contract);
        return validator.requireText(
                StringUtils.hasText(contractText) ? contractText : rawSignalKey,
                check,
                "purpose.signal_key");
    }

    private String displayEvidenceValue(
            String rawValue,
            RuntimeEvidenceCheckResult check,
            FinalPromptMetricCheckContract contract,
            String excludedText) {
        boolean readable = StringUtils.hasText(rawValue)
                && !evidenceFormatter.technicalText(rawValue)
                && !validator.containsRawSymbol(rawValue);
        if (readable && (!validator.sameText(rawValue, excludedText) || contract == null)) {
            return validator.requireText(rawValue, check, "purpose.evidence_value");
        }
        String contractText = contractEvidenceText(check, contract, excludedText);
        return StringUtils.hasText(contractText)
                ? validator.requireText(contractText, check, "purpose.evidence_value")
                : validator.evidenceValue(rawValue, check, excludedText);
    }

    private String contractDisplayTitle(
            RuntimeEvidenceCheckResult check,
            FinalPromptMetricCheckContract contract) {
        if (contract == null) {
            return "";
        }
        return switch (checkInterpreter.purposeResult(check)) {
            case "PURPOSE_FAILED", "FAILED" -> firstNonBlank(
                    contract.problemTitle(), contract.failureMessage(),
                    contract.expectedMessage(), contract.qualityQuestion());
            case "NOT_APPLICABLE" -> firstNonBlank(
                    contract.notApplicableMessage(), contract.passMessage(),
                    contract.expectedMessage(), contract.qualityQuestion());
            default -> firstNonBlank(
                    contract.passMessage(), contract.expectedMessage(),
                    contract.qualityQuestion(), contract.problemTitle());
        };
    }

    private String contractEvidenceText(
            RuntimeEvidenceCheckResult check,
            FinalPromptMetricCheckContract contract,
            String excludedText) {
        if (contract == null) {
            return "";
        }
        List<String> candidates = new ArrayList<>();
        switch (checkInterpreter.purposeResult(check)) {
            case "PURPOSE_FAILED", "FAILED" -> {
                add(candidates, contract.failureMessage());
                add(candidates, contract.shortProblem());
                add(candidates, contract.expectedMessage());
            }
            case "NOT_APPLICABLE" -> {
                add(candidates, contract.notApplicableMessage());
                add(candidates, contract.expectedMessage());
            }
            default -> {
                add(candidates, contract.expectedMessage());
                add(candidates, contract.qualityQuestion());
            }
        }
        return candidates.stream()
                .filter(StringUtils::hasText)
                .filter(candidate -> !validator.sameText(candidate, excludedText))
                .filter(candidate -> !evidenceFormatter.technicalText(candidate))
                .filter(candidate -> !validator.containsRawSymbol(candidate))
                .findFirst().map(String::trim).orElse("");
    }

    List<String> displayItemsFromJson(String value, String nestedKey) {
        if (!StringUtils.hasText(value)) {
            return List.of();
        }
        try {
            List<?> raw = objectMapper.readValue(value, List.class);
            List<String> result = new ArrayList<>();
            boolean runtimeFacts = "runtimeFacts".equals(nestedKey);
            for (Object item : raw) {
                if (item instanceof String text) {
                    appendDisplayItems(result, text, runtimeFacts);
                } else if (item instanceof Map<?, ?> map && map.get(nestedKey) != null) {
                    result.addAll(displayItems(map.get(nestedKey), runtimeFacts));
                }
            }
            return List.copyOf(result);
        }
        catch (Exception ignored) {
            return List.of();
        }
    }
    List<String> displayItems(Object value) {
        return displayItems(value, false);
    }
    private List<String> displayItems(Object value, boolean runtimeFacts) {
        if (value == null) {
            return List.of();
        }
        List<String> result = new ArrayList<>();
        if (value instanceof Iterable<?> iterable) {
            for (Object item : iterable) {
                if (item instanceof Map<?, ?> map) {
                    Object nested = map.get(runtimeFacts ? "runtimeFacts" : "contextItems");
                    if (nested != null) {
                        result.addAll(displayItems(nested, runtimeFacts));
                    }
                } else {
                    appendDisplayItems(result, objectText(item), runtimeFacts);
                }
            }
        } else {
            appendDisplayItems(result, objectText(value), runtimeFacts);
        }
        return List.copyOf(result);
    }

    private void appendDisplayItems(List<String> items, String value, boolean runtimeFacts) {
        if (!StringUtils.hasText(value)) {
            return;
        }
        String normalized = value.replace("\r\n", "\n").replace('\r', '\n').trim();
        String expression = runtimeFacts ? "(?<=\\.)\\s+|\\n+" : "[,\\n]";
        for (String token : normalized.split(expression)) {
            validator.addUnique(items, token);
        }
    }

    boolean structuredSignal(String signal) {
        String text = signal.trim();
        return text.startsWith("{") && text.endsWith("}")
                && text.contains("\"signalKey\"") && text.contains("\"evidenceValue\"");
    }

    private boolean visibleLegacySignal(String signal, boolean purposePassed) {
        if (evidenceFormatter.contractMetadataSignal(signal)
                || evidenceFormatter.promptLocationToken(signal)
                || internalSignal(signal)
                || presenceOnlySignal(signal)) {
            return false;
        }
        return !purposePassed || !absenceSignal(signal);
    }

    private boolean presenceOnlySignal(String signal) {
        return signal.endsWith("=present")
                && (!signal.startsWith("compactMarker=") || "compactMarker=present".equalsIgnoreCase(signal));
    }

    private boolean internalSignal(String signal) {
        return signal.startsWith("consistencyOutcome=") || signal.startsWith("stageNoteRelation=");
    }

    private boolean absenceSignal(String signal) {
        return signal.endsWith("=missing") || signal.endsWith("=absent")
                || signal.endsWith("=present") || signal.contains("missingLabels=");
    }

    @SuppressWarnings("unchecked")
    private Map<String, Object> jsonMap(String json) {
        if (!StringUtils.hasText(json)) {
            return Map.of();
        }
        try {
            return objectMapper.readValue(json, LinkedHashMap.class);
        }
        catch (Exception ignored) {
            return Map.of();
        }
    }

    private IllegalStateException contractError(String message, RuntimeEvidenceCheckResult check) {
        return new IllegalStateException("ENGINE_CONTRACT_ERROR: " + message
                + " metric=" + safe(check == null ? null : check.metricCode())
                + ", check=" + safe(check == null ? null : check.checkCode()));
    }

    private void add(List<String> values, String value) {
        if (StringUtils.hasText(value) && !values.contains(value.trim())) {
            values.add(value.trim());
        }
    }

    private String objectText(Object value) {
        return value == null ? "" : String.valueOf(value).trim();
    }

    private String firstNonBlank(String... values) {
        for (String value : values) {
            if (StringUtils.hasText(value)) {
                return value.trim();
            }
        }
        return "";
    }

    private String normalize(String value) {
        return value == null ? "" : value.trim().toUpperCase(Locale.ROOT);
    }

    private String safe(String value) {
        return value == null ? "" : value.trim();
    }
}
