package io.contexa.contexaiam.admin.promptquality.official.application;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.contexa.contexacore.verification.runtime.OfficialVerificationMessageResolver;
import io.contexa.contexaiam.admin.promptquality.official.model.RuntimeEvidenceCheckResult;
import org.springframework.util.StringUtils;

import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

final class OfficialPromptEvidenceFormatter {

    private static final Set<String> CONTRACT_METADATA_SIGNAL_KEYS = Set.of(
            "purposeSignal", "meaning", "securityRelevance", "interpretationLink", "purposeResult");
    private static final Pattern EVIDENCE_KEY_VALUE = Pattern.compile(
            "([A-Za-z][A-Za-z0-9_.-]{1,80})\\s*=\\s*(.*?)(?=\\s*(?:[,;]\\s*[A-Za-z][A-Za-z0-9_.-]{1,80}\\s*=|[;\\r\\n]|$))");
    private static final Pattern TECHNICAL_CONTRACT_CODE =
            Pattern.compile("\\b[A-Z]{2,}(?:_[A-Z0-9]+)+\\b");

    private final ObjectMapper objectMapper;
    private final OfficialVerificationMessageResolver messageResolver;

    OfficialPromptEvidenceFormatter(ObjectMapper objectMapper) {
        this(objectMapper, OfficialVerificationMessageResolver.classpath(Locale.KOREAN));
    }

    OfficialPromptEvidenceFormatter(
            ObjectMapper objectMapper,
            OfficialVerificationMessageResolver messageResolver) {
        this.objectMapper = objectMapper;
        this.messageResolver = messageResolver;
    }

    boolean technicalText(String value) {
        if (!StringUtils.hasText(value)) {
            return false;
        }
        String text = value.trim();
        return text.contains("Evidence:")
                || text.contains("evidence:")
                || TECHNICAL_CONTRACT_CODE.matcher(text).find()
                || promptLocationToken(text)
                || startsWithTechnicalKey(text)
                || containsTechnicalAssignment(text)
                || EVIDENCE_KEY_VALUE.matcher(text).find();
    }

    String concreteMetricActualValue(RuntimeEvidenceCheckResult check) {
        String concrete = concreteDetectedSignalSummary(check);
        String actual = check == null ? "" : check.actualValue();
        if (!StringUtils.hasText(concrete)) {
            return actual;
        }
        return StringUtils.hasText(actual) && !actual.contains(concrete)
                ? message(
                        "enterprise.pqa.runtimeVerification.evidence.actualWithBasis",
                        actual.trim(),
                        concrete)
                : concrete;
    }

    String concreteDetectedSignalSummary(RuntimeEvidenceCheckResult check) {
        return check == null ? "" : concreteDetectedSignalSummary(jsonStringList(check.detectedSignalsJson()));
    }

    String concreteDetectedSignalSummary(List<String> signals) {
        List<String> facts = new ArrayList<>();
        for (String signal : signals == null ? List.<String>of() : signals) {
            String fact = concreteSignalFact(signal);
            if (StringUtils.hasText(fact) && !facts.contains(fact)) {
                facts.add(fact);
            }
            if (facts.size() >= 6) {
                break;
            }
        }
        return String.join(" / ", facts);
    }

    String concreteSignalFact(String signal) {
        if (!StringUtils.hasText(signal)) {
            return "";
        }
        String text = signal.trim();
        if (contractMetadataSignal(text)) {
            return "";
        }
        String promptFact = concretePromptFactSignal(text);
        if (StringUtils.hasText(promptFact)) {
            return promptFact;
        }
        String presenceFact = presenceFact(text);
        if (StringUtils.hasText(presenceFact)) {
            return presenceFact;
        }
        String consistencyFact = consistencySignalFact(text);
        return StringUtils.hasText(consistencyFact) ? consistencyFact : valueSignalFact(text);
    }

    String concretePromptFactSignal(String signal) {
        String[] prefixes = {"truncatedField=", "truncatedBullet=", "truncatedNarrative=", "unmappedPromptFact="};
        for (String prefix : prefixes) {
            if (!signal.startsWith(prefix)) {
                continue;
            }
            String value = signal.substring(prefix.length()).trim();
            int valueIndex = value.indexOf(" value=");
            String location = valueIndex < 0 ? value : value.substring(0, valueIndex).trim();
            String factValue = valueIndex < 0 ? "" : value.substring(valueIndex + " value=".length()).trim();
            String label = prefix.startsWith("truncated")
                    ? message("enterprise.pqa.runtimeVerification.evidence.truncatedDecisionMaterial")
                    : message("enterprise.pqa.runtimeVerification.evidence.unregisteredPromptItem");
            return StringUtils.hasText(factValue)
                    ? message(
                            "enterprise.pqa.runtimeVerification.evidence.promptFactWithValue",
                            label,
                            evidenceName(location),
                            evidenceValue(factValue))
                    : message(
                            "enterprise.pqa.runtimeVerification.evidence.promptFact",
                            label,
                            evidenceName(location));
        }
        return "";
    }

    List<String> evidenceFragments(String rawEvidence) {
        if (!StringUtils.hasText(rawEvidence)) {
            return List.of();
        }
        String normalized = rawEvidence.trim()
                .replace('[', ' ').replace(']', ' ').replace('{', ' ').replace('}', ' ')
                .replace('"', ' ').replace('\'', ' ');
        List<String> fragments = new ArrayList<>();
        for (String part : normalized.split("\\r?\\n|;|,\\s*(?=[A-Za-z][A-Za-z0-9_.-]{1,80}\\s*=)")) {
            appendEvidenceFragments(fragments, part);
            if (fragments.size() >= 4) {
                break;
            }
        }
        return List.copyOf(fragments);
    }

    List<String> evidenceKeyValueFragments(String rawPart) {
        if (!StringUtils.hasText(rawPart)) {
            return List.of();
        }
        List<String> result = new ArrayList<>();
        Matcher matcher = EVIDENCE_KEY_VALUE.matcher(rawPart.trim());
        while (matcher.find() && result.size() < 4) {
            String key = evidenceName(matcher.group(1));
            String value = evidenceValue(matcher.group(2));
            if (!StringUtils.hasText(key)) {
                continue;
            }
            result.add(evidenceKeyValueFragment(key, value));
        }
        return List.copyOf(result);
    }

    String evidenceValue(String value) {
        if (!StringUtils.hasText(value)) {
            return "";
        }
        String cleaned = value.trim()
                .replace("Evidence:", "").replace("evidence:", "")
                .replace("=", " ").replace("|", ", ").replace(
                        "...",
                        " " + message("enterprise.pqa.runtimeVerification.evidence.omitted"))
                .replaceAll("\\s+", " ");
        return cleaned.length() > 120
                ? message(
                        "enterprise.pqa.runtimeVerification.evidence.truncatedValue",
                        cleaned.substring(0, 120).trim())
                : cleaned;
    }

    String displayValue(String value) {
        if (!StringUtils.hasText(value)) {
            return "";
        }
        String text = value.trim();
        if (!technicalText(text)) {
            return text;
        }
        List<String> fragments = evidenceFragments(text);
        return fragments.isEmpty() ? evidenceValue(text) : joinFragments(fragments);
    }

    String joinFragments(List<String> fragments) {
        List<String> limited = fragments == null
                ? List.of() : fragments.stream().filter(StringUtils::hasText).limit(3).toList();
        return switch (limited.size()) {
            case 0 -> message("enterprise.pqa.runtimeVerification.evidence.noConcreteEvidence");
            case 1 -> limited.get(0);
            case 2 -> message(
                    "enterprise.pqa.runtimeVerification.evidence.joinTwo",
                    limited.get(0),
                    limited.get(1));
            default -> message(
                    "enterprise.pqa.runtimeVerification.evidence.joinThree",
                    limited.get(0),
                    limited.get(1),
                    limited.get(2));
        };
    }

    private void appendEvidenceFragments(List<String> fragments, String rawPart) {
        String part = rawPart == null ? "" : rawPart.trim();
        String promptFact = concretePromptFactSignal(part);
        if (StringUtils.hasText(promptFact)) {
            appendUnique(fragments, promptFact);
            return;
        }
        List<String> keyValues = evidenceKeyValueFragments(part);
        if (!keyValues.isEmpty()) {
            keyValues.forEach(value -> appendUnique(fragments, value));
            return;
        }
        appendUnique(fragments, evidenceFragment(part));
    }

    private String presenceFact(String text) {
        if (text.startsWith("compactMarker=")) {
            String value = text.substring("compactMarker=".length()).trim();
            return !StringUtils.hasText(value) || "absent".equalsIgnoreCase(value)
                    ? "" : message(
                            "enterprise.pqa.runtimeVerification.evidence.compactMarkerFound",
                            value);
        }
        if (text.startsWith("section ") && text.endsWith("=missing")) {
            return message(
                    "enterprise.pqa.runtimeVerification.evidence.missingSection",
                    text.substring("section ".length(), text.length() - "=missing".length()).trim());
        }
        if (text.startsWith("missing:")) {
            return message(
                    "enterprise.pqa.runtimeVerification.evidence.missingItem",
                    text.substring("missing:".length()).trim());
        }
        if (text.endsWith("=missing")) {
            return message(
                    "enterprise.pqa.runtimeVerification.evidence.missingItem",
                    text.substring(0, text.length() - "=missing".length()).trim());
        }
        if (text.endsWith("=absent")) {
            return message(
                    "enterprise.pqa.runtimeVerification.evidence.unobservedItem",
                    text.substring(0, text.length() - "=absent".length()).trim());
        }
        return "";
    }

    private String consistencySignalFact(String signal) {
        if (signal.startsWith("stageNoteRelation=")) {
            String relation = valueAfter(signal, "stageNoteRelation=");
            if ("BOUND_TO_FINAL_AUTHORIZATION_EFFECT".equalsIgnoreCase(relation)) {
                return message("enterprise.pqa.runtimeVerification.evidence.authorizationBound");
            }
            if ("UNBOUND_PARALLEL_FACT_RISK".equalsIgnoreCase(relation)) {
                return message("enterprise.pqa.runtimeVerification.evidence.authorizationUnbound");
            }
            return message(
                    "enterprise.pqa.runtimeVerification.evidence.authorizationRelation",
                    evidenceValue(relation));
        }
        if (!signal.startsWith("consistencyOutcome=")) {
            return "";
        }
        String outcome = valueAfter(signal, "consistencyOutcome=");
        String labels = namedPart(signal, "comparedLabels=");
        String values = namedPart(signal, "distinctValues=");
        String messageKey = outcome.startsWith("CONFLICT")
                ? "enterprise.pqa.runtimeVerification.evidence.conflictItem"
                : "enterprise.pqa.runtimeVerification.evidence.matchedItem";
        return message(
                messageKey,
                evidenceName(firstNonBlank(
                        labels,
                        message("enterprise.pqa.runtimeVerification.evidence.comparisonItem"))),
                evidenceValue(firstNonBlank(values, outcome)));
    }

    private String valueSignalFact(String signal) {
        List<String> fragments = evidenceKeyValueFragments(signal);
        if (fragments.size() > 1) {
            return joinFragments(fragments);
        }
        int equalsIndex = signal.indexOf('=');
        if (equalsIndex <= 0) {
            return "";
        }
        String key = signal.substring(0, equalsIndex).trim();
        String value = evidenceValue(signal.substring(equalsIndex + 1));
        if (!StringUtils.hasText(key) || !StringUtils.hasText(value)
                || "present".equalsIgnoreCase(value) || "absent".equalsIgnoreCase(value)) {
            return "";
        }
        return message(
                "enterprise.pqa.runtimeVerification.evidence.confirmedValue",
                key,
                value);
    }

    private String evidenceFragment(String rawPart) {
        if (!StringUtils.hasText(rawPart)) {
            return "";
        }
        String part = rawPart.trim();
        String promptFact = concretePromptFactSignal(part);
        if (StringUtils.hasText(promptFact)) {
            return promptFact;
        }
        if (part.startsWith("field:")) {
            return message(
                    "enterprise.pqa.runtimeVerification.evidence.fieldReview",
                    evidenceName(part.substring("field:".length())));
        }
        if (part.startsWith("section:")) {
            return message(
                    "enterprise.pqa.runtimeVerification.evidence.sectionReview",
                    evidenceName(part.substring("section:".length())));
        }
        int equalsIndex = part.indexOf('=');
        if (equalsIndex <= 0) {
            return plainFragment(part);
        }
        return evidenceKeyValueFragment(
                evidenceName(part.substring(0, equalsIndex)), evidenceValue(part.substring(equalsIndex + 1)));
    }

    private String evidenceKeyValueFragment(String key, String value) {
        if (!StringUtils.hasText(key)) {
            return "";
        }
        if (!StringUtils.hasText(value) || missingValue(value)) {
            return message(
                    "enterprise.pqa.runtimeVerification.evidence.valueMissing",
                    key);
        }
        return "compactMarker".equals(key)
                ? message("enterprise.pqa.runtimeVerification.evidence.compactMarker", value)
                : message("enterprise.pqa.runtimeVerification.evidence.keyValue", key, value);
    }

    private String plainFragment(String part) {
        String value = evidenceValue(part);
        if (!StringUtils.hasText(value)) {
            return "";
        }
        return value.startsWith("누락") || value.startsWith("부재")
                || value.startsWith("축약 표식") || value.startsWith("잘린 판단 재료")
                ? value.replace(":", " ") : "";
    }

    String evidenceName(String value) {
        return !StringUtils.hasText(value) ? "" : value.trim()
                .replace("=", " ").replace(":", " ").replace("|", " ").replace(
                        "...",
                        " " + message("enterprise.pqa.runtimeVerification.evidence.omitted"))
                .replaceAll("\\s+", " ");
    }

    private boolean missingValue(String value) {
        String normalized = normalize(value);
        return Set.of("MISSING", "ABSENT", "NULL", "EMPTY", "UNKNOWN").contains(normalized);
    }

    boolean contractMetadataSignal(String signal) {
        int equalsIndex = signal.indexOf('=');
        String key = equalsIndex < 0 ? signal.trim() : signal.substring(0, equalsIndex).trim();
        return CONTRACT_METADATA_SIGNAL_KEYS.contains(key);
    }

    boolean promptLocationToken(String text) {
        return text.startsWith("finalUserPrompt.") || text.startsWith("finalSystemPrompt.")
                || text.startsWith("sealedEvidence.") || text.startsWith("internalGate.")
                || text.startsWith("section ");
    }

    private boolean startsWithTechnicalKey(String text) {
        return List.of("field:", "section:", "label:", "term:", "thenLabel:", "thenTerm:", "source:")
                .stream().anyMatch(text::startsWith);
    }

    private boolean containsTechnicalAssignment(String text) {
        return List.of("missingLabels=", "compactMarker=", "unmappedPromptFact=",
                        "truncatedField=", "truncatedBullet=", "truncatedNarrative=")
                .stream().anyMatch(text::contains);
    }

    private List<String> jsonStringList(String value) {
        if (!StringUtils.hasText(value)) {
            return List.of();
        }
        try {
            List<?> raw = objectMapper.readValue(value, List.class);
            List<String> result = new ArrayList<>();
            for (Object item : raw) {
                String text = item instanceof String string ? string : objectMapper.writeValueAsString(item);
                if (StringUtils.hasText(text)) {
                    result.add(text.trim());
                }
            }
            return List.copyOf(result);
        }
        catch (Exception ignored) {
            return List.of(value.trim());
        }
    }

    private String valueAfter(String signal, String prefix) {
        String value = signal.substring(prefix.length()).trim();
        int commaIndex = value.indexOf(',');
        return commaIndex < 0 ? value : value.substring(0, commaIndex).trim();
    }

    private String namedPart(String signal, String name) {
        int index = signal.indexOf(name);
        return index < 0 ? "" : valueAfter(signal.substring(index), name);
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

    String message(String key, Object... args) {
        return messageResolver.resolve(key, args);
    }

    private void appendUnique(List<String> values, String value) {
        if (StringUtils.hasText(value) && !values.contains(value)) {
            values.add(value);
        }
    }
}
