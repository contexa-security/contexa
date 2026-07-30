package io.contexa.contexacore.verification.runtime.prompt;

import org.springframework.util.StringUtils;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

final class FinalPromptMetricRuleEngine {

    boolean evaluate(FinalPromptMetricRule rule, FinalPromptMetricEvaluationContext context) {
        if (rule == null || !StringUtils.hasText(rule.operator())) {
            return false;
        }
        String operator = normalize(rule.operator());
        return switch (operator) {
            case "ALL" -> rule.all().stream().allMatch(child -> evaluate(child, context));
            case "ANY" -> !rule.any().isEmpty() && rule.any().stream().anyMatch(child -> evaluate(child, context));
            case "SECTIONS_DECIDABLE" -> rule.sections().stream().allMatch(section -> sectionDecidable(context.prompt(), section));
            case "FIELDS_DECIDABLE" -> rule.labels().stream().allMatch(label -> fieldDecidable(context.prompt(), label));
            case "ANY_FIELD_DECIDABLE" -> rule.labels().stream().anyMatch(label -> fieldDecidable(context.prompt(), label));
            case "MIN_FIELDS_DECIDABLE" -> countPurposeFields(context.prompt(), rule.labels()) >= safeMin(rule.minCount());
            case "FIELD_VALUES_CONSISTENT" -> fieldValuesConsistent(context.prompt(), rule.labels());
            case "OPTIONAL_FIELD_VALUES_CONSISTENT" -> optionalFieldValuesConsistent(context.prompt(), rule.labels());
            case "BOOLEAN_FIELDS_CONSISTENT" -> booleanFieldsConsistent(context.prompt(), rule.labels());
            case "TERMS_PRESENT" -> rule.terms().stream().allMatch(term -> promptContains(context.prompt(), term));
            case "TERM_GROUPS_PRESENT" -> termGroupsPresent(userPrompt(context), rule.labelGroups());
            case "FORBIDDEN_TERMS_ABSENT" -> rule.forbiddenTerms().stream()
                    .noneMatch(term -> promptContains(context.prompt(), term));
            case "IF_FIELD_EQUALS_THEN_FORBIDDEN_TERMS_ABSENT" -> ifFieldEqualsThenForbiddenAbsent(rule, context);
            case "IF_ANY_TERM_PRESENT_THEN_FORBIDDEN_TERMS_ABSENT" -> ifAnyTermPresentThenForbiddenAbsent(rule, context);
            case "IF_ANY_TERM_PRESENT_THEN_ANY_FIELD_OR_TERM_PRESENT" -> ifAnyTermPresentThenAnyEvidencePresent(rule, context);
            case "COMPACT_MARKERS_ABSENT" -> context.prompt() != null && !context.prompt().hasCompactMarker();
            case "TRUNCATED_VALUES_ABSENT" -> truncatedValuesAbsent(context.prompt());
            case "SYSTEM_TERM_GROUPS_PRESENT" -> termGroupsPresent(systemPrompt(context), rule.labelGroups());
            case "RAG_NOT_FAILED_WHEN_USED" -> ragNotFailedWhenUsed(context, rule);
            case "RAG_APPLICABILITY_DECLARED" -> ragApplicabilityDeclared(context, rule);
            case "RAG_ABSENCE_DECLARED" -> ragAbsenceDeclared(context, rule);
            case "RAG_DOCUMENT_SURFACE_PRESENT" -> ragDocumentSurfacePresent(context, rule);
            case "RAG_PROJECTED_WHEN_RETRIEVED" -> ragProjectedWhenRetrieved(context, rule);
            case "RAG_TEXT_FORBIDDEN_TERMS_ABSENT" -> ragTextForbiddenTermsAbsent(context, rule);
            case "RAG_TEXT_TERM_GROUPS_PRESENT_WHEN_RAG_PRESENT" -> ragTextTermGroupsPresentWhenRagPresent(context, rule);
            case "RAG_DOCUMENT_AUTHORIZATION_SCOPE_ALIGNED" -> ragDocumentAuthorizationScopeAligned(context, rule);
            case "RAG_DOCUMENT_REQUEST_SCOPE_ALIGNED" -> ragDocumentRequestScopeAligned(context, rule);
            case "RAG_NO_SCOPE_MISMATCH_DOCUMENT" -> ragDocumentRequestScopeAligned(context, rule);
            case "RAG_BLOCKED_DOCUMENT_EXCLUDED" -> ragBlockedDocumentExcluded(context, rule);
            case "PREFLIGHT_READY" -> preflightReady(context);
            case "PROMPT_ARTIFACTS_TRACEABLE" -> promptArtifactsTraceable(context);
            case "RAW_FINAL_LINEAGE_TRACEABLE" -> rawFinalLineageTraceable(context);
            case "PROMPT_MANIFEST_PRESENT" -> StringUtils.hasText(promptEvidenceManifestJson(context));
            case "UNMAPPED_PROMPT_FACTS_ABSENT" -> context.prompt() != null && !context.prompt().hasUnmappedFacts();
            case "RESOURCE_TEMPLATE_TOKEN_ABSENT" -> resourceTemplateTokenAbsent(context.prompt());
            case "SENSITIVE_FLAG_CONSISTENT" -> sensitiveFlagConsistent(context.prompt());
            default -> throw new IllegalStateException("Unknown final prompt metric rule operator: " + rule.operator());
        };
    }

    private static boolean sectionHasContent(FinalPromptSnapshot prompt, String section) {
        if (prompt == null || !StringUtils.hasText(section) || !prompt.hasSection(section)) {
            return false;
        }
        return prompt.fields().stream()
                .anyMatch(field -> sameSection(field.section(), section)
                        && valuePurposeDecidable(prompt, field.label(), field.value()))
                || prompt.bullets().stream()
                .anyMatch(bullet -> sameSection(bullet.section(), section)
                        && textPurposeDecidable(bullet.text()))
                || prompt.narrativeLines().stream()
                .anyMatch(line -> sameSection(line.section(), section)
                        && textPurposeDecidable(line.text()));
    }

    private static boolean hasPurposeValue(FinalPromptSnapshot prompt, String label) {
        if (prompt == null) {
            return false;
        }
        return valuesByLabel(prompt, label).stream()
                .anyMatch(value -> valuePurposeDecidable(prompt, label, value));
    }

    private static boolean sectionDecidable(FinalPromptSnapshot prompt, String section) {
        return sectionHasContent(prompt, section) || absenceExplained(prompt, section);
    }

    private static boolean fieldDecidable(FinalPromptSnapshot prompt, String label) {
        if (prompt == null || !StringUtils.hasText(label)) {
            return false;
        }
        List<String> values = valuesByLabel(prompt, label);
        if (!values.isEmpty()) {
            return values.stream().anyMatch(value -> valuePurposeDecidable(prompt, label, value));
        }
        return absenceExplained(prompt, label);
    }

    private static int countPurposeFields(FinalPromptSnapshot prompt, List<String> labels) {
        int count = 0;
        for (String label : labels) {
            if (hasPurposeValue(prompt, label)) {
                count++;
            }
        }
        return count;
    }

    private static boolean valuePurposeDecidable(FinalPromptSnapshot prompt, String label, String value) {
        if (!StringUtils.hasText(value) || looksTruncated(value) || looksCompacted(value)) {
            return false;
        }
        if (looksUncertain(value)) {
            return uncertaintyExplained(prompt, label, value);
        }
        if (looksPlaceholder(value)) {
            return false;
        }
        return true;
    }

    private static boolean textPurposeDecidable(String value) {
        return StringUtils.hasText(value)
                && !looksTruncated(value)
                && !looksCompacted(value)
                && !looksPlaceholder(value);
    }

    private static boolean looksPlaceholder(String value) {
        if (!StringUtils.hasText(value)) {
            return true;
        }
        String normalized = value.trim().toLowerCase(Locale.ROOT);
        return normalized.equals("unknown")
                || normalized.equals("n/a")
                || normalized.equals("na")
                || normalized.equals("null")
                || normalized.equals("none")
                || normalized.equals("-")
                || normalized.equals("missing")
                || normalized.contains("missing")
                || normalized.contains("not available")
                || normalized.contains("unavailable")
                // Korean absence markers preserve compatibility with persisted prompt evidence.
                || normalized.equals("누락됨")
                || normalized.contains("누락")
                || normalized.equals("값 없음")
                || normalized.equals("없음")
                || normalized.equals("확인 불가")                || normalized.contains("placeholder")
                || normalized.contains("to be populated");
    }

    private static boolean looksUncertain(String value) {
        if (!StringUtils.hasText(value)) {
            return true;
        }
        String normalized = value.toLowerCase(Locale.ROOT);
        return normalized.contains("unknown")
                || normalized.contains("insufficient")
                || normalized.contains("provisional")
                || normalized.contains("learning_in_progress")
                || normalized.contains("no_direct_personal_comparable")
                || normalized.contains("no_comparable")
                || normalized.contains("fallback")
                || normalized.contains("thin");
    }

    private static boolean looksCompacted(String value) {
        if (!StringUtils.hasText(value)) {
            return false;
        }
        String normalized = value.toLowerCase(Locale.ROOT);
        return normalized.contains("compactedlinecategories")
                || normalized.contains("additional lines compacted")
                || normalized.contains("additionalcontexttrustwarningscompacted")
                || normalized.contains("additionalconfidencewarningscompacted");
    }

    private static boolean uncertaintyExplained(FinalPromptSnapshot prompt, String label, String value) {
        if (prompt == null) {
            return false;
        }
        if (absenceExplained(prompt, label)) {
            return true;
        }
        String lowerValue = value == null ? "" : value.toLowerCase(Locale.ROOT);
        return prompt.bullets().stream().anyMatch(bullet -> uncertaintyLineExplains(bullet.text(), lowerValue))
                || prompt.narrativeLines().stream().anyMatch(line -> uncertaintyLineExplains(line.text(), lowerValue))
                || prompt.fields().stream().anyMatch(field ->
                uncertaintyLineExplains(field.label() + " " + field.value(), lowerValue));
    }

    private static boolean uncertaintyLineExplains(String line, String lowerValue) {
        if (!StringUtils.hasText(line)) {
            return false;
        }
        String lower = line.toLowerCase(Locale.ROOT);
        boolean mentionsUncertainty = lower.contains("unknown")
                || lower.contains("insufficient")
                || lower.contains("provisional")
                || lower.contains("learning")
                || lower.contains("no direct")
                || lower.contains("no comparable")
                || lower.contains("fallback")
                || lower.contains("thin");
        boolean explainsUse = lower.contains("do not assume")
                || lower.contains("avoid assuming")
                || lower.contains("not proof")
                || lower.contains("absence")
                || lower.contains("limitation")
                || lower.contains("warning")
                || lower.contains("treat")
                || lower.contains("remain conservative")
                || lower.contains("not to infer")
                || lower.contains("cannot infer");
        if (mentionsUncertainty && explainsUse) {
            return true;
        }
        return StringUtils.hasText(lowerValue)
                && lower.contains(lowerValue)
                && explainsUse;
    }

    private static boolean absenceExplained(FinalPromptSnapshot prompt, String concept) {
        if (prompt == null || !StringUtils.hasText(concept)) {
            return false;
        }
        List<String> conceptTokens = conceptTokens(concept);
        if (conceptTokens.isEmpty()) {
            return false;
        }
        return prompt.bullets().stream().anyMatch(bullet -> absenceLineExplains(bullet.text(), conceptTokens))
                || prompt.narrativeLines().stream().anyMatch(line -> absenceLineExplains(line.text(), conceptTokens))
                || prompt.fields().stream().anyMatch(field ->
                absenceLineExplains(field.label() + " " + field.value(), conceptTokens));
    }

    private static boolean absenceLineExplains(String line, List<String> conceptTokens) {
        if (!StringUtils.hasText(line) || conceptTokens == null || conceptTokens.isEmpty()) {
            return false;
        }
        String normalizedLine = FinalPromptSnapshot.normalizeLabel(line);
        if (!conceptMentioned(normalizedLine, conceptTokens)) {
            return false;
        }
        String lower = line.toLowerCase(Locale.ROOT);
        return lower.contains("unknown")
                || lower.contains("missing")
                || lower.contains("not available")
                || lower.contains("unavailable")
                || lower.contains("insufficient")
                || lower.contains("limitation")
                || lower.contains("warning")
                || lower.contains("do not assume")
                || lower.contains("avoid assuming")
                || lower.contains("no observation")
                || lower.contains("not proof")
                || lower.contains("provisional")
                || lower.contains("learning")
                || lower.contains("fallback")
                || lower.contains("thin");
    }

    private static boolean conceptMentioned(String normalizedLine, List<String> conceptTokens) {
        if (!StringUtils.hasText(normalizedLine) || conceptTokens == null || conceptTokens.isEmpty()) {
            return false;
        }
        String joined = String.join("", conceptTokens);
        if (normalizedLine.contains(joined)) {
            return true;
        }
        int matched = 0;
        for (String token : conceptTokens) {
            if (token.length() <= 1) {
                continue;
            }
            if (normalizedLine.contains(token)) {
                matched++;
            }
        }
        int required = conceptTokens.size() <= 2 ? conceptTokens.size() : Math.min(3, conceptTokens.size());
        return matched >= required;
    }

    private static List<String> conceptTokens(String concept) {
        if (!StringUtils.hasText(concept)) {
            return List.of();
        }
        String splitCamelCase = concept.replaceAll("([a-z])([A-Z])", "$1 $2");
        String[] raw = splitCamelCase.split("[^\\p{L}\\p{N}]+");
        List<String> tokens = new ArrayList<>();
        for (String token : raw) {
            String normalized = FinalPromptSnapshot.normalizeLabel(token);
            if (StringUtils.hasText(normalized)) {
                tokens.add(normalized);
            }
        }
        return List.copyOf(tokens);
    }

    private static boolean promptContains(FinalPromptSnapshot prompt, String term) {
        return prompt != null && contains(prompt.userPrompt(), term);
    }

    private static boolean contains(String text, String term) {
        return StringUtils.hasText(text) && StringUtils.hasText(term)
                && text.toLowerCase(Locale.ROOT).contains(term.toLowerCase(Locale.ROOT));
    }

    private static boolean termGroupsPresent(String text, List<List<String>> groups) {
        if (groups == null || groups.isEmpty()) {
            return false;
        }
        for (List<String> group : groups) {
            if (group == null || group.isEmpty() || group.stream().noneMatch(term -> contains(text, term))) {
                return false;
            }
        }
        return true;
    }

    private static boolean ifFieldEqualsThenForbiddenAbsent(
            FinalPromptMetricRule rule,
            FinalPromptMetricEvaluationContext context) {
        if (!fieldEquals(context.prompt(), rule.field(), rule.equals())) {
            return true;
        }
        return rule.forbiddenTerms().stream().noneMatch(term -> promptContains(context.prompt(), term));
    }

    private static boolean ifAnyTermPresentThenAnyEvidencePresent(
            FinalPromptMetricRule rule,
            FinalPromptMetricEvaluationContext context
    ) {
        FinalPromptSnapshot prompt = context == null ? null : context.prompt();
        boolean trigger = rule.terms().stream().anyMatch(term -> promptContains(prompt, term));
        if (!trigger) {
            return true;
        }
        boolean labelEvidence = rule.thenLabels().stream().anyMatch(label -> hasPurposeValue(prompt, label));
        boolean termEvidence = triggeredPurposeEvidencePresent(prompt, rule.terms(), rule.thenTerms());
        return labelEvidence || termEvidence;
    }

    private static boolean triggeredPurposeEvidencePresent(
            FinalPromptSnapshot prompt,
            List<String> triggerTerms,
            List<String> evidenceTerms
    ) {
        if (prompt == null || triggerTerms == null || triggerTerms.isEmpty()
                || evidenceTerms == null || evidenceTerms.isEmpty()) {
            return false;
        }
        for (String trigger : triggerTerms) {
            if (!promptContains(prompt, trigger)) {
                continue;
            }
            if (sectionContainsAnyEvidenceTerm(prompt, trigger, evidenceTerms)) {
                return true;
            }
            for (String line : promptEvidenceLines(prompt)) {
                if (lineConnectsTriggerAndEvidence(line, trigger, evidenceTerms)) {
                    return true;
                }
            }
        }
        return false;
    }

    private static boolean sectionContainsAnyEvidenceTerm(
            FinalPromptSnapshot prompt,
            String section,
            List<String> evidenceTerms
    ) {
        if (prompt == null || !StringUtils.hasText(section) || !prompt.hasSection(section)) {
            return false;
        }
        return prompt.fields().stream()
                .anyMatch(field -> sameSection(field.section(), section)
                        && evidenceTerms.stream().anyMatch(term -> contains(field.label() + " " + field.value(), term)))
                || prompt.bullets().stream()
                .anyMatch(bullet -> sameSection(bullet.section(), section)
                        && evidenceTerms.stream().anyMatch(term -> contains(bullet.text(), term)))
                || prompt.narrativeLines().stream()
                .anyMatch(line -> sameSection(line.section(), section)
                        && evidenceTerms.stream().anyMatch(term -> contains(line.text(), term)));
    }

    private static boolean lineConnectsTriggerAndEvidence(
            String line,
            String trigger,
            List<String> evidenceTerms
    ) {
        if (!StringUtils.hasText(line) || !StringUtils.hasText(trigger)) {
            return false;
        }
        boolean hasEvidence = evidenceTerms.stream().anyMatch(term -> contains(line, term));
        if (!hasEvidence) {
            return false;
        }
        if (contains(line, trigger)) {
            return true;
        }
        return significantTriggerConceptMentioned(line, trigger);
    }

    private static boolean significantTriggerConceptMentioned(String line, String trigger) {
        List<String> tokens = significantTriggerTokens(trigger);
        if (tokens.isEmpty()) {
            return false;
        }
        String normalizedLine = FinalPromptSnapshot.normalizeLabel(line);
        for (String token : tokens) {
            if (normalizedLine.contains(token)) {
                return true;
            }
        }
        return false;
    }

    private static List<String> significantTriggerTokens(String trigger) {
        return conceptTokens(trigger).stream()
                .filter(token -> token.length() > 2)
                .filter(token -> !Set.of(
                        "status", "state", "value", "values", "field", "fields",
                        "current", "present", "observed", "context", "scope",
                        "count", "section", "line", "signal", "signals"
                ).contains(token))
                .toList();
    }

    private static List<String> promptEvidenceLines(FinalPromptSnapshot prompt) {
        if (prompt == null) {
            return List.of();
        }
        List<String> lines = new ArrayList<>();
        prompt.fields().forEach(field -> lines.add(field.label() + " " + field.value()));
        prompt.bullets().forEach(bullet -> lines.add(bullet.text()));
        prompt.narrativeLines().forEach(line -> lines.add(line.text()));
        return lines;
    }

    private static boolean ifAnyTermPresentThenForbiddenAbsent(
            FinalPromptMetricRule rule,
            FinalPromptMetricEvaluationContext context
    ) {
        boolean trigger = rule.terms().stream().anyMatch(term -> promptContains(context.prompt(), term));
        if (!trigger) {
            return true;
        }
        return rule.forbiddenTerms().stream().noneMatch(term -> promptContains(context.prompt(), term));
    }

    private static boolean fieldEquals(FinalPromptSnapshot prompt, String label, String expected) {
        if (!StringUtils.hasText(label) || !StringUtils.hasText(expected)) {
            return false;
        }
        String expectedNorm = normalizeScalar(expected);
        return valuesByLabel(prompt, label).stream()
                .map(FinalPromptMetricRuleEngine::normalizeScalar)
                .anyMatch(value -> value.equals(expectedNorm));
    }

    private static boolean fieldValuesConsistent(FinalPromptSnapshot prompt, List<String> labels) {
        if (prompt == null || labels == null || labels.isEmpty()) {
            return false;
        }
        Set<String> values = new HashSet<>();
        boolean hasComparableValue = false;
        for (String label : labels) {
            for (String value : valuesByLabel(prompt, label)) {
                if (!StringUtils.hasText(value) || !valuePurposeDecidable(prompt, label, value)) {
                    return false;
                }
                hasComparableValue = true;
                values.add(normalizeComparableValue(value));
            }
        }
        return hasComparableValue && values.size() <= 1;
    }

    private static boolean optionalFieldValuesConsistent(FinalPromptSnapshot prompt, List<String> labels) {
        if (prompt == null || labels == null || labels.isEmpty()) {
            return true;
        }
        Set<String> values = new HashSet<>();
        for (String label : labels) {
            for (String value : valuesByLabel(prompt, label)) {
                if (!StringUtils.hasText(value) || looksPlaceholder(value)) {
                    continue;
                }
                if (!valuePurposeDecidable(prompt, label, value)) {
                    return false;
                }
                values.add(normalizeComparableValue(value));
            }
        }
        return values.size() <= 1;
    }

    private static boolean booleanFieldsConsistent(FinalPromptSnapshot prompt, List<String> labels) {
        if (prompt == null || labels == null || labels.isEmpty()) {
            return false;
        }
        boolean hasBooleanEvidence = false;
        for (String label : labels) {
            List<String> rawValues = valuesByLabel(prompt, label);
            if (rawValues.isEmpty()) {
                if (absenceExplained(prompt, label)) {
                    continue;
                }
                return false;
            }
            Set<String> values = new HashSet<>();
            for (String value : rawValues) {
                String bool = normalizeBoolean(value);
                if (bool != null) {
                    if (!valuePurposeDecidable(prompt, label, value)) {
                        return false;
                    }
                    values.add(bool);
                    continue;
                }
                if (looksUncertain(value) && uncertaintyExplained(prompt, label, value)) {
                    continue;
                }
                if (!StringUtils.hasText(value) || looksPlaceholder(value) || absenceExplained(prompt, label)) {
                    continue;
                }
                if (!valuePurposeDecidable(prompt, label, value)) {
                    return false;
                }
                return false;
            }
            if (values.size() > 1) {
                return false;
            }
            hasBooleanEvidence = hasBooleanEvidence || !values.isEmpty();
        }
        return hasBooleanEvidence;
    }

    private static boolean truncatedValuesAbsent(FinalPromptSnapshot prompt) {
        if (prompt == null) {
            return false;
        }
        return prompt.fields().stream().map(FinalPromptField::value).noneMatch(FinalPromptMetricRuleEngine::looksTruncated)
                && prompt.bullets().stream().map(FinalPromptBullet::text).noneMatch(FinalPromptMetricRuleEngine::looksTruncated)
                && prompt.narrativeLines().stream().map(FinalPromptNarrativeLine::text).noneMatch(FinalPromptMetricRuleEngine::looksTruncated);
    }

    private static boolean looksTruncated(String value) {
        if (!StringUtils.hasText(value)) {
            return false;
        }
        String normalized = value.toLowerCase(Locale.ROOT);
        return normalized.endsWith("...")
                || normalized.contains("[truncated]")
                || normalized.contains("value truncated")
                || normalized.contains("truncated value")
                || normalized.contains("omitted for length");
    }

    private static boolean ragNotFailedWhenUsed(FinalPromptMetricEvaluationContext context, FinalPromptMetricRule rule) {
        Map<String, Object> rag = ragResults(context);
        if (!ragUsed(context, rule)) {
            return true;
        }
        if (asBoolean(rag.get("searchTimedOut")) || asBoolean(rag.get("ragTimedOut"))
                || asBoolean(rag.get("providerError"))
                || asBoolean(rag.get("vectorError"))) {
            return false;
        }
        Object status = firstPresent(rag, "status", "retrievalStatus");
        return status == null || !contains(String.valueOf(status), "timeout") && !contains(String.valueOf(status), "error");
    }

    private static boolean ragApplicabilityDeclared(FinalPromptMetricEvaluationContext context, FinalPromptMetricRule rule) {
        Map<String, Object> rag = ragResults(context);
        String ragText = ragText(context, rule);
        FinalPromptSnapshot prompt = context == null ? null : context.prompt();
        if (StringUtils.hasText(ragText) && promptRagStateDeclared(prompt)) {
            return true;
        }
        if ((rag == null || rag.isEmpty()) && !StringUtils.hasText(ragText)) {
            return false;
        }
        if (ragSearchExecuted(rag)) {
            Object status = firstPresent(rag, "status", "retrievalStatus", "ragRetrievalState");
            return status != null && StringUtils.hasText(ragText);
        }
        return ragAbsenceDeclared(context, rule);
    }

    private static boolean ragAbsenceDeclared(FinalPromptMetricEvaluationContext context, FinalPromptMetricRule rule) {
        Map<String, Object> rag = ragResults(context);
        FinalPromptSnapshot prompt = context == null ? null : context.prompt();
        if (retrievedDocumentCount(rag) > 0) {
            return false;
        }
        if (StringUtils.hasText(ragText(context, rule)) && promptRagStateDeclared(prompt)) {
            return true;
        }
        if (rag == null || rag.isEmpty()) {
            return !StringUtils.hasText(ragText(context, rule));
        }
        if (ragSearchExecuted(rag) || retrievedDocumentCount(rag) > 0 || StringUtils.hasText(ragText(context, rule))) {
            return StringUtils.hasText(ragText(context, rule));
        }
        Object reason = firstPresent(rag, "ragAbsenceReason", "absenceReason", "retrievalState", "ragRetrievalState");
        return reason != null && StringUtils.hasText(String.valueOf(reason)) && StringUtils.hasText(ragText(context, rule));
    }

    private static boolean promptRagStateDeclared(FinalPromptSnapshot prompt) {
        if (prompt == null) {
            return false;
        }
        String searchExecuted = firstPromptValue(prompt, "RagSearchExecuted");
        String applicability = firstPromptValue(prompt, "RagApplicability");
        String retrievalState = firstPromptValue(prompt, "RagRetrievalState");
        int relatedDocumentCount = asInt(firstPromptValue(prompt, "RelatedDocumentCount"));
        boolean hasSearchState = StringUtils.hasText(searchExecuted)
                || StringUtils.hasText(applicability)
                || StringUtils.hasText(retrievalState);
        boolean hasDeclaredResult = relatedDocumentCount > 0
                || contains(applicability, "DOCUMENTS_RETRIEVED")
                || contains(applicability, "ZERO_RESULTS")
                || contains(applicability, "NOT_EXECUTED")
                || contains(retrievalState, "AVAILABLE")
                || contains(retrievalState, "ZERO_RESULTS")
                || contains(retrievalState, "NOT_EXECUTED")
                || contains(retrievalState, "PERMISSION_FILTERED");
        return hasSearchState && hasDeclaredResult;
    }

    private static boolean ragDocumentSurfacePresent(
            FinalPromptMetricEvaluationContext context,
            FinalPromptMetricRule rule) {
        if (retrievedDocumentCount(ragResults(context)) > 0) {
            return true;
        }
        String ragText = ragText(context, rule);
        return StringUtils.hasText(ragText)
                && (contains(ragText, "RagDocument")
                || contains(ragText, "Document:")
                || contains(ragText, "\nDocument ")
                || ragText.trim().toLowerCase(Locale.ROOT).startsWith("document ")
                || contains(ragText, "relatedDocuments:"));
    }

    private static boolean ragProjectedWhenRetrieved(
            FinalPromptMetricEvaluationContext context,
            FinalPromptMetricRule rule) {
        Map<String, Object> rag = ragResults(context);
        int retrieved = retrievedDocumentCount(rag);
        if (retrieved <= 0) {
            return true;
        }
        Object projected = firstPresent(rag, "ragProjectedToFinalPrompt", "projectedToFinalPrompt");
        if (projected instanceof Boolean bool && !bool) {
            return false;
        }
        if (projected != null && "false".equalsIgnoreCase(String.valueOf(projected).trim())) {
            return false;
        }
        Object projectionState = firstPresent(rag, "ragProjectionState", "projectionState");
        if (projectionState != null && contains(String.valueOf(projectionState), "missing")) {
            return false;
        }
        requireContractTerms(rule, "RAG_PROJECTED_WHEN_RETRIEVED");
        return rule.terms().stream().anyMatch(term -> promptContains(context.prompt(), term));
    }

    private static boolean ragTextForbiddenTermsAbsent(
            FinalPromptMetricEvaluationContext context,
            FinalPromptMetricRule rule) {
        String ragText = ragText(context, rule);
        return rule.forbiddenTerms().stream().noneMatch(term -> contains(ragText, term));
    }

    private static boolean ragTextTermGroupsPresentWhenRagPresent(
            FinalPromptMetricEvaluationContext context,
            FinalPromptMetricRule rule
    ) {
        String ragText = ragText(context, rule);
        if (!StringUtils.hasText(ragText)) {
            return true;
        }
        return termGroupsPresent(ragText, rule.labelGroups());
    }

    private static boolean ragDocumentAuthorizationScopeAligned(
            FinalPromptMetricEvaluationContext context,
            FinalPromptMetricRule rule
    ) {
        if (!ragHasRetrievedDocuments(context, rule)) {
            return true;
        }
        List<Map<String, String>> documents = ragDocuments(context, rule);
        if (documents.isEmpty()) {
            return false;
        }
        RequestScope request = requestScope(context == null ? null : context.prompt());
        if (!request.hasTenant() || !request.hasUser() || !request.hasResource()) {
            return false;
        }
        return documents.stream().allMatch(document ->
                documentTenantMatches(document, request)
                        && documentUserMatches(document, request)
                        && documentResourceMatches(document, request)
                        && documentPurposeDeclared(document)
                        && documentAuthorized(document));
    }

    private static boolean ragDocumentRequestScopeAligned(
            FinalPromptMetricEvaluationContext context,
            FinalPromptMetricRule rule
    ) {
        if (!ragHasRetrievedDocuments(context, rule)) {
            return true;
        }
        List<Map<String, String>> documents = ragDocuments(context, rule);
        if (documents.isEmpty()) {
            return false;
        }
        RequestScope request = requestScope(context == null ? null : context.prompt());
        if (!request.hasTenant() || !request.hasResource()) {
            return false;
        }
        return documents.stream().allMatch(document ->
                documentTenantMatches(document, request)
                        && documentResourceMatches(document, request)
                        && documentPurposeDeclared(document));
    }

    private static boolean ragBlockedDocumentExcluded(
            FinalPromptMetricEvaluationContext context,
            FinalPromptMetricRule rule
    ) {
        String ragText = ragText(context, rule);
        boolean blockedMentioned = rule.terms().stream().anyMatch(term -> contains(ragText, term));
        if (!blockedMentioned) {
            return true;
        }
        return rule.thenTerms().stream().anyMatch(term -> contains(ragText, term));
    }

    private static boolean ragHasRetrievedDocuments(FinalPromptMetricEvaluationContext context, FinalPromptMetricRule rule) {
        Map<String, Object> rag = ragResults(context);
        if (retrievedDocumentCount(rag) > 0) {
            return true;
        }
        return ragDocumentSurfacePresent(context, rule);
    }

    private static List<Map<String, String>> ragDocuments(FinalPromptMetricEvaluationContext context, FinalPromptMetricRule rule) {
        List<Map<String, String>> documents = new ArrayList<>();
        addPromptRagDocuments(documents, context == null ? null : context.prompt());
        if (documents.isEmpty()) {
            Map<String, Object> rag = ragResults(context);
            addRagDocuments(documents, firstPresent(rag,
                    "ragDocument", "ragDocuments", "documents", "relatedDocuments", "retrievedDocuments", "authorizedDocuments"));
        }
        if (documents.isEmpty()) {
            String ragText = ragText(context, rule);
            for (String line : ragText.split("\\R+")) {
                if (contains(line, "RagDocument") || contains(line, "Document:")) {
                    Map<String, String> parsed = parseRagDocumentText(line);
                    if (!parsed.isEmpty()) {
                        documents.add(parsed);
                    }
                }
            }
        }
        return documents;
    }

    private static void addPromptRagDocuments(List<Map<String, String>> documents, FinalPromptSnapshot prompt) {
        if (documents == null || prompt == null) {
            return;
        }
        prompt.fields().stream()
                .filter(field -> field != null && StringUtils.hasText(field.label()))
                .filter(field -> field.label().trim().toLowerCase(Locale.ROOT).matches("ragdocument\\d+"))
                .map(FinalPromptField::value)
                .filter(StringUtils::hasText)
                .map(FinalPromptMetricRuleEngine::parseRagDocumentText)
                .filter(parsed -> parsed != null && !parsed.isEmpty())
                .forEach(documents::add);
    }

    private static void addRagDocuments(List<Map<String, String>> documents, Object value) {
        if (documents == null || value == null) {
            return;
        }
        if (value instanceof Iterable<?> iterable) {
            for (Object item : iterable) {
                addRagDocuments(documents, item);
            }
            return;
        }
        if (value instanceof Map<?, ?> map) {
            Map<String, String> document = new LinkedHashMap<>();
            map.forEach((key, entryValue) -> {
                if (key != null && entryValue != null && StringUtils.hasText(String.valueOf(entryValue))) {
                    document.put(String.valueOf(key).trim(), String.valueOf(entryValue).trim());
                }
            });
            if (!document.isEmpty()) {
                documents.add(document);
            }
            return;
        }
        Map<String, String> parsed = parseRagDocumentText(String.valueOf(value));
        if (!parsed.isEmpty()) {
            documents.add(parsed);
        }
    }

    private static Map<String, String> parseRagDocumentText(String text) {
        if (!StringUtils.hasText(text)) {
            return Map.of();
        }
        String body = text;
        int open = body.indexOf('[');
        int close = body.indexOf(']');
        if (open >= 0 && close > open) {
            body = body.substring(open + 1, close);
        }
        Map<String, String> values = new LinkedHashMap<>();
        for (String token : body.split("\\|\\s*|,\\s*")) {
            if (!StringUtils.hasText(token)) {
                continue;
            }
            int separator = token.indexOf('=');
            if (separator < 0) {
                separator = token.indexOf(':');
            }
            if (separator <= 0) {
                continue;
            }
            String key = token.substring(0, separator).trim();
            String value = token.substring(separator + 1).trim();
            if (StringUtils.hasText(key) && StringUtils.hasText(value)) {
                values.put(key, value);
            }
        }
        putIfAbsentText(values, "resource", namedTokenValue(text, "resource"));
        putIfAbsentText(values, "resourceFamily", namedTokenValue(text, "resourceFamily"));
        putIfAbsentText(values, "path", extractPathToken(text));
        putIfAbsentText(values, "pathFamily", namedTokenValue(text, "pathFamily"));
        return values;
    }

    private static void putIfAbsentText(Map<String, String> values, String key, String value) {
        if (values == null || !StringUtils.hasText(key) || !StringUtils.hasText(value)) {
            return;
        }
        values.putIfAbsent(key, value.trim());
    }

    private static String namedTokenValue(String text, String key) {
        if (!StringUtils.hasText(text) || !StringUtils.hasText(key)) {
            return "";
        }
        Matcher matcher = Pattern
                .compile("(?i)(?:^|[\\[\\],|\\s])" + Pattern.quote(key.trim())
                        + "\\s*(?:=|:)\\s*([^,|\\]\\s\\n\\r]+)")
                .matcher(text);
        return matcher.find() ? matcher.group(1).trim() : "";
    }

    private static String extractPathToken(String text) {
        if (!StringUtils.hasText(text)) {
            return "";
        }
        Matcher matcher = Pattern
                .compile("(/[^\\s,;|\\]]+)")
                .matcher(text);
        return matcher.find() ? matcher.group(1).trim() : "";
    }

    private static RequestScope requestScope(FinalPromptSnapshot prompt) {
        if (prompt == null) {
            return new RequestScope("", "", "", "", "", "", "");
        }
        return new RequestScope(
                firstPromptValue(prompt, "TenantId", "Tenant"),
                firstPromptValue(prompt, "UserId", "User"),
                firstPromptValue(prompt, "OrganizationId", "Organization"),
                firstPromptValue(prompt, "ResourceId", "Resource ID"),
                firstPromptValue(prompt, "RequestPath", "Path"),
                firstPromptValue(prompt, "CurrentResourceFamily", "ResourceFamily"),
                firstPromptValue(prompt, "CurrentPathFamily", "PathFamily"));
    }

    private static String firstPromptValue(FinalPromptSnapshot prompt, String... labels) {
        if (prompt == null || labels == null) {
            return "";
        }
        for (String label : labels) {
            String value = prompt.firstValue(label);
            if (StringUtils.hasText(value) && !looksPlaceholder(value)) {
                return value.trim();
            }
        }
        return "";
    }

    private static boolean documentTenantMatches(Map<String, String> document, RequestScope request) {
        String value = documentValue(document, "tenantId", "tenant");
        if (StringUtils.hasText(value)) {
            return normalizedEquals(value, request.tenant());
        }
        String tenantBound = documentValue(document, "tenantBound", "tenantMatched", "tenantScopeMatched");
        String mismatch = documentValue(document, "tenantMismatch", "tenantScopeMismatch");
        return truthy(tenantBound) && !truthy(mismatch);
    }

    private static boolean documentUserMatches(Map<String, String> document, RequestScope request) {
        String scope = documentValue(document, "accessScope", "scope");
        String value = documentValue(document, "userId", "user", "subjectId", "userScope");
        if (contains(scope, "USER")) {
            return StringUtils.hasText(value) && normalizedEquals(value, request.user());
        }
        return StringUtils.hasText(value) ? normalizedEquals(value, request.user()) : StringUtils.hasText(scope);
    }

    private static boolean documentResourceMatches(Map<String, String> document, RequestScope request) {
        String exactValue = documentValue(document, "resourceId", "resourceScope", "requestPath", "path");
        if (normalizedEquals(exactValue, request.resourceId()) || normalizedEquals(exactValue, request.requestPath())) {
            return true;
        }
        String resourceFamily = documentValue(document, "resourceFamily", "currentResourceFamily", "resourceType", "resourceCategory", "resource");
        if (normalizedEquals(resourceFamily, request.resourceFamily())) {
            return true;
        }
        String pathFamily = documentValue(document, "pathFamily", "requestPathFamily");
        return normalizedEquals(pathFamily, request.pathFamily())
                || pathFamilyCoversPath(pathFamily, request.requestPath())
                || pathFamilyCoversPath(request.pathFamily(), exactValue);
    }

    private static boolean documentPurposeDeclared(Map<String, String> document) {
        String purpose = documentValue(document, "retrievalPurpose", "purpose", "retrievalPolicy");
        return StringUtils.hasText(purpose) && !looksPlaceholder(purpose);
    }

    private static boolean documentAuthorized(Map<String, String> document) {
        String authorization = documentValue(document,
                "authorization", "authorizationDecision", "authorizationBasis", "authorizationReason",
                "authorized", "allowed", "auth");
        if (!StringUtils.hasText(authorization)) {
            return false;
        }
        String normalized = authorization.toLowerCase(Locale.ROOT);
        return (normalized.contains("allow") || normalized.contains("authorized") || normalized.contains("true"))
                && !normalized.contains("deny")
                && !normalized.contains("blocked")
                && !normalized.contains("unauthorized");
    }

    private static boolean truthy(String value) {
        if (!StringUtils.hasText(value)) {
            return false;
        }
        String normalized = value.trim().toLowerCase(Locale.ROOT);
        return normalized.equals("true")
                || normalized.equals("yes")
                || normalized.equals("y")
                || normalized.equals("1")
                || normalized.equals("matched")
                || normalized.equals("bound");
    }

    private static String documentValue(Map<String, String> document, String... aliases) {
        if (document == null || aliases == null) {
            return "";
        }
        for (String alias : aliases) {
            for (Map.Entry<String, String> entry : document.entrySet()) {
                if (entry.getKey() != null && alias.equalsIgnoreCase(entry.getKey().trim())
                        && StringUtils.hasText(entry.getValue())) {
                    return entry.getValue().trim();
                }
            }
        }
        return "";
    }

    private static boolean normalizedEquals(String actual, String expected) {
        String left = normalizeScopeValue(actual);
        String right = normalizeScopeValue(expected);
        return StringUtils.hasText(left) && left.equals(right);
    }

    private static boolean pathFamilyCoversPath(String family, String path) {
        String normalizedFamily = normalizeScopeValue(family);
        String normalizedPath = normalizeScopeValue(path);
        if (!StringUtils.hasText(normalizedFamily) || !StringUtils.hasText(normalizedPath)) {
            return false;
        }
        if (!normalizedFamily.endsWith("/*")) {
            return normalizedFamily.equals(normalizedPath);
        }
        String prefix = normalizedFamily.substring(0, normalizedFamily.length() - 1);
        return normalizedPath.startsWith(prefix);
    }

    private static String normalizeScopeValue(String value) {
        if (!StringUtils.hasText(value)) {
            return "";
        }
        return value.trim()
                .replaceAll("^/+", "")
                .replaceAll("/+$", "")
                .toLowerCase(Locale.ROOT);
    }

    private record RequestScope(
            String tenant,
            String user,
            String organization,
            String resourceId,
            String requestPath,
            String resourceFamily,
            String pathFamily) {
        boolean hasTenant() {
            return StringUtils.hasText(tenant);
        }

        boolean hasUser() {
            return StringUtils.hasText(user);
        }

        boolean hasResource() {
            return StringUtils.hasText(resourceId) || StringUtils.hasText(requestPath);
        }
    }

    private static String ragText(FinalPromptMetricEvaluationContext context, FinalPromptMetricRule rule) {
        if (context == null || context.prompt() == null) {
            return "";
        }
        requireContractSections(rule, "RAG_EVIDENCE_SURFACE");
        StringBuilder builder = new StringBuilder();
        for (String section : rule.sections()) {
            context.prompt().fields().stream()
                    .filter(field -> sameSection(field.section(), section))
                    .forEach(field -> builder.append(field.label()).append(' ').append(field.value()).append('\n'));
            context.prompt().bullets().stream()
                    .filter(bullet -> sameSection(bullet.section(), section))
                    .forEach(bullet -> builder.append(bullet.text()).append('\n'));
            context.prompt().narrativeLines().stream()
                    .filter(line -> sameSection(line.section(), section))
                    .forEach(line -> builder.append(line.text()).append('\n'));
        }
        return builder.toString();
    }

    private static void requireContractSections(FinalPromptMetricRule rule, String operator) {
        if (rule == null || rule.sections().isEmpty()) {
            throw new IllegalStateException("RAG metric rule requires contract-defined sections. operator=" + operator);
        }
    }

    private static void requireContractTerms(FinalPromptMetricRule rule, String operator) {
        if (rule == null || rule.terms().isEmpty()) {
            throw new IllegalStateException("RAG metric rule requires contract-defined terms. operator=" + operator);
        }
    }

    private static boolean promptArtifactsTraceable(FinalPromptMetricEvaluationContext context) {
        FinalPromptEvidenceContext evidence = context.evidence();
        return context.prompt() != null
                && evidence != null
                && StringUtils.hasText(evidence.packageId())
                && StringUtils.hasText(evidence.correlationId())
                && StringUtils.hasText(evidence.systemPrompt())
                && StringUtils.hasText(context.prompt().userPrompt())
                && StringUtils.hasText(evidence.systemPromptHash())
                && StringUtils.hasText(evidence.userPromptHash());
    }

    private static boolean rawFinalLineageTraceable(FinalPromptMetricEvaluationContext context) {
        FinalPromptEvidenceContext evidence = context.evidence();
        return evidence != null
                && StringUtils.hasText(evidence.rawSystemPrompt())
                && StringUtils.hasText(evidence.rawUserPrompt())
                && StringUtils.hasText(evidence.systemPromptHash())
                && StringUtils.hasText(evidence.userPromptHash())
                && StringUtils.hasText(evidence.rawSystemPromptHash())
                && StringUtils.hasText(evidence.rawUserPromptHash());
    }

    private static boolean resourceTemplateTokenAbsent(FinalPromptSnapshot prompt) {
        if (prompt == null) {
            return false;
        }
        boolean hasActualResourceValue = hasPurposeValue(prompt, "ResourceId")
                || hasPurposeValue(prompt, "RequestPath");
        if (!hasActualResourceValue) {
            return false;
        }
        String combined = String.join(" ",
                safe(prompt.firstValue("ResourceId")),
                safe(prompt.firstValue("RequestPath")),
                safe(prompt.firstValue("Path")));
        return !contains(combined, "{resourceId}");
    }

    private static boolean sensitiveFlagConsistent(FinalPromptSnapshot prompt) {
        if (prompt == null) {
            return false;
        }
        if (!hasPurposeValue(prompt, "Sensitivity") || !hasPurposeValue(prompt, "SensitiveResource")) {
            return false;
        }
        String sensitivity = safe(prompt.firstValue("Sensitivity"));
        boolean highSensitivity = normalize(sensitivity).contains("HIGH") || normalize(sensitivity).contains("CRITICAL");
        for (String value : valuesByLabel(prompt, "Sensitivity")) {
            if (!valuePurposeDecidable(prompt, "Sensitivity", value)) {
                return false;
            }
            String normalized = normalize(value);
            highSensitivity = highSensitivity || normalized.contains("HIGH") || normalized.contains("CRITICAL");
        }
        for (String value : valuesByLabel(prompt, "SensitiveResource")) {
            if (!valuePurposeDecidable(prompt, "SensitiveResource", value) || normalizeBoolean(value) == null) {
                return false;
            }
        }
        if (highSensitivity) {
            return valuesByLabel(prompt, "SensitiveResource").stream()
                    .noneMatch(value -> "FALSE".equals(normalizeBoolean(value)));
        }
        return true;
    }

    private static Object firstPresent(Map<String, Object> values, String... keys) {
        if (values == null || values.isEmpty()) {
            return null;
        }
        for (String key : keys) {
            if (values.containsKey(key)) {
                return values.get(key);
            }
        }
        return null;
    }

    private static boolean asBoolean(Object value) {
        if (value instanceof Boolean bool) {
            return bool;
        }
        return value != null && "true".equalsIgnoreCase(String.valueOf(value).trim());
    }

    private static int asInt(Object value) {
        if (value instanceof Number number) {
            return number.intValue();
        }
        if (value == null) {
            return 0;
        }
        try {
            return Integer.parseInt(String.valueOf(value).trim());
        }
        catch (NumberFormatException ignored) {
            return 0;
        }
    }

    private static boolean sameSection(String actual, String expected) {
        String actualNorm = FinalPromptSnapshot.normalizeSection(actual);
        String expectedNorm = FinalPromptSnapshot.normalizeSection(expected);
        return actualNorm.equals(expectedNorm);
    }

    private static String normalize(String value) {
        return value == null ? "" : value.trim().toUpperCase(Locale.ROOT);
    }

    private static String normalizeScalar(String value) {
        return value == null ? "" : value.trim().toLowerCase(Locale.ROOT);
    }

    private static String normalizeComparableValue(String value) {
        String normalized = normalizeScalar(value);
        if (!normalized.startsWith("/") && normalized.matches("^[a-z][a-z0-9 ._-]*/[0-9].*")) {
            normalized = normalized.substring(0, normalized.indexOf('/'));
        }
        return normalized.replace("windows", "window").replaceAll("\\s+", " ");
    }

    private static String normalizeBoolean(String value) {
        String normalized = normalize(value);
        if (normalized.equals("TRUE") || normalized.equals("FALSE")) {
            return normalized;
        }
        if (normalized.equals("YES") || normalized.equals("Y")) {
            return "TRUE";
        }
        if (normalized.equals("NO") || normalized.equals("N")) {
            return "FALSE";
        }
        return null;
    }

    private static List<String> valuesByLabel(FinalPromptSnapshot prompt, String label) {
        if (prompt == null || !StringUtils.hasText(label)) {
            return List.of();
        }
        return prompt.fieldsByLabel(label).stream()
                .map(FinalPromptField::value)
                .filter(StringUtils::hasText)
                .toList();
    }

    private static String safe(String value) {
        return value == null ? "" : value;
    }

    private static int safeMin(Integer value) {
        return value == null ? 1 : value;
    }

    private static Map<String, Object> ragResults(FinalPromptMetricEvaluationContext context) {
        FinalPromptEvidenceContext evidence = context == null ? null : context.evidence();
        return evidence == null ? Map.of() : evidence.ragResults();
    }

    private static boolean ragUsed(FinalPromptMetricEvaluationContext context, FinalPromptMetricRule rule) {
        Map<String, Object> rag = ragResults(context);
        return ragSearchExecuted(rag) || retrievedDocumentCount(rag) > 0 || StringUtils.hasText(ragText(context, rule));
    }

    private static boolean ragSearchExecuted(Map<String, Object> rag) {
        if (rag == null || rag.isEmpty()) {
            return false;
        }
        Object executed = firstPresent(rag, "ragSearchExecuted", "searchExecuted", "retrievalExecuted");
        if (executed instanceof Boolean bool) {
            return bool;
        }
        if (executed != null) {
            return "true".equalsIgnoreCase(String.valueOf(executed).trim());
        }
        Object status = firstPresent(rag, "status", "retrievalStatus", "ragRetrievalState");
        if (status == null) {
            return retrievedDocumentCount(rag) > 0;
        }
        String normalized = normalize(String.valueOf(status));
        return !normalized.contains("NOT_EXECUTED") && !normalized.contains("NOT EXECUTED");
    }

    private static int retrievedDocumentCount(Map<String, Object> rag) {
        if (rag == null || rag.isEmpty()) {
            return 0;
        }
        return asInt(firstPresent(rag,
                "retrievedDocumentCount",
                "authorizedDocumentCount",
                "allowedDocumentCount",
                "relatedDocumentCount"));
    }

    private static String systemPrompt(FinalPromptMetricEvaluationContext context) {
        FinalPromptEvidenceContext evidence = context == null ? null : context.evidence();
        return evidence == null ? null : evidence.systemPrompt();
    }

    private static String userPrompt(FinalPromptMetricEvaluationContext context) {
        FinalPromptSnapshot prompt = context == null ? null : context.prompt();
        return prompt == null ? null : prompt.userPrompt();
    }

    private static String promptEvidenceManifestJson(FinalPromptMetricEvaluationContext context) {
        FinalPromptEvidenceContext evidence = context == null ? null : context.evidence();
        return evidence == null ? null : evidence.promptEvidenceManifestJson();
    }

    private static boolean preflightReady(FinalPromptMetricEvaluationContext context) {
        FinalPromptEvidenceContext evidence = context == null ? null : context.evidence();
        return evidence != null && evidence.preflight() != null && evidence.preflight().ready();
    }
}
