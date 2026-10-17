package io.contexa.showcase.workload.contexa.internal;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.contexa.contexacore.autonomous.context.prompt.PromptBlock;
import io.contexa.contexacore.autonomous.context.prompt.PromptDictionaryEntry;
import io.contexa.contexacore.autonomous.context.prompt.PromptSourceGrade;
import io.contexa.contexacore.autonomous.tiered.prompt.SecurityDecisionPromptDictionary;
import io.contexa.contexacore.verification.evidence.SealedEvidencePackage;
import io.contexa.contexacore.verification.inspection.InspectedPrompt;
import io.contexa.contexacore.verification.inspection.PromptInspectionCheckResult;
import io.contexa.contexacore.verification.inspection.PromptInspectionFinding;
import io.contexa.contexacore.verification.inspection.PromptInspectionOutcome;
import io.contexa.contexacore.verification.inspection.PromptInspectionRecord;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.ArrayList;
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * W6-1 (P6-CHANGE-2): the sealed prompt of a decision as the harness reads it. The user prompt is read line by line by
 * the OSS prompt parser; every entry line names the source grades its dictionary entry declares. The bundle is the one
 * the seal's governance descriptor names, the reason codes are the sealed decision's and the inspection is the latest
 * stored one. The portal has no engine library, so control D gives these facts (P7 screens read the same view).
 * N-DLV-2: the kinds of company record the host looked up and the request's action family (the sealed context's
 * friction profile and resource), so the harness tells a condition the operation does not look up.
 * N-SRC-4: the request's action line also names the grade of its own value (its entry allows HOST and INFERRED), as
 * the sealed context states the action family's source, so the source a visitor sees is the value's, not the entry's
 * first grade.
 */
final class SealedPromptFacts {

    private static final Logger log = LoggerFactory.getLogger(SealedPromptFacts.class);
    /** N-SRC-4: the request block's action line, whose value states the grade of its own source. */
    private static final String ACTION = "Action";
    /** N-SRC-5: the decision fact whose value states the stage its effect came from, in brackets. */
    private static final String AUTHORIZATION_EFFECT = "AuthorizationEffect";
    private static final Pattern EFFECT_STAGE = Pattern.compile("\\(([A-Z_]+)\\)");
    /** N-SRC-5: the session lines only the host's official request fields give. */
    private static final Set<String> HOST_ONLY_SESSION = Set.of("ConcurrentSessions", "PasswordAge");
    /** N-SRC-5: the session line the host gives or the core counts; the seal does not say which. */
    private static final String RECENT_SENSITIVE_ACCESS = "RecentSensitiveAccess";
    private static final TypeReference<Map<String, Object>> MAP = new TypeReference<>() {
    };

    private SealedPromptFacts() {
    }

    static Map<String, Object> view(SealedEvidencePackage sealed, List<PromptInspectionRecord> inspections,
                                    ObjectMapper objectMapper) {
        Map<String, Object> view = new LinkedHashMap<>();
        view.put("packageId", sealed.getPackageId());
        view.put("requestId", sealed.getCorrelationId());
        view.put("capturedAt", sealed.getCapturedAt() != null ? sealed.getCapturedAt().toString() : null);
        view.put("packageHash", sealed.getPackageHash());
        Map<String, Object> descriptor = descriptor(read(sealed, "promptExecutionMetadataJson",
                sealed.getPromptExecutionMetadataJson(), objectMapper));
        for (String key : List.of("promptBundleVersion", "promptBundleHash", "promptBundleSelectionSource",
                "userPromptLayoutVersion")) {
            view.put(key, descriptor.get(key));
        }
        Object reasonCodes = read(sealed, "decisionJson", sealed.getDecisionJson(), objectMapper).get("reasonCodes");
        view.put("reasonCodes", reasonCodes instanceof List<?> codes ? codes : List.of());
        Map<String, Object> context = read(sealed, "canonicalContextJson", sealed.getCanonicalContextJson(),
                objectMapper);
        view.put("lines", lines(sealed.getUserPromptText(), context));
        view.put("checkedRecordKinds", checkedRecordKinds(context));
        view.put("actionFamily", context.get("resource") instanceof Map<?, ?> resource
                && resource.get("actionFamily") instanceof String family ? family : null);
        view.put("inspection", latest(inspections));
        return view;
    }

    private static List<Map<String, Object>> lines(String userPrompt, Map<String, Object> context) {
        List<Map<String, Object>> lines = new ArrayList<>();
        for (InspectedPrompt.Line line : InspectedPrompt.parse(userPrompt).lines()) {
            if (line.kind() != InspectedPrompt.Kind.ENTRY || line.entryLine() == null) {
                continue;
            }
            Map<String, Object> view = new LinkedHashMap<>();
            view.put("number", line.number());
            view.put("block", line.block() != null ? line.block().name() : null);
            view.put("factId", line.factId());
            view.put("label", line.entryLine().label());
            view.put("value", line.entryLine().value());
            List<String> grades = grades(line);
            view.put("grades", grades);
            String label = line.entryLine().label();
            if (line.block() == PromptBlock.REQUEST && ACTION.equals(label)) {
                view.put("source", actionSource(context, grades));
            }
            else if (line.block() == PromptBlock.DECISION_FACTS && AUTHORIZATION_EFFECT.equals(label)) {
                view.put("source", effectSource(line.entryLine().value(), grades));
            }
            else if (line.block() == PromptBlock.SESSION && HOST_ONLY_SESSION.contains(label)) {
                view.put("source", declared(PromptSourceGrade.HOST, grades));
            }
            else if (line.block() == PromptBlock.SESSION && RECENT_SENSITIVE_ACCESS.equals(label)) {
                view.put("source", null);
            }
            lines.add(view);
        }
        return lines;
    }

    /** The source grades the dictionary entry of the line declares, in the grade order; empty without an entry. */
    private static List<String> grades(InspectedPrompt.Line line) {
        for (PromptDictionaryEntry entry : SecurityDecisionPromptDictionary.ENTRIES) {
            if (entry.block() == line.block() && entry.matchesLabel(line.entryLine().label())) {
                return entry.grades().stream().sorted(Comparator.comparing(PromptSourceGrade::ordinal))
                        .map(Enum::name).toList();
            }
        }
        return List.of();
    }

    /**
     * N-SRC-4: the grade of the request's action: the grade the sealed context states for its source
     * ({@code resource.actionFamilySource}, {@code <grade word>:<key>} of core ActionFamilyResolver, the source the
     * line's value states too), when the line's entry declares that grade; null when the context states none (the
     * value then says the source is not stated) or a grade the entry does not declare.
     */
    private static String actionSource(Map<String, Object> context, List<String> grades) {
        Object source = context.get("resource") instanceof Map<?, ?> resource
                ? resource.get("actionFamilySource") : null;
        if (!(source instanceof String stated) || stated.isBlank()) {
            return null;
        }
        int separator = stated.indexOf(':');
        String word = (separator < 0 ? stated : stated.substring(0, separator)).trim();
        for (PromptSourceGrade grade : PromptSourceGrade.values()) {
            if (grade.word().equalsIgnoreCase(word)) {
                return grades.contains(grade.name()) ? grade.name() : null;
            }
        }
        return null;
    }

    /**
     * N-SRC-5 (the dictionary document's rule): the grade of an authorization effect is that of the stage the line
     * states, an effect the core took from the method authorization ({@code METHOD_AUTHORIZATION_*}) computed and a
     * host stamp ({@code BRIDGE_AUTHORIZATION_STAMP}) host, when the entry declares it; null without a stage.
     */
    private static String effectSource(String value, List<String> grades) {
        Matcher stage = value != null ? EFFECT_STAGE.matcher(value) : null;
        if (stage == null || !stage.find()) {
            return null;
        }
        if (stage.group(1).startsWith("METHOD_AUTHORIZATION_")) {
            return declared(PromptSourceGrade.COMPUTED, grades);
        }
        return "BRIDGE_AUTHORIZATION_STAMP".equals(stage.group(1)) ? declared(PromptSourceGrade.HOST, grades) : null;
    }

    private static String declared(PromptSourceGrade grade, List<String> grades) {
        return grades.contains(grade.name()) ? grade.name() : null;
    }

    private static Map<String, Object> latest(List<PromptInspectionRecord> inspections) {
        if (inspections == null || inspections.isEmpty()) {
            return null;
        }
        PromptInspectionRecord record = inspections.stream()
                .max(Comparator.comparing(PromptInspectionRecord::inspectedAt)).orElseThrow();
        Map<String, Object> view = new LinkedHashMap<>();
        view.put("verdict", record.result().verdict().name());
        view.put("inspectorVersion", record.result().inspectorVersion());
        view.put("inspectedAt", record.inspectedAt().toString());
        List<Map<String, Object>> checks = new ArrayList<>();
        for (PromptInspectionCheckResult check : record.result().checks()) {
            Map<String, Object> checkView = new LinkedHashMap<>();
            checkView.put("code", check.checkCode());
            checkView.put("matched", check.matched());
            checkView.put("mismatched", check.mismatched());
            checkView.put("unverifiable", check.unverifiable());
            List<Map<String, Object>> mismatches = new ArrayList<>();
            for (PromptInspectionFinding finding : check.findings()) {
                if (finding.outcome() != PromptInspectionOutcome.MISMATCH) {
                    continue;
                }
                Map<String, Object> findingView = new LinkedHashMap<>();
                findingView.put("block", finding.block());
                findingView.put("entry", finding.entry());
                findingView.put("factId", finding.factId());
                findingView.put("line", finding.lineNumber());
                findingView.put("expected", finding.expected());
                findingView.put("actual", finding.actual());
                findingView.put("reason", finding.reason());
                mismatches.add(findingView);
            }
            checkView.put("mismatches", mismatches);
            checks.add(checkView);
        }
        view.put("checks", checks);
        return view;
    }

    /** The record kinds of the sealed context's friction profile; null when the context does not say (N-DLV-2). */
    private static List<String> checkedRecordKinds(Map<String, Object> context) {
        if (context.get("frictionProfile") instanceof Map<?, ?> friction
                && friction.get("checkedRecordKinds") instanceof List<?> kinds) {
            return kinds.stream().map(String::valueOf).toList();
        }
        return null;
    }

    @SuppressWarnings("unchecked")
    private static Map<String, Object> descriptor(Map<String, Object> metadata) {
        return metadata.get("governanceDescriptor") instanceof Map<?, ?> descriptor
                ? (Map<String, Object>) descriptor : Map.of();
    }

    private static Map<String, Object> read(SealedEvidencePackage sealed, String column, String json,
                                            ObjectMapper objectMapper) {
        if (json == null || json.isBlank()) {
            return Map.of();
        }
        try {
            return objectMapper.readValue(json, MAP);
        } catch (Exception e) {
            log.error("Sealed package column unreadable: packageId={}, column={}", sealed.getPackageId(), column, e);
            return Map.of();
        }
    }
}
