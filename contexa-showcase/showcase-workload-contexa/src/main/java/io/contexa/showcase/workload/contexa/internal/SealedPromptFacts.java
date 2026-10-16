package io.contexa.showcase.workload.contexa.internal;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
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

/**
 * W6-1 (P6-CHANGE-2): the sealed prompt of a decision as the harness reads it. The user prompt is read line by line by
 * the OSS prompt parser; every entry line names the source grades its dictionary entry declares. The bundle is the one
 * the seal's governance descriptor names, the reason codes are the sealed decision's and the inspection is the latest
 * stored one. The portal has no engine library, so control D gives these facts (P7 screens read the same view).
 */
final class SealedPromptFacts {

    private static final Logger log = LoggerFactory.getLogger(SealedPromptFacts.class);
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
        view.put("lines", lines(sealed.getUserPromptText()));
        view.put("inspection", latest(inspections));
        return view;
    }

    private static List<Map<String, Object>> lines(String userPrompt) {
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
            view.put("grades", grades(line));
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
