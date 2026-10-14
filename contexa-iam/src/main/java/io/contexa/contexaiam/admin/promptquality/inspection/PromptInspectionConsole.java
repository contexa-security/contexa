package io.contexa.contexaiam.admin.promptquality.inspection;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.contexa.contexacore.verification.evidence.SealedEvidencePackage;
import io.contexa.contexacore.verification.evidence.SealedEvidencePackageRepository;
import io.contexa.contexacore.verification.inspection.InspectedPrompt;
import io.contexa.contexacore.verification.inspection.PromptInspectionCheckResult;
import io.contexa.contexacore.verification.inspection.PromptInspectionFinding;
import io.contexa.contexacore.verification.inspection.PromptInspectionRecord;
import io.contexa.contexacore.verification.inspection.PromptInspectionResult;
import io.contexa.contexacore.verification.inspection.PromptInspectionResultStore;
import io.contexa.contexacore.verification.inspection.PromptInspector;

import java.time.Instant;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;

/**
 * The inspection detail of one sealed package: the user prompt the model got, line by line, inspected again with this
 * inspector so each line shows the checks that matched it and the findings on it; the stored results; and what changed
 * from the newest stored result of another inspector version (or the newest stored result when there is none): the
 * findings gone and the new ones. Inspecting again stores nothing.
 */
public class PromptInspectionConsole {

    private static final TypeReference<Map<String, Object>> MAP = new TypeReference<>() {
    };

    private final SealedEvidencePackageRepository packages;
    private final PromptInspector inspector;
    private final PromptInspectionResultStore results;
    private final ObjectMapper objectMapper;

    public PromptInspectionConsole(SealedEvidencePackageRepository packages, PromptInspector inspector,
                                   PromptInspectionResultStore results, ObjectMapper objectMapper) {
        this.packages = Objects.requireNonNull(packages, "packages");
        this.inspector = Objects.requireNonNull(inspector, "inspector");
        this.results = Objects.requireNonNull(results, "results");
        this.objectMapper = Objects.requireNonNull(objectMapper, "objectMapper");
    }

    /** A line of the user prompt with the checks that matched it and the findings on it. */
    public record LineView(int number, String text, String block, List<String> matchedBy,
                           List<PromptInspectionFinding> findings) {
    }

    public record CheckView(String checkCode, int matched, int mismatched, int unverifiable) {
    }

    /**
     * The newest stored result as it stands beside the inspection again.
     *
     * @param sameInspector whether it was stored by this inspector version
     * @param sameFindings  whether its findings are the findings of the inspection again
     */
    public record StoredView(String verdict, String inspectorVersion, Instant inspectedAt, String trigger,
                             boolean sameInspector, boolean sameFindings) {
    }

    public record HistoryView(String inspectorVersion, String dictionaryVersion, String verdict,
                              int mismatchCount, int unverifiableCount, String trigger, Instant inspectedAt) {
    }

    /**
     * What the inspection again finds other than a stored result.
     *
     * @param disappeared the stored result's findings the inspection again does not make
     * @param appeared    the findings of the inspection again the stored result does not hold
     */
    public record Changes(String comparedVersion, Instant comparedAt, List<PromptInspectionFinding> disappeared,
                          List<PromptInspectionFinding> appeared) {
    }

    public record Detail(String packageId, Instant capturedAt, String userId, String httpMethod,
                         String requestPath, String resourceId, String verdict, String inspectorVersion,
                         String dictionaryVersion, String layoutVersion, String errorReason, List<CheckView> checks,
                         List<LineView> lines, List<PromptInspectionFinding> unplacedFindings, StoredView stored,
                         Changes changes, List<HistoryView> history) {
    }

    public Optional<Detail> detail(String packageId) {
        return packages.findByPackageId(packageId).map(this::detail);
    }

    private Detail detail(SealedEvidencePackage evidencePackage) {
        PromptInspectionResult current = inspector.inspect(evidencePackage);
        Map<Integer, List<String>> matchedBy = new LinkedHashMap<>();
        Map<Integer, List<PromptInspectionFinding>> findingsByLine = new LinkedHashMap<>();
        List<PromptInspectionFinding> unplaced = new ArrayList<>();
        List<CheckView> checks = new ArrayList<>();
        for (PromptInspectionCheckResult check : current.checks()) {
            checks.add(new CheckView(check.checkCode(), check.matched(), check.mismatched(), check.unverifiable()));
            for (Integer number : check.matchedLines()) {
                List<String> codes = matchedBy.computeIfAbsent(number, key -> new ArrayList<>());
                if (!codes.contains(check.checkCode())) {
                    codes.add(check.checkCode());
                }
            }
            for (PromptInspectionFinding finding : check.findings()) {
                if (finding.lineNumber() == null) {
                    unplaced.add(finding);
                }
                else {
                    findingsByLine.computeIfAbsent(finding.lineNumber(), key -> new ArrayList<>()).add(finding);
                }
            }
        }
        List<LineView> lines = new ArrayList<>();
        String prompt = evidencePackage.getUserPromptText();
        if (prompt != null) {
            for (InspectedPrompt.Line line : InspectedPrompt.parse(prompt).lines()) {
                lines.add(new LineView(line.number(), line.text(),
                        line.block() != null ? line.block().title() : null,
                        List.copyOf(matchedBy.getOrDefault(line.number(), List.of())),
                        List.copyOf(findingsByLine.getOrDefault(line.number(), List.of()))));
            }
        }
        List<PromptInspectionRecord> stored = results.findAll(evidencePackage.getPackageId());
        Map<String, Object> request = read(evidencePackage.getRequestFactsJson());
        return new Detail(evidencePackage.getPackageId(), evidencePackage.getCapturedAt(), evidencePackage.getUserId(),
                text(request.get("httpMethod")), text(request.get("requestPath")),
                text(request.get("resourceId")), current.verdict().name(), current.inspectorVersion(),
                current.dictionaryVersion(), current.layoutVersion(), current.errorReason(), checks, lines,
                unplaced, storedView(stored, current), changes(stored, current), history(stored));
    }

    private static StoredView storedView(List<PromptInspectionRecord> stored, PromptInspectionResult current) {
        if (stored.isEmpty()) {
            return null;
        }
        PromptInspectionRecord newest = stored.get(0);
        boolean sameInspector = Objects.equals(newest.result().inspectorVersion(), current.inspectorVersion());
        return new StoredView(newest.result().verdict().name(), newest.result().inspectorVersion(),
                newest.inspectedAt(), newest.trigger().name(), sameInspector,
                sameInspector && without(newest.result().findings(), current.findings()).isEmpty()
                        && without(current.findings(), newest.result().findings()).isEmpty());
    }

    /** Against the newest stored result of another inspector version, or the newest stored result when none is. */
    private static Changes changes(List<PromptInspectionRecord> stored, PromptInspectionResult current) {
        if (stored.isEmpty()) {
            return null;
        }
        PromptInspectionRecord compared = stored.stream()
                .filter(record -> !Objects.equals(record.result().inspectorVersion(), current.inspectorVersion()))
                .findFirst().orElse(stored.get(0));
        return new Changes(compared.result().inspectorVersion(), compared.inspectedAt(),
                without(compared.result().findings(), current.findings()),
                without(current.findings(), compared.result().findings()));
    }

    /**
     * The findings of the first list not in the second, compared by kind (W3-20: a stored result keeps its findings as
     * kinds with their lines, not the lines' numbers and values), each match taking one finding out.
     */
    private static List<PromptInspectionFinding> without(List<PromptInspectionFinding> findings,
                                                         List<PromptInspectionFinding> others) {
        List<List<Object>> remaining = new ArrayList<>(others.stream().map(PromptInspectionConsole::kind).toList());
        List<PromptInspectionFinding> left = new ArrayList<>();
        for (PromptInspectionFinding finding : findings) {
            if (!remaining.remove(kind(finding))) {
                left.add(finding);
            }
        }
        return List.copyOf(left);
    }

    /** What makes findings one kind: the check, outcome, block, entry and reason. */
    private static List<Object> kind(PromptInspectionFinding finding) {
        return Arrays.asList(finding.checkCode(), finding.outcome(), finding.block(), finding.entry(), finding.reason());
    }

    private static List<HistoryView> history(List<PromptInspectionRecord> stored) {
        return stored.stream()
                .map(record -> new HistoryView(record.result().inspectorVersion(), record.result().dictionaryVersion(),
                        record.result().verdict().name(), record.result().mismatchCount(),
                        record.result().unverifiableCount(), record.trigger().name(), record.inspectedAt()))
                .toList();
    }

    private Map<String, Object> read(String json) {
        if (json == null || json.isBlank()) {
            return Map.of();
        }
        try {
            Map<String, Object> map = objectMapper.readValue(json, MAP);
            return map == null ? Map.of() : map;
        }
        catch (Exception exception) {
            // Unreadable request facts leave the request fields empty; the seal integrity check shows the change.
            return Map.of();
        }
    }

    private static String text(Object value) {
        return value == null ? null : value.toString();
    }
}
