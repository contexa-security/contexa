package io.contexa.contexacore.autonomous.exception;

import org.springframework.util.StringUtils;

import java.util.ArrayList;
import java.util.List;
import java.util.Locale;

public class IntentSemanticClassifier {

    private final ObjectiveResourceCompatibilityCatalog compatibilityCatalog;

    public IntentSemanticClassifier() {
        this(new ObjectiveResourceCompatibilityCatalog());
    }

    public IntentSemanticClassifier(ObjectiveResourceCompatibilityCatalog compatibilityCatalog) {
        this.compatibilityCatalog = compatibilityCatalog;
    }

    public ObjectiveSemanticProfile classify(
            String taskIntent,
            String taskPurpose,
            String objectiveFamily,
            String toolName,
            String argumentsSummary,
            String requestedOperation,
            String resourceFamily,
            String requiredScope) {
        ObjectiveResourceCompatibilityCatalog.ObjectiveContract contract = compatibilityCatalog.resolve(objectiveFamily);
        String resolvedOperation = compatibilityCatalog.resolveOperation(requestedOperation, toolName, argumentsSummary, requiredScope);
        String resolvedResourceFamily = compatibilityCatalog.resolveResourceFamily(
                resourceFamily,
                requiredScope,
                toolName,
                toolName,
                argumentsSummary);
        String objectiveSurface = join(taskIntent, taskPurpose, objectiveFamily);
        boolean readOnlyObjective = contract.readOnlyObjective() || containsAny(objectiveSurface, "summary", "read", "query", "search");
        boolean containmentObjective = contract.containmentObjective() || containsAny(objectiveSurface, "incident", "containment", "response", "remediate");
        boolean learningObjective = contract.learningObjective() || containsAny(objectiveSurface, "ingest", "learning", "feedback", "telemetry", "audit");
        boolean exportOperation = compatibilityCatalog.isExportOperation(resolvedOperation);
        boolean mutatingOperation = compatibilityCatalog.isMutatingOperation(resolvedOperation);

        List<String> semanticFacts = new ArrayList<>();
        semanticFacts.add(String.format(
                Locale.ROOT,
                "Objective %s resolves to operation=%s, resourceFamily=%s, known=%s.",
                safeValue(objectiveFamily, "UNSPECIFIED"),
                resolvedOperation,
                resolvedResourceFamily,
                contract.known()));
        if (readOnlyObjective) {
            semanticFacts.add("Objective semantic profile is read-only.");
        }
        if (containmentObjective) {
            semanticFacts.add("Objective semantic profile is containment-oriented.");
        }
        if (learningObjective) {
            semanticFacts.add("Objective semantic profile is learning or audit oriented.");
        }
        if (exportOperation) {
            semanticFacts.add("Resolved operation contains export semantics.");
        }
        if (mutatingOperation && !exportOperation) {
            semanticFacts.add("Resolved operation mutates protected state.");
        }

        return new ObjectiveSemanticProfile(
                safeValue(objectiveFamily, "UNSPECIFIED"),
                resolvedOperation,
                resolvedResourceFamily,
                contract.known(),
                readOnlyObjective,
                containmentObjective,
                learningObjective,
                mutatingOperation,
                exportOperation,
                semanticFacts);
    }

    private boolean containsAny(String value, String... tokens) {
        if (!StringUtils.hasText(value) || tokens == null) {
            return false;
        }
        String normalized = value.trim().toLowerCase(Locale.ROOT);
        for (String token : tokens) {
            if (StringUtils.hasText(token) && normalized.contains(token.trim().toLowerCase(Locale.ROOT))) {
                return true;
            }
        }
        return false;
    }

    private String join(String... values) {
        if (values == null || values.length == 0) {
            return "";
        }
        StringBuilder builder = new StringBuilder();
        for (String value : values) {
            if (StringUtils.hasText(value)) {
                if (!builder.isEmpty()) {
                    builder.append(' ');
                }
                builder.append(value.trim());
            }
        }
        return builder.toString();
    }

    private String safeValue(String value, String fallback) {
        return StringUtils.hasText(value) ? value.trim() : fallback;
    }
}
