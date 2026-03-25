package io.contexa.contexacore.autonomous.context;

import io.contexa.contexacore.autonomous.execution.ObjectiveResourceCompatibilityCatalog;
import org.springframework.util.StringUtils;

import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;

public class ObjectiveDriftEvaluator {

    private final ObjectiveResourceCompatibilityCatalog compatibilityCatalog;

    public ObjectiveDriftEvaluator() {
        this(new ObjectiveResourceCompatibilityCatalog());
    }

    public ObjectiveDriftEvaluator(ObjectiveResourceCompatibilityCatalog compatibilityCatalog) {
        this.compatibilityCatalog = compatibilityCatalog != null ? compatibilityCatalog : new ObjectiveResourceCompatibilityCatalog();
    }

    public ObjectiveDriftEvaluation evaluate(
            CanonicalSecurityContext.Delegation delegation,
            CanonicalSecurityContext context) {
        if (delegation == null || !Boolean.TRUE.equals(delegation.getDelegated())) {
            return new ObjectiveDriftEvaluation(null, null, null, null, List.of(), List.of(), List.of(), List.of());
        }

        String objectiveFamily = normalizeText(delegation.getObjectiveFamily());
        ObjectiveResourceCompatibilityCatalog.ObjectiveContract contract = compatibilityCatalog.resolve(objectiveFamily);
        String currentActionFamily = resolveCurrentActionFamily(context);
        String currentResourceFamily = resolveCurrentResourceFamily(context);
        String currentResourceId = resolveCurrentResourceId(context);

        List<String> explicitAllowedActions = normalizeAllowedActionFamilies(delegation.getAllowedOperations());
        List<String> contractAllowedActions = new ArrayList<>(contract.allowedOperations());
        List<String> comparedActionFamilies = !explicitAllowedActions.isEmpty() ? explicitAllowedActions : contractAllowedActions;

        ResourceConstraints resourceConstraints = resolveResourceConstraints(delegation.getAllowedResources());
        List<String> contractAllowedResourceFamilies = new ArrayList<>(contract.allowedResourceFamilies());
        List<String> comparedResourceFamilies = !resourceConstraints.resourceFamilies().isEmpty()
                ? resourceConstraints.resourceFamilies()
                : contractAllowedResourceFamilies;

        String comparisonSource = resolveComparisonSource(
                explicitAllowedActions,
                contractAllowedActions,
                resourceConstraints.resourceFamilies(),
                contractAllowedResourceFamilies,
                resourceConstraints.rawConstraints());

        List<String> facts = new ArrayList<>();
        if (StringUtils.hasText(objectiveFamily)) {
            facts.add("Objective family: " + objectiveFamily);
        }
        if (StringUtils.hasText(currentActionFamily)) {
            facts.add("Current action family: " + currentActionFamily);
        }
        if (StringUtils.hasText(currentResourceFamily)) {
            facts.add("Current resource family: " + currentResourceFamily);
        }
        if (!comparedActionFamilies.isEmpty()) {
            facts.add("Allowed action families: " + String.join(", ", comparedActionFamilies));
        }
        if (!comparedResourceFamilies.isEmpty()) {
            facts.add("Allowed resource families: " + String.join(", ", comparedResourceFamilies));
        }
        if (!resourceConstraints.rawConstraints().isEmpty()) {
            facts.add("Allowed raw resource constraints: " + String.join(", ", resourceConstraints.rawConstraints()));
        }
        if (StringUtils.hasText(comparisonSource)) {
            facts.add("Comparison source: " + comparisonSource);
        }

        boolean compared = false;
        boolean drift = false;

        if (StringUtils.hasText(currentActionFamily) && !comparedActionFamilies.isEmpty()) {
            compared = true;
            boolean actionAllowed = comparedActionFamilies.stream().anyMatch(currentActionFamily::equalsIgnoreCase);
            drift = drift || !actionAllowed;
            facts.add(actionAllowed
                    ? "Current action family stays inside the delegated objective."
                    : "Current action family falls outside the delegated objective.");
        }

        if (StringUtils.hasText(currentResourceFamily) && !comparedResourceFamilies.isEmpty()) {
            compared = true;
            boolean resourceFamilyAllowed = comparedResourceFamilies.stream().anyMatch(currentResourceFamily::equalsIgnoreCase);
            drift = drift || !resourceFamilyAllowed;
            facts.add(resourceFamilyAllowed
                    ? "Current resource family stays inside the delegated objective."
                    : "Current resource family falls outside the delegated objective.");
        }

        if (StringUtils.hasText(currentResourceId) && !resourceConstraints.rawConstraints().isEmpty()) {
            compared = true;
            boolean rawResourceAllowed = resourceConstraints.rawConstraints().stream().anyMatch(constraint -> matchesResourceConstraint(constraint, currentResourceId));
            drift = drift || !rawResourceAllowed;
            facts.add(rawResourceAllowed
                    ? "Current resource matches delegated raw resource constraints."
                    : "Current resource does not match delegated raw resource constraints.");
        }

        if (Boolean.TRUE.equals(delegation.getContainmentOnly()) && StringUtils.hasText(currentActionFamily)) {
            compared = true;
            boolean containmentAligned = "CONTAIN".equalsIgnoreCase(currentActionFamily)
                    || "READ".equalsIgnoreCase(currentActionFamily)
                    || "QUERY".equalsIgnoreCase(currentActionFamily)
                    || "RETRIEVE".equalsIgnoreCase(currentActionFamily);
            drift = drift || !containmentAligned;
            if (!containmentAligned) {
                facts.add("Containment-only delegated objective does not permit the current action family.");
            }
        }

        if (Boolean.FALSE.equals(delegation.getPrivilegedExportAllowed()) && "EXPORT".equalsIgnoreCase(currentActionFamily)) {
            compared = true;
            drift = true;
            facts.add("Privileged export is not allowed for this delegated objective.");
        }

        if (!compared) {
            facts.add("Objective drift is unknown because comparable action/resource family inputs are missing.");
            return new ObjectiveDriftEvaluation(
                    null,
                    comparisonSource,
                    currentActionFamily,
                    currentResourceFamily,
                    comparedActionFamilies,
                    comparedResourceFamilies,
                    resourceConstraints.rawConstraints(),
                    facts);
        }

        facts.add(drift
                ? "Delegated objective drift is present."
                : "Delegated objective remains aligned.");
        return new ObjectiveDriftEvaluation(
                drift,
                comparisonSource,
                currentActionFamily,
                currentResourceFamily,
                comparedActionFamilies,
                comparedResourceFamilies,
                resourceConstraints.rawConstraints(),
                facts);
    }

    private List<String> normalizeAllowedActionFamilies(List<String> allowedOperations) {
        if (allowedOperations == null || allowedOperations.isEmpty()) {
            return List.of();
        }
        LinkedHashSet<String> normalized = new LinkedHashSet<>();
        for (String allowedOperation : allowedOperations) {
            String normalizedAction = compatibilityCatalog.normalizeOperationFamily(allowedOperation);
            if (StringUtils.hasText(normalizedAction)) {
                normalized.add(normalizedAction);
            }
        }
        return List.copyOf(normalized);
    }

    private ResourceConstraints resolveResourceConstraints(List<String> allowedResources) {
        if (allowedResources == null || allowedResources.isEmpty()) {
            return new ResourceConstraints(List.of(), List.of());
        }
        LinkedHashSet<String> resourceFamilies = new LinkedHashSet<>();
        LinkedHashSet<String> rawConstraints = new LinkedHashSet<>();
        for (String allowedResource : allowedResources) {
            if (!StringUtils.hasText(allowedResource)) {
                continue;
            }
            String trimmed = allowedResource.trim();
            if (looksLikeRawResourceConstraint(trimmed)) {
                rawConstraints.add(trimmed);
            }
            else {
                resourceFamilies.add(compatibilityCatalog.normalizeResourceFamily(trimmed));
            }
        }
        return new ResourceConstraints(List.copyOf(resourceFamilies), List.copyOf(rawConstraints));
    }

    private String resolveCurrentActionFamily(CanonicalSecurityContext context) {
        if (context == null) {
            return null;
        }
        String candidate = firstText(
                context.getRoleScopeProfile() != null ? context.getRoleScopeProfile().getCurrentActionFamily() : null,
                context.getResource() != null ? context.getResource().getActionFamily() : null);
        return compatibilityCatalog.normalizeOperationFamily(candidate);
    }

    private String resolveCurrentResourceFamily(CanonicalSecurityContext context) {
        if (context == null) {
            return null;
        }
        String explicit = firstText(
                context.getRoleScopeProfile() != null ? context.getRoleScopeProfile().getCurrentResourceFamily() : null,
                context.getResource() != null ? context.getResource().getResourceType() : null);
        if (StringUtils.hasText(explicit)) {
            return compatibilityCatalog.normalizeResourceFamily(explicit);
        }
        if (context.getResource() == null) {
            return null;
        }
        return compatibilityCatalog.resolveResourceFamily(
                null,
                context.getResource().getRequestPath(),
                context.getResource().getResourceType(),
                context.getResource().getBusinessLabel(),
                firstText(context.getResource().getResourceId(), context.getResource().getRequestPath()));
    }

    private String resolveCurrentResourceId(CanonicalSecurityContext context) {
        if (context == null || context.getResource() == null) {
            return null;
        }
        return firstText(context.getResource().getResourceId(), context.getResource().getRequestPath());
    }

    private boolean looksLikeRawResourceConstraint(String value) {
        String trimmed = value.trim();
        return trimmed.contains("/")
                || trimmed.contains(":")
                || trimmed.contains(".")
                || trimmed.contains("*")
                || trimmed.contains("-");
    }

    private boolean matchesResourceConstraint(String constraint, String currentResourceId) {
        String normalizedConstraint = normalizeText(constraint);
        String normalizedCurrent = normalizeText(currentResourceId);
        if (!StringUtils.hasText(normalizedConstraint) || !StringUtils.hasText(normalizedCurrent)) {
            return false;
        }
        if (normalizedConstraint.endsWith("*")) {
            String prefix = normalizedConstraint.substring(0, normalizedConstraint.length() - 1);
            return normalizedCurrent.startsWith(prefix);
        }
        return normalizedCurrent.equalsIgnoreCase(normalizedConstraint)
                || normalizedCurrent.startsWith(normalizedConstraint)
                || normalizedConstraint.startsWith(normalizedCurrent);
    }

    private String resolveComparisonSource(
            List<String> explicitAllowedActions,
            List<String> contractAllowedActions,
            List<String> explicitAllowedResourceFamilies,
            List<String> contractAllowedResourceFamilies,
            List<String> rawResourceConstraints) {
        boolean explicitAction = !explicitAllowedActions.isEmpty();
        boolean contractAction = !explicitAction && !contractAllowedActions.isEmpty();
        boolean explicitResource = !explicitAllowedResourceFamilies.isEmpty() || !rawResourceConstraints.isEmpty();
        boolean contractResource = !explicitAllowedResourceFamilies.isEmpty() ? false : !contractAllowedResourceFamilies.isEmpty();

        if ((explicitAction || explicitResource) && (contractAction || contractResource)) {
            return "MIXED_EXPLICIT_AND_OBJECTIVE_CONTRACT";
        }
        if (explicitAction || explicitResource) {
            return "EXPLICIT_DELEGATION_SCOPE";
        }
        if (contractAction || contractResource) {
            return "OBJECTIVE_CONTRACT";
        }
        return "UNABLE_TO_COMPARE";
    }

    private String firstText(String... values) {
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

    private String normalizeText(String value) {
        return StringUtils.hasText(value) ? value.trim().toLowerCase(Locale.ROOT) : null;
    }

    private record ResourceConstraints(List<String> resourceFamilies, List<String> rawConstraints) {
    }
}
