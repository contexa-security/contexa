/*
 * Copyright 2026 The Contexa Project
 *
 * The Contexa Project licenses this file to you under the Apache License,
 * version 2.0 (the "License"); you may not use this file except in compliance
 * with the License. You may obtain a copy of the License at:
 *
 *   https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
 * License for the specific language governing permissions and limitations
 * under the License.
 */
package io.contexa.contexacore.autonomous.context.inference;

import io.contexa.contexacore.autonomous.context.support.ActionFamily;
import io.contexa.contexacore.autonomous.execution.ObjectiveResourceCompatibilityCatalog;
import org.springframework.util.StringUtils;

import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import io.contexa.contexacore.autonomous.context.model.ObjectiveDriftEvaluation;
import io.contexa.contexacore.autonomous.context.CanonicalSecurityContext;
import io.contexa.contexacore.autonomous.context.support.SessionExports;

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
        // The facts name the request by its one action family, as every other line of the prompt does; the delegated
        // scope is compared in the delegation's own operation vocabulary.
        String currentActionFamily = resolveCurrentActionFamily(context);
        String currentOperation = compatibilityCatalog.normalizeOperationFamily(currentActionFamily);
        String currentResourceFamily = resolveCurrentResourceFamily(context);
        List<String> currentTargets = resolveCurrentTargets(context);

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
        boolean operationUnknown = ObjectiveResourceCompatibilityCatalog.UNKNOWN_OPERATION.equalsIgnoreCase(currentOperation);
        if (StringUtils.hasText(currentActionFamily)) {
            facts.add("Current action family: " + currentActionFamily);
            if (StringUtils.hasText(currentOperation) && !operationUnknown
                    && !currentOperation.equalsIgnoreCase(currentActionFamily)) {
                facts.add("Current action family compared as delegated operation: " + currentOperation);
            }
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

        if (operationUnknown && !comparedActionFamilies.isEmpty()) {
            // An action no source names, or one the delegation vocabulary has no operation for, cannot be compared with
            // the delegated scope: neither inside nor outside it.
            facts.add(ActionFamily.UNKNOWN.name().equalsIgnoreCase(currentActionFamily)
                    ? "Current action family is unknown; it is not compared with delegated action scope evidence."
                    : "Current action family has no delegated operation; it is not compared with delegated action scope evidence.");
        }
        if (StringUtils.hasText(currentOperation) && !operationUnknown && !comparedActionFamilies.isEmpty()) {
            compared = true;
            boolean actionAllowed = comparedActionFamilies.stream().anyMatch(currentOperation::equalsIgnoreCase);
            drift = drift || !actionAllowed;
            facts.add(actionAllowed
                    ? "Current action family is listed in delegated action scope evidence."
                    : "Current action family is not listed in delegated action scope evidence.");
        }

        if (StringUtils.hasText(currentResourceFamily) && !comparedResourceFamilies.isEmpty()) {
            compared = true;
            boolean resourceFamilyAllowed = comparedResourceFamilies.stream().anyMatch(currentResourceFamily::equalsIgnoreCase);
            drift = drift || !resourceFamilyAllowed;
            facts.add(resourceFamilyAllowed
                    ? "Current resource family is listed in delegated resource scope evidence."
                    : "Current resource family is not listed in delegated resource scope evidence.");
        }

        if (!currentTargets.isEmpty() && !resourceConstraints.rawConstraints().isEmpty()) {
            compared = true;
            boolean rawResourceAllowed = resourceConstraints.rawConstraints().stream()
                    .anyMatch(constraint -> withinRawConstraint(constraint, context));
            drift = drift || !rawResourceAllowed;
            facts.add(rawResourceAllowed
                    ? "Current resource matches delegated raw resource constraints."
                    : "Current resource does not match delegated raw resource constraints.");
        }

        if (Boolean.TRUE.equals(delegation.getContainmentOnly()) && StringUtils.hasText(currentOperation)) {
            compared = true;
            boolean containmentAligned = "CONTAIN".equalsIgnoreCase(currentOperation)
                    || "READ".equalsIgnoreCase(currentOperation)
                    || "QUERY".equalsIgnoreCase(currentOperation)
                    || "RETRIEVE".equalsIgnoreCase(currentOperation);
            drift = drift || !containmentAligned;
            if (!containmentAligned) {
                facts.add("Containment-only delegated scope evidence does not include the current action family.");
            }
        }

        // A2-1: the most items one export of the application's objective may carry.
        Integer requestedItems = context != null && context.getResource() != null
                ? context.getResource().getRequestedItems() : null;
        if (contract.maxExportItems() != null && requestedItems != null && "EXPORT".equalsIgnoreCase(currentOperation)) {
            compared = true;
            boolean withinLimit = requestedItems <= contract.maxExportItems();
            drift = drift || !withinLimit;
            facts.add(withinLimit
                    ? requestedItems + " requested items are within the objective's export limit of " + contract.maxExportItems() + "."
                    : requestedItems + " requested items exceed the objective's export limit of " + contract.maxExportItems() + ".");
        }

        // RL-6: the quantity limits the delegation itself states, apart from the objective's: the items one request may
        // carry, and the items the agent may export in its session (this request included).
        Integer perRequest = delegation.getMaxItemsPerRequest();
        if (perRequest != null && requestedItems != null && "EXPORT".equalsIgnoreCase(currentOperation)) {
            compared = true;
            boolean withinLimit = requestedItems <= perRequest;
            drift = drift || !withinLimit;
            facts.add(withinLimit
                    ? requestedItems + " requested items are within the delegation's limit of " + perRequest
                            + " items per request."
                    : requestedItems + " requested items exceed the delegation's limit of " + perRequest
                            + " items per request.");
        }
        Integer total = delegation.getMaxItemsTotal();
        if (total != null && requestedItems != null && "EXPORT".equalsIgnoreCase(currentOperation)) {
            compared = true;
            long inSession = SessionExports.exportedItems(context) + requestedItems;
            boolean withinLimit = inSession <= total;
            drift = drift || !withinLimit;
            facts.add(withinLimit
                    ? inSession + " items exported in the session with this request are within the delegation's limit of "
                            + total + "."
                    : inSession + " items exported in the session with this request exceed the delegation's limit of "
                            + total + ".");
        }

        if (Boolean.FALSE.equals(delegation.getPrivilegedExportAllowed()) && "EXPORT".equalsIgnoreCase(currentOperation)) {
            compared = true;
            drift = true;
            facts.add("Delegated scope evidence marks privileged export as disallowed.");
        }

        if (!compared) {
            facts.add("Delegated objective comparison is incomplete because comparable action/resource family inputs are missing.");
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
        return ActionFamily.nameOrRaw(candidate);
    }

    private String resolveCurrentResourceFamily(CanonicalSecurityContext context) {
        if (context == null) {
            return null;
        }
        // The delegated scope names business categories: the request's category, never its class (W2-10).
        String explicit = firstText(
                context.getRoleScopeProfile() != null ? context.getRoleScopeProfile().getCurrentResourceFamily() : null,
                context.getResource() != null ? context.getResource().getResourceCategory() : null);
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

    /** What the request works on, as the delegation's raw constraints may name it (see {@link #withinRawConstraint}). */
    private List<String> resolveCurrentTargets(CanonicalSecurityContext context) {
        if (context == null || context.getResource() == null) {
            return List.of();
        }
        CanonicalSecurityContext.Resource resource = context.getResource();
        LinkedHashSet<String> targets = new LinkedHashSet<>();
        addText(targets, resource.getResourceId());
        addText(targets, resource.getRequestPath());
        targets.addAll(scopeIdentifiers(resource.getScope()));
        return List.copyOf(targets);
    }

    /**
     * Whether the request lies within a raw constraint of the delegation. A path ({@code /api/reports/*}) is compared
     * with the request's path and resource. An identifier of a business record ({@code HX-310}, a project) is compared
     * with the request's business target: the scope the host records for it and the identifiers in its path. It is
     * never the protected method's id, which no delegation names (A2-4, the drawing HX-310-DWG-00002 of project HX-310
     * was found outside a delegation for HX-310 on the showcase).
     */
    private boolean withinRawConstraint(String constraint, CanonicalSecurityContext context) {
        if (context == null || context.getResource() == null || !StringUtils.hasText(constraint)) {
            return false;
        }
        CanonicalSecurityContext.Resource resource = context.getResource();
        if (constraint.contains("/")) {
            return matchesResourceConstraint(constraint, resource.getResourceId())
                    || matchesResourceConstraint(constraint, resource.getRequestPath());
        }
        LinkedHashSet<String> identifiers = new LinkedHashSet<>(scopeIdentifiers(resource.getScope()));
        if (StringUtils.hasText(resource.getRequestPath())) {
            for (String segment : resource.getRequestPath().split("/")) {
                addText(identifiers, segment);
            }
        }
        addText(identifiers, resource.getResourceId());
        return identifiers.stream().anyMatch(identifier -> matchesResourceConstraint(constraint, identifier));
    }

    /** The values of a host-recorded scope such as {@code projectKey=HX-310} or {@code HX-310, GB-500}. */
    private static List<String> scopeIdentifiers(String scope) {
        if (!StringUtils.hasText(scope)) {
            return List.of();
        }
        List<String> identifiers = new ArrayList<>();
        for (String part : scope.split("[,;\\s]+")) {
            int equals = part.indexOf('=');
            String value = equals >= 0 ? part.substring(equals + 1) : part;
            if (StringUtils.hasText(value)) {
                identifiers.add(value.trim());
            }
        }
        return identifiers;
    }

    private static void addText(LinkedHashSet<String> values, String value) {
        if (StringUtils.hasText(value)) {
            values.add(value.trim());
        }
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
        // The request lies within a constraint that its resource starts with; a constraint that starts with the
        // request's resource names something narrower than what is asked for (N-ID-1).
        return normalizedCurrent.equalsIgnoreCase(normalizedConstraint)
                || normalizedCurrent.startsWith(normalizedConstraint);
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
