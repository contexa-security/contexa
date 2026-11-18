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
package io.contexa.contexacore.autonomous.tiered.prompt;

import io.contexa.contexacommon.domain.SecurityEvent;
import io.contexa.contexacore.autonomous.context.CanonicalSecurityContext;
import io.contexa.contexacore.autonomous.context.decision.CompanyRecordsEvaluator;
import io.contexa.contexacore.autonomous.context.support.NetworkZone;
import io.contexa.contexacore.autonomous.learning.evidence.LearningContextEvidence;
import org.springframework.util.StringUtils;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;

/**
 * The values of the lines v1.0 adds to the v21 dictionary (plan 2.8 F1 to F8, D5), each from its source as the render
 * draws it: shared with the prompt inspector, which computes the same lines again from the sealed context.
 */
public final class V1LineValues {

    /** The source of an anomaly signal the server itself issued (v19 TRUSTED_VERIFICATION_INPUT; v1.0 D5). */
    public static final String TRUSTED_SIGNAL_SOURCE = "OFFICIAL_VERIFICATION_INTERNAL";

    private V1LineValues() {
    }

    /** v1.0 F4: the host's auth.failure_count, stated as the failed logins line states a count without its window. */
    public static String hostFailureCount(SecurityEvent event) {
        String value = metadata(event, "auth.failure_count");
        if (value == null || !value.matches("\\d{1,9}")) {
            return null;
        }
        return Integer.parseInt(value) + " recent failed logins (window not stated)";
    }

    /** v1.0 F6: {@code burst observed (host)} or {@code no burst (host)}, or null when the host does not say. */
    public static String burstPattern(CanonicalSecurityContext.SessionNarrativeProfile narrative) {
        if (narrative == null || narrative.getBurstPattern() == null) {
            return null;
        }
        return narrative.getBurstPattern() ? "burst observed (host)" : "no burst (host)";
    }

    /** v1.0 F8: the host's counts of recent challenges, blocks and escalations; the session's first, then the company's. */
    public static String hostDecisionCounts(CanonicalSecurityContext.Session session,
                                     CanonicalSecurityContext.FrictionProfile friction) {
        Integer challenges = firstCount(session != null ? session.getRecentChallengeCount() : null,
                friction != null ? friction.getRecentChallengeCount() : null);
        Integer blocks = firstCount(session != null ? session.getRecentBlockCount() : null,
                friction != null ? friction.getRecentBlockCount() : null);
        Integer escalations = firstCount(session != null ? session.getRecentEscalationCount() : null,
                friction != null ? friction.getRecentEscalationCount() : null);
        if (challenges == null && blocks == null && escalations == null) {
            return null;
        }
        return "host counts: challenges " + countOrNotStated(challenges) + ", blocks " + countOrNotStated(blocks)
                + ", escalations " + countOrNotStated(escalations);
    }

    private static Integer firstCount(Integer first, Integer second) {
        return first != null ? first : second;
    }

    private static String countOrNotStated(Integer count) {
        return count != null ? String.valueOf(count) : "not stated";
    }

    /** v1.0 F7: {@code type CUSTOMER_RECORD}, the resource type the host declares, or null. */
    public static String targetType(CanonicalSecurityContext.Resource resource) {
        return resource != null && StringUtils.hasText(resource.getResourceType())
                ? "type " + resource.getResourceType().trim().replaceAll("\\s+", " ") : null;
    }

    /** v1.0 F7: {@code CORPORATE - a company network (host)}, the zone with what it means, or null. */
    public static String networkZone(CanonicalSecurityContext.Location location) {
        NetworkZone zone = location != null ? NetworkZone.of(location.getNetworkZone()) : null;
        return zone == null ? null : zone.name() + " - " + zone.meaning() + " (host)";
    }

    /** The record kinds the records looked up line states, with the kind of record each one is. */
    private static final List<Map.Entry<String, String>> LOOKED_UP_KINDS = List.of(
            Map.entry("approvals", CanonicalSecurityContext.FrictionProfile.RECORD_APPROVAL),
            Map.entry("tickets", CanonicalSecurityContext.FrictionProfile.RECORD_TICKET),
            Map.entry("assignment", CanonicalSecurityContext.FrictionProfile.RECORD_ASSIGNMENT),
            Map.entry("on-call", CanonicalSecurityContext.FrictionProfile.RECORD_ON_CALL),
            Map.entry("travel", CanonicalSecurityContext.FrictionProfile.RECORD_TRAVEL),
            Map.entry("access history", CanonicalSecurityContext.FrictionProfile.RECORD_ACCESS_HISTORY));

    /**
     * v1.0 F1: for each kind of company record, whether the host looked it up and how many it found, so a missing
     * approval reads apart from an approval that was not looked up; null without the company records.
     */
    public static String recordsLookedUp(CanonicalSecurityContext.FrictionProfile friction) {
        if (friction == null) {
            return null;
        }
        List<String> parts = new ArrayList<>();
        for (Map.Entry<String, String> kind : LOOKED_UP_KINDS) {
            int found = recordsFound(friction, kind.getValue());
            boolean lookedUp = found > 0 || CompanyRecordsEvaluator.checked(friction, kind.getValue());
            parts.add(kind.getKey() + (lookedUp
                    ? " looked up, " + (found == 0 ? "none found" : found + " found")
                    : " not looked up"));
        }
        return String.join("; ", parts);
    }

    private static int recordsFound(CanonicalSecurityContext.FrictionProfile friction, String kind) {
        return switch (kind) {
            case CanonicalSecurityContext.FrictionProfile.RECORD_APPROVAL ->
                    friction.getApprovalRecords() != null ? friction.getApprovalRecords().size() : 0;
            case CanonicalSecurityContext.FrictionProfile.RECORD_TICKET ->
                    friction.getTicketRecords() != null ? friction.getTicketRecords().size() : 0;
            case CanonicalSecurityContext.FrictionProfile.RECORD_ASSIGNMENT -> friction.getAssignment() != null ? 1 : 0;
            case CanonicalSecurityContext.FrictionProfile.RECORD_ON_CALL -> friction.getOnCall() != null ? 1 : 0;
            case CanonicalSecurityContext.FrictionProfile.RECORD_TRAVEL -> friction.getTravel() != null ? 1 : 0;
            case CanonicalSecurityContext.FrictionProfile.RECORD_ACCESS_HISTORY ->
                    friction.getAccessHistory() != null ? 1 : 0;
            default -> 0;
        };
    }

    /**
     * v1.0 F2: the scope group's denied categories and actions, whether the request's are among them (a comparison
     * of the two lists, as v19 drew it) and the drift the host states; null when the scope says none of them.
     */
    public static String scopeDenied(CanonicalSecurityContext.RoleScopeProfile roleScope) {
        if (roleScope == null) {
            return null;
        }
        List<String> parts = new ArrayList<>();
        List<String> categories = texts(roleScope.getForbiddenResourceFamilies());
        if (!categories.isEmpty()) {
            parts.add("denied categories " + String.join(", ", categories));
            String current = firstText(roleScope.getCurrentResourceFamily());
            if (current != null) {
                parts.add("category " + current + " in denied: " + yesNo(containsIgnoringCase(categories, current)));
            }
        }
        List<String> actions = texts(roleScope.getForbiddenActionFamilies());
        if (!actions.isEmpty()) {
            parts.add("denied actions " + String.join(", ", actions));
            String current = firstText(roleScope.getCurrentActionFamily());
            if (current != null) {
                parts.add("action " + current + " in denied: " + yesNo(containsIgnoringCase(actions, current)));
            }
        }
        if (roleScope.getResourceFamilyDrift() != null || roleScope.getActionFamilyDrift() != null) {
            parts.add("host drift: category " + yesNoOrNotStated(roleScope.getResourceFamilyDrift())
                    + ", action " + yesNoOrNotStated(roleScope.getActionFamilyDrift()));
        }
        return parts.isEmpty() ? null : String.join("; ", parts);
    }

    /** v1.0 F7: the approval and escalation patterns usual in the scope group, or null. */
    public static String scopeHabits(CanonicalSecurityContext.RoleScopeProfile roleScope) {
        if (roleScope == null) {
            return null;
        }
        List<String> parts = new ArrayList<>();
        List<String> approvals = texts(roleScope.getNormalApprovalPatterns());
        if (!approvals.isEmpty()) {
            parts.add("usual approvals " + String.join(", ", approvals));
        }
        List<String> escalations = texts(roleScope.getNormalEscalationPatterns());
        if (!escalations.isEmpty()) {
            parts.add("usual escalations " + String.join(", ", escalations));
        }
        return parts.isEmpty() ? null : String.join("; ", parts);
    }

    /** v1.0 F3: the controls the delegation names, each as the host states it, or null when it names none. */
    public static String delegationControls(CanonicalSecurityContext.Delegation delegation) {
        List<String> parts = new ArrayList<>();
        if (delegation.getApprovalRequired() != null) {
            parts.add("approval required: " + yesNo(delegation.getApprovalRequired()));
        }
        if (delegation.getPrivilegedExportAllowed() != null) {
            parts.add("privileged export allowed: " + yesNo(delegation.getPrivilegedExportAllowed()));
        }
        if (delegation.getContainmentOnly() != null) {
            parts.add("containment only: " + yesNo(delegation.getContainmentOnly()));
        }
        return parts.isEmpty() ? null : String.join("; ", parts);
    }

    /**
     * v1.0 F5: the actor's tenant against the tenant the request names (v19 CONFLICTS_WITH_REQUEST_TENANT), or null
     * when either is not stated.
     */
    public static String tenantMatch(CanonicalSecurityContext canonical) {
        String actorTenant = canonical.getActor() != null ? firstText(canonical.getActor().getTenantId()) : null;
        Object requested = canonical.getAttributes() != null ? canonical.getAttributes().get("tenantId") : null;
        String requestTenant = requested instanceof String text ? firstText(text) : null;
        if (actorTenant == null || requestTenant == null) {
            return null;
        }
        return "actor tenant " + actorTenant + ", request tenant " + requestTenant + ": "
                + (actorTenant.equalsIgnoreCase(requestTenant) ? "same" : "differ");
    }

    /**
     * N2: whether the TenantMatch line says the tenants differ, the tenant conflict of the required BLOCK boundary; null
     * when the line is not drawn because either tenant is not stated.
     */
    public static Boolean tenantsDiffer(CanonicalSecurityContext canonical) {
        String line = tenantMatch(canonical);
        return line == null ? null : line.endsWith(": differ");
    }

    /**
     * v1.0 F6: how many times the past records show this request's whole combination, with the scope searched and the
     * dimensions compared; null without personal past records to compare with.
     */
    public static String seenCombination(LearningContextEvidence evidence) {
        if (evidence == null || evidence.personalRetrievedEvidence().isEmpty()) {
            return null;
        }
        List<String> qualifiers = new ArrayList<>();
        addPart(qualifiers, "scope ", evidence.currentRequestCombinationEvidenceScope());
        addPart(qualifiers, "compared ", evidence.currentRequestCombinationComparedDimensions());
        return "this combination seen " + evidence.currentRequestCombinationSeenCount() + " times"
                + (qualifiers.isEmpty() ? "" : " (" + String.join("; ", qualifiers).replaceAll("\\s+", " ") + ")");
    }

    /** v1.0 F7: the protectable frequency and sensitivity bands usual in the peer cohort, or null. */
    public static String cohortBands(CanonicalSecurityContext.PeerCohortProfile cohort) {
        if (cohort == null) {
            return null;
        }
        List<String> parts = new ArrayList<>();
        addPart(parts, "usual protectable frequency ", cohort.getNormalProtectableFrequencyBand());
        addPart(parts, "usual sensitivity ", cohort.getNormalSensitivityBand());
        return parts.isEmpty() ? null : String.join("; ", parts);
    }

    /**
     * v1.0 D5: the anomaly signal the server itself issued, with its source; null for a signal of any other source,
     * which a requester could have sent (that claim stays an untrusted text).
     */
    public static String verifiedSignal(CanonicalSecurityContext.Intent intent) {
        if (intent == null || !StringUtils.hasText(intent.getAnomalySignal())
                || !TRUSTED_SIGNAL_SOURCE.equalsIgnoreCase(firstText(intent.getAnomalySignalSource()))) {
            return null;
        }
        return intent.getAnomalySignal().trim().replaceAll("\\s+", " ") + " (server-issued verification input "
                + TRUSTED_SIGNAL_SOURCE + ")";
    }

    /** v1.0 F7: whether the past record search left out records the requester may not see, or null when not stated. */
    public static String pastRecordsPermission(SecurityEvent event) {
        return pastRecordsPermission(metadata(event, "ragPermissionFiltered"));
    }

    /** As above, from the value the event or the sealed retrieval summary keeps (shared with the inspector). */
    public static String pastRecordsPermission(Object filtered) {
        if (filtered == null || !StringUtils.hasText(filtered.toString())) {
            return null;
        }
        return "records filtered by the requester's permission: "
                + ("true".equalsIgnoreCase(filtered.toString().trim()) ? "yes" : "no");
    }

    private static List<String> texts(List<String> values) {
        return values == null ? List.of() : values.stream().filter(StringUtils::hasText).map(String::trim).toList();
    }

    private static boolean containsIgnoringCase(List<String> values, String value) {
        return values.stream().anyMatch(value::equalsIgnoreCase);
    }

    private static String yesNo(boolean value) {
        return value ? "yes" : "no";
    }

    private static String yesNoOrNotStated(Boolean value) {
        return value == null ? "not stated" : yesNo(value);
    }


    private static String metadata(SecurityEvent event, String key) {
        if (event == null || event.getMetadata() == null) {
            return null;
        }
        Object value = event.getMetadata().get(key);
        return value != null && StringUtils.hasText(value.toString()) ? value.toString().trim() : null;
    }

    private static void addPart(List<String> parts, String prefix, String value) {
        if (StringUtils.hasText(value)) {
            parts.add(prefix + value.trim());
        }
    }

    private static String firstText(String... values) {
        for (String value : values) {
            if (StringUtils.hasText(value)) {
                return value.trim();
            }
        }
        return null;
    }
}
