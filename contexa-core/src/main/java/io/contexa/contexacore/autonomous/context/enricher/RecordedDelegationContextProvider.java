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
package io.contexa.contexacore.autonomous.context.enricher;

import io.contexa.contexacommon.domain.SecurityEvent;
import io.contexa.contexacore.autonomous.context.CanonicalSecurityContext;
import lombok.extern.slf4j.Slf4j;

import java.time.Instant;
import java.time.format.DateTimeParseException;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Optional;

/**
 * Applies the delegation the host's business records keep (A1-4, AG-1e) to an agent request's canonical context, so
 * the objective drift evaluation and the prompt compare the request with what the person actually delegated.
 *
 * <p>The record is the delegation of record, and it only ever narrows what the request stated (a token or a session):
 * <ul>
 *   <li>Its objective replaces a different stated objective.</li>
 *   <li>Allowed operations and resources become the items both state. When they share none, the record's list is
 *   kept: an empty list means "not stated" to the drift evaluation and would widen the delegation.</li>
 *   <li>Approval and containment hold when either requires them; a privileged export is allowed only when neither
 *   denies it; the earlier end applies.</li>
 *   <li>A record for another agent than the one the request names is not applied.</li>
 * </ul>
 * The outcome is kept in the context attributes: {@value #LOOKUP_ATTRIBUTE} ({@code FOUND}, {@code NOT_FOUND},
 * {@code AGENT_MISMATCH} or {@code FAILED}), {@value #RECORD_ID_ATTRIBUTE} and {@value #CONFLICTS_ATTRIBUTE} (the
 * stated facts the record overrode). A person's own request is never looked up.
 */
@Slf4j
public class RecordedDelegationContextProvider implements DelegationContextProvider {

    public static final String LOOKUP_ATTRIBUTE = "delegationRecordLookup";
    public static final String RECORD_ID_ATTRIBUTE = "delegationRecordId";
    public static final String CONFLICTS_ATTRIBUTE = "delegationRecordConflicts";
    /** A2-10: who wrote the delegation's record and when, as the host states it. */
    public static final String RECORDED_BY_ATTRIBUTE = "delegationRecordedBy";
    public static final String RECORDED_AT_ATTRIBUTE = "delegationRecordedAt";

    private final DelegationRecordLookup lookup;

    public RecordedDelegationContextProvider(DelegationRecordLookup lookup) {
        if (lookup == null) {
            throw new IllegalArgumentException("A delegation record lookup is required");
        }
        this.lookup = lookup;
    }

    @Override
    public void enrich(SecurityEvent event, CanonicalSecurityContext context) {
        if (context == null) {
            return;
        }
        Map<String, Object> attributes = attributes(context);
        CanonicalSecurityContext.Delegation delegation = context.getDelegation();
        String agentId = delegation != null ? text(delegation.getAgentId()) : null;
        String delegationId = text(attributes.get("delegationId"));
        boolean namesADelegation = agentId != null || delegationId != null
                || (delegation != null && Boolean.TRUE.equals(delegation.getDelegated()));
        if (!namesADelegation) {
            return;
        }
        if (delegation == null) {
            delegation = new CanonicalSecurityContext.Delegation();
            context.setDelegation(delegation);
        }

        Optional<DelegationRecord> found;
        try {
            found = lookup.find(query(event, context, agentId, delegationId));
        } catch (RuntimeException ex) {
            log.warn("Delegation record lookup failed for agent {}: {}", agentId, ex.getMessage(), ex);
            attributes.put(LOOKUP_ATTRIBUTE, "FAILED");
            return;
        }
        if (found == null || found.isEmpty()) {
            attributes.put(LOOKUP_ATTRIBUTE, "NOT_FOUND");
            return;
        }
        DelegationRecord record = found.get();
        if (agentId != null && text(record.agentId()) != null && !agentId.equals(record.agentId().trim())) {
            attributes.put(LOOKUP_ATTRIBUTE, "AGENT_MISMATCH");
            return;
        }

        List<String> conflicts = new ArrayList<>();
        apply(record, delegation, conflicts);
        attributes.put(LOOKUP_ATTRIBUTE, "FOUND");
        if (text(record.delegationId()) != null) {
            attributes.put(RECORD_ID_ATTRIBUTE, record.delegationId().trim());
        }
        if (text(record.recordedBy()) != null) {
            attributes.put(RECORDED_BY_ATTRIBUTE, record.recordedBy().trim());
        }
        if (record.recordedAt() != null) {
            attributes.put(RECORDED_AT_ATTRIBUTE, record.recordedAt().toString());
        }
        if (!conflicts.isEmpty()) {
            attributes.put(CONFLICTS_ATTRIBUTE, List.copyOf(conflicts));
        }
    }

    private static DelegationRecordQuery query(SecurityEvent event, CanonicalSecurityContext context, String agentId,
                                               String delegationId) {
        CanonicalSecurityContext.Actor actor = context.getActor();
        Map<String, Object> attributes = context.getAttributes();
        String tenantId = firstText(actor != null ? actor.getTenantId() : null,
                actor != null ? actor.getOrganizationId() : null,
                text(attributes.get("tenantId")),
                text(attributes.get("organizationId")));
        String delegatorId = firstText(actor != null ? actor.getUserId() : null, event != null ? event.getUserId() : null);
        Instant requestedAt = event != null ? event.getTimestamp() : null;
        return new DelegationRecordQuery(tenantId, delegatorId, agentId, delegationId,
                text(context.getDelegation().getObjectiveId()), requestedAt);
    }

    private static void apply(DelegationRecord record, CanonicalSecurityContext.Delegation delegation,
                              List<String> conflicts) {
        delegation.setDelegated(true);
        if (text(delegation.getAgentId()) == null && text(record.agentId()) != null) {
            delegation.setAgentId(record.agentId().trim());
        }
        delegation.setObjectiveId(recorded("objectiveId", delegation.getObjectiveId(), record.objectiveId(), conflicts));
        delegation.setObjectiveFamily(recorded("objectiveFamily", delegation.getObjectiveFamily(),
                record.objectiveFamily(), conflicts));
        delegation.setObjectiveSummary(recorded("objectiveSummary", delegation.getObjectiveSummary(),
                record.objectiveSummary(), conflicts));
        delegation.setAllowedOperations(narrowed("allowedOperations", delegation.getAllowedOperations(),
                record.allowedOperations(), conflicts));
        delegation.setAllowedResources(narrowed("allowedResources", delegation.getAllowedResources(),
                record.allowedResources(), conflicts));
        delegation.setApprovalRequired(eitherHolds(delegation.getApprovalRequired(), record.approvalRequired()));
        delegation.setContainmentOnly(eitherHolds(delegation.getContainmentOnly(), record.containmentOnly()));
        delegation.setPrivilegedExportAllowed(bothAllow(delegation.getPrivilegedExportAllowed(),
                record.privilegedExportAllowed()));
        delegation.setExpiresAt(earlier(delegation.getExpiresAt(), record.expiresAt()));
    }

    /** The recorded value; a different stated value is noted as a conflict. */
    private static String recorded(String name, String stated, String recorded, List<String> conflicts) {
        String recordedText = text(recorded);
        if (recordedText == null) {
            return stated;
        }
        String statedText = text(stated);
        if (statedText != null && !statedText.equalsIgnoreCase(recordedText)) {
            conflicts.add(name);
        }
        return recordedText;
    }

    /** The items both state; the record's list when either states none of the other's (never an empty list). */
    private static List<String> narrowed(String name, List<String> stated, List<String> recorded, List<String> conflicts) {
        List<String> statedItems = stated != null ? stated : List.of();
        if (recorded == null || recorded.isEmpty()) {
            return new ArrayList<>(statedItems);
        }
        if (statedItems.isEmpty()) {
            return new ArrayList<>(recorded);
        }
        List<String> recordedKeys = recorded.stream().map(RecordedDelegationContextProvider::key).toList();
        List<String> common = new ArrayList<>();
        for (String item : statedItems) {
            if (item != null && recordedKeys.contains(key(item)) && !common.contains(item)) {
                common.add(item);
            }
        }
        if (common.isEmpty()) {
            conflicts.add(name);
            return new ArrayList<>(recorded);
        }
        return common;
    }

    /** True when either requires it, false when both state otherwise, or the one stated value. */
    private static Boolean eitherHolds(Boolean stated, Boolean recorded) {
        if (Boolean.TRUE.equals(stated) || Boolean.TRUE.equals(recorded)) {
            return true;
        }
        return stated != null ? stated : recorded;
    }

    /** False when either denies it, true only when one allows it and neither denies it. */
    private static Boolean bothAllow(Boolean stated, Boolean recorded) {
        if (Boolean.FALSE.equals(stated) || Boolean.FALSE.equals(recorded)) {
            return false;
        }
        return stated != null ? stated : recorded;
    }

    /** The earlier end; a stated end that is not an instant gives way to the recorded one. */
    private static String earlier(String stated, Instant recorded) {
        Instant statedInstant = instant(stated);
        if (recorded == null) {
            return stated;
        }
        if (statedInstant == null || recorded.isBefore(statedInstant)) {
            return recorded.toString();
        }
        return statedInstant.toString();
    }

    private static Instant instant(String value) {
        String text = text(value);
        if (text == null) {
            return null;
        }
        try {
            return Instant.parse(text);
        } catch (DateTimeParseException notAnInstant) {
            return null;
        }
    }

    private static Map<String, Object> attributes(CanonicalSecurityContext context) {
        Map<String, Object> attributes = context.getAttributes();
        if (attributes == null) {
            attributes = new LinkedHashMap<>();
            context.setAttributes(attributes);
        }
        return attributes;
    }

    private static String key(String value) {
        return value == null ? "" : value.trim().toLowerCase(Locale.ROOT);
    }

    private static String firstText(String... values) {
        for (String value : values) {
            String text = text(value);
            if (text != null) {
                return text;
            }
        }
        return null;
    }

    private static String text(Object value) {
        if (value == null) {
            return null;
        }
        String text = value.toString().trim();
        return text.isEmpty() ? null : text;
    }
}
