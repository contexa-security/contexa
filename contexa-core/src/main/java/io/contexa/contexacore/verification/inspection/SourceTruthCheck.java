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
package io.contexa.contexacore.verification.inspection;

import io.contexa.contexacore.autonomous.company.CompanyRecordSet;
import io.contexa.contexacore.autonomous.context.CanonicalSecurityContext;
import io.contexa.contexacore.autonomous.context.CanonicalSecurityContext.ApprovalRecord;
import io.contexa.contexacore.autonomous.context.CanonicalSecurityContext.AssignmentRecord;
import io.contexa.contexacore.autonomous.context.CanonicalSecurityContext.FrictionProfile;
import io.contexa.contexacore.autonomous.context.CanonicalSecurityContext.OnCallRecord;
import io.contexa.contexacore.autonomous.context.decision.DecisionFacts;
import io.contexa.contexacore.autonomous.context.prompt.PromptBlock;
import io.contexa.contexacore.autonomous.tiered.prompt.AgentLineValues;

import java.time.Instant;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;

/**
 * W6-7 (P6-CHANGE-5, plan 2 C1, plan 2.1 of the prompt quality redesign): the facts the sealed decision collected are
 * the host's own records of them. The host's source verifier reads its sources again for the sealed decision and gives,
 * per fact, the piece of the dictionary line's value that states it; the check compares the piece with what the sealed
 * decision collected, the on-call record, the assignment, the approvals and the delegation of its canonical context,
 * written as the dictionary line states them. A collected value that holds the piece matches, another value or none is
 * a mismatch, unless the sealed decision facts name the fact unknown (its missing notation, N-SRC-1). Whether those
 * values reached the prompt as they were collected is the renderer's, which the build checks over the golden inputs.
 * <p>
 * Without a verifier the check records that no host source is integrated; a source that cannot be read now inspects the
 * package again later. A host that does not keep the records of the decision has the facts counted once as not compared
 * (N-SRC-2), and a fact of a line the sealed context keeps no structured value of is counted as not compared.
 */
public final class SourceTruthCheck implements PromptInspectionCheck {

    public static final String CODE = "SOURCE_TRUTH";
    private static final String NOT_INTEGRATED = "host source verifier";
    private static final String SEALED_CONTEXT = "canonicalContext";
    private static final String NOT_KEPT = "the host does not keep the records of this decision, so the facts are not "
            + "compared with the host's records";
    /** The structured values of the decision facts block the sealed context keeps, by the entry that states them. */
    private static final List<String> STRUCTURED_ENTRIES = List.of("OnCall", "Assignment", "Approval", "Delegation",
            "RecordProvenance");

    private final PromptFactSourceVerifier verifier;

    public SourceTruthCheck(PromptFactSourceVerifier verifier) {
        this.verifier = verifier;
    }

    @Override
    public String code() {
        return CODE;
    }

    /** The check reads the sealed context, not the prompt's lines, so it runs whatever the prompt's layout. */
    @Override
    public boolean dictionaryPromptOnly() {
        return false;
    }

    @Override
    public void inspect(PromptInspectionTally tally) {
        if (verifier == null) {
            tally.unverifiable(tally.unverifiableFinding().sourceRef(NOT_INTEGRATED)
                    .reason("no host source is integrated, so the facts are not compared with the host's records")
                    .build());
            return;
        }
        PromptFactSourceVerifier.SourceReading reading = verifier.read(tally.subject());
        if (reading != null && !reading.recordsKept()) {
            // N-SRC-2: the decision's records are gone at the host, so the facts are counted once as not compared.
            tally.unverifiable(tally.unverifiableFinding().sourceRef(reading.notKeptRef()).reason(NOT_KEPT).build());
            return;
        }
        List<PromptFactSourceVerifier.SourceFact> facts = reading == null ? List.of() : reading.facts();
        if (facts.isEmpty()) {
            return;
        }
        CanonicalSecurityContext context = tally.subject().canonicalContext();
        if (context == null) {
            tally.unverifiable(tally.unverifiableFinding().sourceRef(SEALED_CONTEXT)
                    .reason("the decision's context is not sealed, so the host's facts are not compared").build());
            return;
        }
        Map<String, List<String>> collected = collected(context);
        DecisionFacts decisionFacts = context.getDecisionFacts();
        for (PromptFactSourceVerifier.SourceFact fact : facts) {
            if (fact.block() != PromptBlock.DECISION_FACTS || !STRUCTURED_ENTRIES.contains(fact.entry())) {
                tally.unverifiable(tally.unverifiableFinding().block(title(fact.block())).entry(fact.entry())
                        .expected(fact.fragment()).sourceRef(fact.sourceRef())
                        .reason("the sealed context keeps no structured value of this line, so the fact is not compared")
                        .build());
                continue;
            }
            List<String> values = collected.getOrDefault(fact.entry(), List.of());
            if (values.isEmpty()) {
                // N-SRC-1: a fact the sealed decision facts name unknown has its missing notation.
                if (decisionFacts != null && decisionFacts.unknown().contains(fact.entry())) {
                    tally.matched();
                    continue;
                }
                tally.mismatch(tally.mismatchFinding().block(title(fact.block())).entry(fact.entry())
                        .expected(fact.fragment()).actual("not collected").sourceRef(fact.sourceRef())
                        .reason("the host's source keeps the fact but the sealed decision did not collect it").build());
                continue;
            }
            if (values.stream().anyMatch(value -> holds(value, fact))) {
                tally.matched();
                continue;
            }
            tally.mismatch(tally.mismatchFinding().block(title(fact.block())).entry(fact.entry())
                    .expected(fact.fragment()).actual(values.get(0)).sourceRef(fact.sourceRef())
                    .reason("the sealed decision collected another value than the host's source keeps").build());
        }
    }

    /**
     * What the sealed decision collected for the decision facts lines the host's facts name, in the words of those lines:
     * whether the person was on call at the request time, the assignment to the target, each approval with its approver,
     * item limit and the use the host stated, and the delegation and who recorded the records the request rests on.
     */
    static Map<String, List<String>> collected(CanonicalSecurityContext context) {
        Map<String, List<String>> values = new LinkedHashMap<>();
        Instant at = context.getRequestObservedAt();
        FrictionProfile friction = context.getFrictionProfile();
        if (friction != null) {
            Boolean onCall = onCallAt(friction.getOnCall(), at);
            if (onCall != null) {
                add(values, "OnCall", onCall ? "on call" : "not on call");
            }
            AssignmentRecord assignment = friction.getAssignment();
            String target = assignment != null ? text(assignment.getTarget()) : null;
            if (target != null && assignment.getAssigned() != null) {
                boolean manager = CompanyRecordSet.ACCOUNT_MANAGER.equalsIgnoreCase(
                        String.valueOf(assignment.getResponsibility()));
                boolean assigned = assignment.getAssigned();
                add(values, "Assignment", (manager
                        ? (assigned ? "account manager of " : "not the account manager of ")
                        : (assigned ? "assigned to " : "not assigned to ")) + target);
            }
            if (friction.getApprovalRecords() != null) {
                for (ApprovalRecord approval : friction.getApprovalRecords()) {
                    String approvalText = approval != null ? approval(approval) : null;
                    if (approvalText != null) {
                        add(values, "Approval", approvalText);
                    }
                }
            }
        }
        String delegation = AgentLineValues.delegation(context, at);
        if (delegation != null) {
            add(values, "Delegation", delegation);
        }
        String provenance = AgentLineValues.recordProvenance(context, at);
        if (provenance != null) {
            add(values, "RecordProvenance", provenance);
        }
        return values;
    }

    /** An approval as the approval line states it: its id and approver, its item limit, and the use the host stated. */
    private static String approval(ApprovalRecord approval) {
        String id = text(approval.getApprovalId());
        if (id == null) {
            return null;
        }
        List<String> parts = new ArrayList<>();
        String approver = text(approval.getApprover());
        parts.add(approver != null ? id + " by " + approver : id);
        if (approval.getMaxItems() != null) {
            parts.add("up to " + number(approval.getMaxItems()) + " items");
        }
        if (approval.getUsedItems() != null) {
            parts.add("used " + number(approval.getUsedItems()) + " before this request");
        }
        return String.join(", ", parts);
    }

    /**
     * Whether the person is on call at the request time by the on-call record the host stated, as CompanyRecordsEvaluator
     * reads it for the decision; null when the host did not say.
     */
    private static Boolean onCallAt(OnCallRecord record, Instant at) {
        if (record == null || record.getOnCall() == null) {
            return null;
        }
        if (!record.getOnCall()) {
            return false;
        }
        return at == null || ((record.getStartsAt() == null || !at.isBefore(record.getStartsAt()))
                && (record.getEndsAt() == null || at.isBefore(record.getEndsAt())));
    }

    private static boolean holds(String value, PromptFactSourceVerifier.SourceFact fact) {
        return value.contains(fact.fragment()) && (fact.excluded() == null || !value.contains(fact.excluded()));
    }

    private static void add(Map<String, List<String>> values, String entry, String value) {
        values.computeIfAbsent(entry, key -> new ArrayList<>()).add(value);
    }

    private static String number(int value) {
        return String.format(Locale.ROOT, "%,d", value);
    }

    private static String text(Object value) {
        if (value == null) {
            return null;
        }
        String text = value.toString().trim();
        return text.isEmpty() ? null : text;
    }

    private static String title(PromptBlock block) {
        return block != null ? block.title() : null;
    }
}
