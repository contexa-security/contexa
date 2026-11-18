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

import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

/**
 * The output contract v4 of the v21 security decision: the response fields with the explanations the model weighed, and
 * the reason codes it cites with a fact ID. A code names a fact the model weighed or a judgment the model made on the
 * lines it cites (a record that covers the work is the model's judgment of the record's line, not the core's); no code
 * belongs to a decision rule. The output contract v5 and the response check read its reason codes, and the response
 * check still reads an answer of this contract with the explanations it weighed (plan 6-2: the v4 schema and output
 * block went with the bundles that asked for them).
 */
public final class SecurityDecisionOutputContractV4 {

    public static final List<String> ACTIONS = SecurityDecisionOutputContract.ACTIONS;
    /** The longest reason the response processor keeps: 40 words fit in it. */
    public static final int MAX_REASON_CHARACTERS = 300;
    public static final String FACT_ID_PATTERN = SecurityDecisionOutputContract.FACT_ID_PATTERN;
    /** The explanations the system text names; H5 is another one the model names. */
    public static final List<String> HYPOTHESES = List.of("H1", "H2", "H3", "H4", "H5");
    public static final List<String> ASSESSMENTS = List.of("MOST_LIKELY", "POSSIBLE", "UNLIKELY", "NO_EVIDENCE");

    /** The reason code groups of v4. */
    public enum Group {
        BUSINESS_RECORDS, DEVIATION, AS_USUAL, DATA_AND_SCOPE, DELEGATION, SESSION, PAST_RECORDS, CONFLICTS, ESCALATION
    }

    /**
     * One reason code: its meaning as the system text states it and the dictionary entries it may cite, as
     * {@code BLOCK.Name}.
     */
    public record ReasonCode(String code, Group group, String meaning, List<String> citedFacts) {

        public ReasonCode {
            citedFacts = List.copyOf(citedFacts);
        }
    }

    /**
     * The meaning of each code, from the product prompt document (plan 6-1): the sentences of the prompt are the
     * document's, the identifiers, groups and cited lines the engine's.
     */
    private static final Map<String, String> MEANINGS = SecurityDecisionPromptDocument.reasonMeanings(
            SecurityDecisionPromptDocument.product());

    public static final List<ReasonCode> REASON_CODES = List.of(
            // v21.15 (RL-2): the delegation and the company policy are records too; a model that finds the work covered by
            // either cites the line that says so under this code.
            code(Group.BUSINESS_RECORDS, "RECORD_COVERS_WORK",
                    List.of("DECISION_FACTS.Approval", "DECISION_FACTS.Ticket", "DECISION_FACTS.RecordProvenance",
                            "DECISION_FACTS.Delegation", "DECISION_FACTS.Policy")),
            code(Group.BUSINESS_RECORDS, "RECORD_DECIDED_AFTER_REQUEST",
                    List.of("DECISION_FACTS.Approval")),
            code(Group.BUSINESS_RECORDS, "RECORD_OUTSIDE_PERIOD",
                    List.of("DECISION_FACTS.Approval", "DECISION_FACTS.Ticket")),
            code(Group.BUSINESS_RECORDS, "RECORD_OTHER_TARGET",
                    List.of("DECISION_FACTS.Approval", "DECISION_FACTS.Ticket")),
            code(Group.BUSINESS_RECORDS, "RECORD_OVER_LIMIT",
                    List.of("DECISION_FACTS.Approval")),
            code(Group.BUSINESS_RECORDS, "RECORD_CUMULATIVE_OVER_LIMIT",
                    List.of("DECISION_FACTS.Approval", "DECISION_FACTS.RepeatInSession")),
            code(Group.BUSINESS_RECORDS, "NO_COVERING_RECORD",
                    List.of("DECISION_FACTS.Policy", "DECISION_FACTS.Approval", "DECISION_FACTS.Ticket")),
            code(Group.BUSINESS_RECORDS, "POLICY_NOT_KNOWN",
                    List.of("DECISION_FACTS.Policy", "UNKNOWN.Unknown")),
            code(Group.BUSINESS_RECORDS, "TICKET_CLAIM_FALSE",
                    List.of("DECISION_FACTS.Ticket")),
            code(Group.BUSINESS_RECORDS, "ASSIGNED_TARGET",
                    List.of("DECISION_FACTS.Assignment")),
            code(Group.BUSINESS_RECORDS, "ON_CALL",
                    List.of("DECISION_FACTS.OnCall")),
            code(Group.BUSINESS_RECORDS, "TRAVEL_EXPLAINS_NETWORK",
                    List.of("DECISION_FACTS.Travel")),
            code(Group.BUSINESS_RECORDS, "BREAK_GLASS",
                    List.of("DECISION_FACTS.BreakGlass")),
            code(Group.DEVIATION, "DEVIATION_TIME",
                    List.of("DECISION_FACTS.DeviationsFromBaseline")),
            code(Group.DEVIATION, "DEVIATION_DAY",
                    List.of("DECISION_FACTS.DeviationsFromBaseline")),
            code(Group.DEVIATION, "DEVIATION_NETWORK",
                    List.of("DECISION_FACTS.DeviationsFromBaseline")),
            code(Group.DEVIATION, "DEVIATION_DEVICE",
                    List.of("DECISION_FACTS.DeviationsFromBaseline")),
            code(Group.DEVIATION, "DEVIATION_LOGIN_METHOD",
                    List.of("DECISION_FACTS.DeviationsFromBaseline")),
            code(Group.DEVIATION, "DEVIATION_TARGET",
                    List.of("DECISION_FACTS.DeviationsFromBaseline")),
            code(Group.DEVIATION, "DEVIATION_ACTION",
                    List.of("DECISION_FACTS.DeviationsFromBaseline")),
            code(Group.DEVIATION, "DEVIATION_RESOURCE_CLASS",
                    List.of("DECISION_FACTS.DeviationsFromBaseline")),
            code(Group.DEVIATION, "DEVIATION_SIZE",
                    List.of("DECISION_FACTS.DeviationsFromBaseline")),
            code(Group.DEVIATION, "DEVIATION_RATE",
                    List.of("DECISION_FACTS.DeviationsFromBaseline")),
            code(Group.DEVIATION, "DEVIATION_MOVEMENT",
                    List.of("DECISION_FACTS.Movement")),
            code(Group.DEVIATION, "SESSION_DEVICE_CHANGE",
                    List.of("DECISION_FACTS.SessionDeviceChange")),
            code(Group.DEVIATION, "SESSION_NETWORK_CHANGE",
                    List.of("DECISION_FACTS.SessionNetworkChange")),
            code(Group.AS_USUAL, "BASELINE_MATCH",
                    List.of("DECISION_FACTS.SameAsBaseline")),
            code(Group.AS_USUAL, "BASELINE_NOT_ESTABLISHED",
                    List.of("USER_BASELINE.BaselineStatus")),
            code(Group.DATA_AND_SCOPE, "DATA_NATURE_MISMATCH",
                    List.of("REQUEST.Target", "REQUEST.ResourceClass", "DECISION_FACTS.Assignment",
                            "DECISION_FACTS.RoleScope", "DECISION_FACTS.DeviationsFromBaseline")),
            code(Group.DATA_AND_SCOPE, "ROLE_SCOPE_OUTSIDE",
                    List.of("DECISION_FACTS.RoleScope")),
            code(Group.DATA_AND_SCOPE, "RECENT_PERMISSION_CHANGE",
                    List.of("DECISION_FACTS.RecentPermissionChanges")),
            code(Group.DATA_AND_SCOPE, "TEMPORARY_ELEVATION",
                    List.of("DECISION_FACTS.TemporaryElevation")),
            // v21.18 (CQ-1): the host states where a value of the call first appeared; what that means is the model's.
            code(Group.DATA_AND_SCOPE, "VALUE_FROM_UNTRUSTED_OUTPUT",
                    List.of("DECISION_FACTS.ArgumentOrigin")),
            // v21.9 (A2-9): what the agent did so far in its session is part of its delegated run and its session.
            code(Group.DELEGATION, "DELEGATION_SCOPE_DRIFT",
                    List.of("DECISION_FACTS.Delegation", "SESSION.DelegationActivity")),
            // v21.15 (RL-2): what the delegation's objective calls for is read from its words and the amounts the lines
            // state; that reading is the model's judgment, apart from the core's own comparison above.
            code(Group.DELEGATION, "DELEGATION_OBJECTIVE_EXCEEDED",
                    List.of("DECISION_FACTS.Delegation", "SESSION.DelegationActivity")),
            code(Group.SESSION, "SESSION_SEQUENCE",
                    List.of("SESSION.RequestsInSession", "SESSION.RecentRequests", "DECISION_FACTS.RepeatInSession",
                            "SESSION.DelegationActivity")),
            code(Group.SESSION, "REPEAT_IN_SESSION",
                    List.of("DECISION_FACTS.RepeatInSession", "SESSION.RequestsInSession")),
            code(Group.SESSION, "PRIOR_CHALLENGE_IN_SESSION",
                    List.of("SESSION.RequestsInSession")),
            code(Group.SESSION, "CHALLENGE_VERIFIED_IN_SESSION",
                    List.of("SESSION.ChallengeVerified")),
            code(Group.SESSION, "FAILED_LOGINS",
                    List.of("SESSION.FailedLogins")),
            code(Group.SESSION, "MFA_FAILURES",
                    List.of("SESSION.MfaFailures")),
            // v21.5 (finding 12): the counted fact states the same target's earlier allowed records too, as the
            // dictionary's use of that entry says.
            code(Group.PAST_RECORDS, "PAST_RECORD_SAME_TARGET",
                    List.of("PAST_RECORDS.PastRecordCounts", "PAST_RECORDS.PastRecord{i}")),
            code(Group.PAST_RECORDS, "PAST_DENIED_SAME_ACTION",
                    List.of("PAST_RECORDS.PastDeniedDecision{i}", "SESSION.RecentDenied")),
            code(Group.PAST_RECORDS, "VALIDATED_CASE_MATCH",
                    List.of("PAST_RECORDS.ValidatedCases")),
            code(Group.CONFLICTS, "CLIENT_SIGNAL_TAMPERING",
                    List.of("DECISION_FACTS.ClientSignals")),
            code(Group.CONFLICTS, "TENANT_CONFLICT",
                    List.of("DECISION_FACTS.DataConflicts")),
            code(Group.CONFLICTS, "AUTHORIZATION_CONFLICT",
                    List.of("DECISION_FACTS.DataConflicts", "DECISION_FACTS.AuthorizationEffect")),
            code(Group.CONFLICTS, "DATA_CONFLICT",
                    List.of("DECISION_FACTS.DataConflicts")),
            code(Group.CONFLICTS, "THREAT_MATCH",
                    List.of("DECISION_FACTS.ThreatMatch")),
            code(Group.ESCALATION, "MATERIAL_CONTRADICTION",
                    List.of("DECISION_FACTS.DataConflicts", "DECISION_FACTS.AuthorizationEffect",
                            "SESSION.LoginMethod", "REQUEST.Roles", "REQUEST.Credential")),
            code(Group.ESCALATION, "MATERIAL_MISSING_EVIDENCE",
                    List.of("UNKNOWN.Unknown")));

    private static final List<String> CODES = REASON_CODES.stream().map(ReasonCode::code).toList();

    static {
        // The start fails when the document names other codes than the engine (plan 6-1).
        SecurityDecisionPromptDocument.verifyReasonCodes(SecurityDecisionPromptDocument.product(), CODES);
        // Plan 3.9: the prompt injection guard of every Contexa version is checked here, not by an evaluation record.
        SecurityDecisionPromptDocument.verifyInjectionGuardOfReleases();
    }

    /** The line names each code may cite, by code, as the output block names them. */
    private static final Map<String, List<String>> CITED_LINES = citedLinesByCode();
    private SecurityDecisionOutputContractV4() {
    }

    public static List<String> codes() {
        return CODES;
    }

    /** The code of that name, if the contract has it. */
    public static Optional<ReasonCode> find(String code) {
        return REASON_CODES.stream().filter(reason -> reason.code().equals(code)).findFirst();
    }

    /** A cited entry as the output block names it: its line name. */
    private static String citedName(String fact) {
        return fact.substring(fact.indexOf('.') + 1).replace("{i}", "");
    }

    private static ReasonCode code(Group group, String code, List<String> citedFacts) {
        return new ReasonCode(code, group, MEANINGS.get(code), citedFacts);
    }

    /** The line names each code may cite, by code, in the order of the codes. */
    public static Map<String, List<String>> citedLines() {
        return CITED_LINES;
    }

    private static Map<String, List<String>> citedLinesByCode() {
        Map<String, List<String>> lines = new LinkedHashMap<>();
        for (ReasonCode code : REASON_CODES) {
            lines.put(code.code(), code.citedFacts().stream().map(SecurityDecisionOutputContractV4::citedName)
                    .distinct().toList());
        }
        return Collections.unmodifiableMap(lines);
    }

}
