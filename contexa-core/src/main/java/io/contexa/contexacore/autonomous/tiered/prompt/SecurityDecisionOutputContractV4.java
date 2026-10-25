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

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.stream.Collectors;

/**
 * The output contract v4 of the v21 security decision: the response fields with the explanations the model weighed, and
 * the reason codes it cites with a fact ID. A code names a fact the model weighed or a judgment the model made on the
 * lines it cites (a record that covers the work is the model's judgment of the record's line, not the core's); no code
 * belongs to a decision rule. The provider schema, the system text's output block and the response check read this one
 * source.
 */
public final class SecurityDecisionOutputContractV4 {

    public static final List<String> ACTIONS = SecurityDecisionOutputContract.ACTIONS;
    public static final int MIN_REASON_CODES = 1;
    public static final int MAX_REASON_CODES = 5;
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

    public static final List<ReasonCode> REASON_CODES = List.of(
            // v21.15 (RL-2): the delegation and the company policy are records too; a model that finds the work covered by
            // either cites the line that says so under this code.
            code(Group.BUSINESS_RECORDS, "RECORD_COVERS_WORK",
                    "you judged that this record, delegation or company policy covers this work by its target, purpose,"
                            + " period, limit and decision time",
                    List.of("DECISION_FACTS.Approval", "DECISION_FACTS.Ticket", "DECISION_FACTS.RecordProvenance",
                            "DECISION_FACTS.Delegation", "DECISION_FACTS.Policy")),
            code(Group.BUSINESS_RECORDS, "RECORD_DECIDED_AFTER_REQUEST",
                    "the record was decided after this request",
                    List.of("DECISION_FACTS.Approval")),
            code(Group.BUSINESS_RECORDS, "RECORD_OUTSIDE_PERIOD",
                    "this request is outside the record's period",
                    List.of("DECISION_FACTS.Approval", "DECISION_FACTS.Ticket")),
            code(Group.BUSINESS_RECORDS, "RECORD_OTHER_TARGET",
                    "the record is for another target or purpose than this request",
                    List.of("DECISION_FACTS.Approval", "DECISION_FACTS.Ticket")),
            code(Group.BUSINESS_RECORDS, "RECORD_OVER_LIMIT",
                    "this request asks for more than the record allows",
                    List.of("DECISION_FACTS.Approval")),
            code(Group.BUSINESS_RECORDS, "RECORD_CUMULATIVE_OVER_LIMIT",
                    "what was already used under the record and this request together exceed its limit",
                    List.of("DECISION_FACTS.Approval", "DECISION_FACTS.RepeatInSession")),
            code(Group.BUSINESS_RECORDS, "NO_COVERING_RECORD",
                    "you judged that no record stated for this request covers the work the policy asks a record for",
                    List.of("DECISION_FACTS.Policy", "DECISION_FACTS.Approval", "DECISION_FACTS.Ticket")),
            code(Group.BUSINESS_RECORDS, "POLICY_NOT_KNOWN",
                    "the company policy for this work is not known",
                    List.of("DECISION_FACTS.Policy", "UNKNOWN.Unknown")),
            code(Group.BUSINESS_RECORDS, "TICKET_CLAIM_FALSE",
                    "the ticket the requester names does not exist",
                    List.of("DECISION_FACTS.Ticket")),
            code(Group.BUSINESS_RECORDS, "ASSIGNED_TARGET",
                    "the requester is assigned to the target",
                    List.of("DECISION_FACTS.Assignment")),
            code(Group.BUSINESS_RECORDS, "ON_CALL",
                    "the requester is on call at the request time",
                    List.of("DECISION_FACTS.OnCall")),
            code(Group.BUSINESS_RECORDS, "TRAVEL_EXPLAINS_NETWORK",
                    "you judged that a trip explains the network of this request",
                    List.of("DECISION_FACTS.Travel")),
            code(Group.BUSINESS_RECORDS, "BREAK_GLASS",
                    "an emergency access is declared",
                    List.of("DECISION_FACTS.BreakGlass")),
            code(Group.DEVIATION, "DEVIATION_TIME",
                    "the time is not among the usual ones",
                    List.of("DECISION_FACTS.DeviationsFromBaseline")),
            code(Group.DEVIATION, "DEVIATION_DAY",
                    "the day is not among the usual ones",
                    List.of("DECISION_FACTS.DeviationsFromBaseline")),
            code(Group.DEVIATION, "DEVIATION_NETWORK",
                    "the network is not among the usual ones",
                    List.of("DECISION_FACTS.DeviationsFromBaseline")),
            code(Group.DEVIATION, "DEVIATION_DEVICE",
                    "the device is not among the usual ones",
                    List.of("DECISION_FACTS.DeviationsFromBaseline")),
            code(Group.DEVIATION, "DEVIATION_LOGIN_METHOD",
                    "the login method is not among the usual ones",
                    List.of("DECISION_FACTS.DeviationsFromBaseline")),
            code(Group.DEVIATION, "DEVIATION_TARGET",
                    "the target is not among the usual ones",
                    List.of("DECISION_FACTS.DeviationsFromBaseline")),
            code(Group.DEVIATION, "DEVIATION_ACTION",
                    "the action is not among the usual ones",
                    List.of("DECISION_FACTS.DeviationsFromBaseline")),
            code(Group.DEVIATION, "DEVIATION_RESOURCE_CLASS",
                    "the resource class is not among the usual ones",
                    List.of("DECISION_FACTS.DeviationsFromBaseline")),
            code(Group.DEVIATION, "DEVIATION_SIZE",
                    "the size is beyond the usual sizes",
                    List.of("DECISION_FACTS.DeviationsFromBaseline")),
            code(Group.DEVIATION, "DEVIATION_RATE",
                    "the request rate is beyond the usual rate",
                    List.of("DECISION_FACTS.DeviationsFromBaseline")),
            code(Group.DEVIATION, "DEVIATION_MOVEMENT",
                    "the movement from the previous place",
                    List.of("DECISION_FACTS.Movement")),
            code(Group.DEVIATION, "SESSION_DEVICE_CHANGE",
                    "the device changed within the session",
                    List.of("DECISION_FACTS.SessionDeviceChange")),
            code(Group.DEVIATION, "SESSION_NETWORK_CHANGE",
                    "the network address changed within the session",
                    List.of("DECISION_FACTS.SessionNetworkChange")),
            code(Group.AS_USUAL, "BASELINE_MATCH",
                    "the compared dimensions are among the usual ones",
                    List.of("DECISION_FACTS.SameAsBaseline")),
            code(Group.AS_USUAL, "BASELINE_NOT_ESTABLISHED",
                    "the personal baseline is not established, so a comparison shows little",
                    List.of("USER_BASELINE.BaselineStatus")),
            code(Group.DATA_AND_SCOPE, "DATA_NATURE_MISMATCH",
                    "you judged that what the data is does not fit the requester's role, assignment or usual work",
                    List.of("REQUEST.Target", "REQUEST.ResourceClass", "DECISION_FACTS.Assignment",
                            "DECISION_FACTS.RoleScope", "DECISION_FACTS.DeviationsFromBaseline")),
            code(Group.DATA_AND_SCOPE, "ROLE_SCOPE_OUTSIDE",
                    "you judged that the action or category is not among what the scope group does",
                    List.of("DECISION_FACTS.RoleScope")),
            code(Group.DATA_AND_SCOPE, "RECENT_PERMISSION_CHANGE",
                    "a recent permission change",
                    List.of("DECISION_FACTS.RecentPermissionChanges")),
            code(Group.DATA_AND_SCOPE, "TEMPORARY_ELEVATION",
                    "a temporary elevation is active",
                    List.of("DECISION_FACTS.TemporaryElevation")),
            // v21.9 (A2-9): what the agent did so far in its session is part of its delegated run and its session.
            code(Group.DELEGATION, "DELEGATION_SCOPE_DRIFT",
                    "the comparison of this request with the delegation says drift: it leaves the allowed operations,"
                            + " resources or stated limits",
                    List.of("DECISION_FACTS.Delegation", "SESSION.DelegationActivity")),
            // v21.15 (RL-2): what the delegation's objective calls for is read from its words and the amounts the lines
            // state; that reading is the model's judgment, apart from the core's own comparison above.
            code(Group.DELEGATION, "DELEGATION_OBJECTIVE_EXCEEDED",
                    "you judged that the amount, breadth or purpose of this request goes beyond what the delegation's"
                            + " objective calls for",
                    List.of("DECISION_FACTS.Delegation", "SESSION.DelegationActivity")),
            code(Group.SESSION, "SESSION_SEQUENCE",
                    "you judged that the order, pace or amount of this session's requests changes the story",
                    List.of("SESSION.RequestsInSession", "SESSION.RecentRequests", "DECISION_FACTS.RepeatInSession",
                            "SESSION.DelegationActivity")),
            code(Group.SESSION, "REPEAT_IN_SESSION",
                    "the same action repeats in the session",
                    List.of("DECISION_FACTS.RepeatInSession", "SESSION.RequestsInSession")),
            code(Group.SESSION, "PRIOR_CHALLENGE_IN_SESSION",
                    "an earlier challenge or non-allow decision in this session",
                    List.of("SESSION.RequestsInSession")),
            code(Group.SESSION, "CHALLENGE_VERIFIED_IN_SESSION",
                    "a challenge was passed in this session",
                    List.of("SESSION.ChallengeVerified")),
            code(Group.SESSION, "FAILED_LOGINS",
                    "recent failed logins",
                    List.of("SESSION.FailedLogins")),
            code(Group.SESSION, "MFA_FAILURES",
                    "recent MFA failures",
                    List.of("SESSION.MfaFailures")),
            // v21.5 (finding 12): the counted fact states the same target's earlier allowed records too, as the
            // dictionary's use of that entry says.
            code(Group.PAST_RECORDS, "PAST_RECORD_SAME_TARGET",
                    "an earlier allowed record on the same target",
                    List.of("PAST_RECORDS.PastRecordCounts", "PAST_RECORDS.PastRecord{i}")),
            code(Group.PAST_RECORDS, "PAST_DENIED_SAME_ACTION",
                    "a recent non-allow decision or refusal of the same action",
                    List.of("PAST_RECORDS.PastDeniedDecision{i}", "SESSION.RecentDenied")),
            code(Group.PAST_RECORDS, "VALIDATED_CASE_MATCH",
                    "a validated case matches",
                    List.of("PAST_RECORDS.ValidatedCases")),
            code(Group.CONFLICTS, "CLIENT_SIGNAL_TAMPERING",
                    "a measured client tampering signal",
                    List.of("DECISION_FACTS.ClientSignals")),
            code(Group.CONFLICTS, "TENANT_CONFLICT",
                    "a tenant or organization conflict",
                    List.of("DECISION_FACTS.DataConflicts")),
            code(Group.CONFLICTS, "AUTHORIZATION_CONFLICT",
                    "an authorization conflict",
                    List.of("DECISION_FACTS.DataConflicts", "DECISION_FACTS.AuthorizationEffect")),
            code(Group.CONFLICTS, "DATA_CONFLICT",
                    "a data conflict",
                    List.of("DECISION_FACTS.DataConflicts")),
            code(Group.CONFLICTS, "THREAT_MATCH",
                    "a match with threat knowledge",
                    List.of("DECISION_FACTS.ThreatMatch")),
            code(Group.ESCALATION, "MATERIAL_CONTRADICTION",
                    "facts that weigh in the judgment contradict each other",
                    List.of("DECISION_FACTS.DataConflicts", "DECISION_FACTS.AuthorizationEffect",
                            "SESSION.LoginMethod", "REQUEST.Roles", "REQUEST.Credential")),
            code(Group.ESCALATION, "MATERIAL_MISSING_EVIDENCE",
                    "a fact that would separate the explanations is missing",
                    List.of("UNKNOWN.Unknown")));

    private static final List<String> CODES = REASON_CODES.stream().map(ReasonCode::code).toList();
    private static final String PROVIDER_SCHEMA = writeProviderSchema(true);
    private static final String TEXT_SCHEMA = writeProviderSchema(false);
    private static final String OUTPUT_BLOCK = writeOutputBlock();

    private SecurityDecisionOutputContractV4() {
    }

    public static List<String> codes() {
        return CODES;
    }

    /** The code of that name, if the contract has it. */
    public static Optional<ReasonCode> find(String code) {
        return REASON_CODES.stream().filter(reason -> reason.code().equals(code)).findFirst();
    }

    /** The strict JSON schema for a provider with structured output: every field required, no other keys. */
    public static String providerSchema() {
        return PROVIDER_SCHEMA;
    }

    /** The schema as text for a provider without structured output; the output block states the code meanings. */
    public static String textSchema() {
        return TEXT_SCHEMA;
    }

    /** The output block of the v21 system text: the fields, how a code cites a fact and the meaning of every code. */
    public static String systemOutputBlock() {
        return OUTPUT_BLOCK;
    }

    private static String writeOutputBlock() {
        StringBuilder block = new StringBuilder();
        block.append("=== OUTPUT ===\n");
        block.append("Return one JSON object with exactly these keys: action, hypotheses, reasonCodes, reason, riskScore,"
                + " confidence, mitre.\n");
        block.append("action: ALLOW, CHALLENGE, ESCALATE or BLOCK.\n");
        block.append("hypotheses: one object per explanation you weighed: {\"id\": \"H1\" | \"H2\" | \"H3\" | \"H4\" |"
                + " \"H5\", \"name\": a short name for H5 or null, \"assessment\": \"MOST_LIKELY\" | \"POSSIBLE\" |"
                + " \"UNLIKELY\" | \"NO_EVIDENCE\", \"for\": [fact ids], \"against\": [fact ids]}. H5 is another"
                + " explanation you named.\n");
        block.append("reasonCodes: ").append(MIN_REASON_CODES).append(" to ").append(MAX_REASON_CODES)
                .append(" objects {\"code\": ..., \"fact\": ...} for the facts that weigh most in your judgment, first the"
                        + " strongest. code is one of the codes below; fact is the id at the start of the line it cites"
                        + " (F1, B2, S3, R1, P1); MATERIAL_MISSING_EVIDENCE cites the id the UNKNOWN line gives the"
                        + " missing fact (U1).\n");
        block.append("reason: one sentence of at most 40 words, in your own words, that names the explanation you judged"
                + " most likely and the facts behind it.\n");
        block.append("riskScore and confidence: numbers from 0 to 1, or null. mitre: a list of MITRE ATT&CK technique ids,"
                + " or null. These three are kept for audit.\n");
        block.append("Reason codes (code: meaning; the lines it cites):\n");
        for (ReasonCode code : REASON_CODES) {
            block.append("- ").append(code.code()).append(": ").append(code.meaning()).append("; ")
                    .append(String.join(", ", code.citedFacts().stream()
                            .map(SecurityDecisionOutputContractV4::citedName).distinct().toList()))
                    .append('\n');
        }
        return block.toString();
    }

    /** A cited entry as the output block names it: its line name. */
    private static String citedName(String fact) {
        return fact.substring(fact.indexOf('.') + 1).replace("{i}", "");
    }

    private static ReasonCode code(Group group, String code, String meaning, List<String> citedFacts) {
        return new ReasonCode(code, group, meaning, citedFacts);
    }

    private static String writeProviderSchema(boolean withCodeMeanings) {
        Map<String, Object> factId = new LinkedHashMap<>();
        factId.put("type", "string");
        factId.put("pattern", FACT_ID_PATTERN);

        Map<String, Object> hypothesisId = new LinkedHashMap<>();
        hypothesisId.put("type", "string");
        hypothesisId.put("enum", HYPOTHESES);
        Map<String, Object> assessment = new LinkedHashMap<>();
        assessment.put("type", "string");
        assessment.put("enum", ASSESSMENTS);
        Map<String, Object> facts = new LinkedHashMap<>();
        facts.put("type", "array");
        facts.put("items", factId);
        Map<String, Object> name = new LinkedHashMap<>();
        name.put("type", List.of("string", "null"));
        Map<String, Object> hypothesisProperties = new LinkedHashMap<>();
        hypothesisProperties.put("id", hypothesisId);
        hypothesisProperties.put("name", name);
        hypothesisProperties.put("assessment", assessment);
        hypothesisProperties.put("for", facts);
        hypothesisProperties.put("against", facts);
        Map<String, Object> hypothesis = new LinkedHashMap<>();
        hypothesis.put("type", "object");
        hypothesis.put("additionalProperties", false);
        hypothesis.put("required", List.copyOf(hypothesisProperties.keySet()));
        hypothesis.put("properties", hypothesisProperties);
        Map<String, Object> hypotheses = new LinkedHashMap<>();
        hypotheses.put("type", "array");
        hypotheses.put("minItems", 1);
        hypotheses.put("maxItems", HYPOTHESES.size());
        hypotheses.put("items", hypothesis);

        Map<String, Object> code = new LinkedHashMap<>();
        code.put("type", "string");
        code.put("enum", CODES);
        if (withCodeMeanings) {
            code.put("description", REASON_CODES.stream().map(reason -> reason.code() + ": " + reason.meaning())
                    .collect(Collectors.joining("\n")));
        }
        Map<String, Object> itemProperties = new LinkedHashMap<>();
        itemProperties.put("code", code);
        itemProperties.put("fact", factId);
        Map<String, Object> item = new LinkedHashMap<>();
        item.put("type", "object");
        item.put("additionalProperties", false);
        item.put("required", List.of("code", "fact"));
        item.put("properties", itemProperties);
        Map<String, Object> reasonCodes = new LinkedHashMap<>();
        reasonCodes.put("type", "array");
        reasonCodes.put("minItems", MIN_REASON_CODES);
        reasonCodes.put("maxItems", MAX_REASON_CODES);
        reasonCodes.put("items", item);

        Map<String, Object> properties = new LinkedHashMap<>();
        Map<String, Object> action = new LinkedHashMap<>();
        action.put("type", "string");
        action.put("enum", ACTIONS);
        properties.put("action", action);
        properties.put("hypotheses", hypotheses);
        properties.put("reasonCodes", reasonCodes);
        properties.put("reason", Map.of("type", "string"));
        properties.put("riskScore", score());
        properties.put("confidence", score());
        Map<String, Object> mitre = new LinkedHashMap<>();
        mitre.put("type", List.of("array", "null"));
        mitre.put("items", Map.of("type", "string"));
        properties.put("mitre", mitre);
        Map<String, Object> schema = new LinkedHashMap<>();
        schema.put("type", "object");
        schema.put("additionalProperties", false);
        schema.put("required", List.copyOf(properties.keySet()));
        schema.put("properties", properties);
        try {
            return new ObjectMapper().writeValueAsString(schema);
        } catch (JsonProcessingException e) {
            throw new IllegalStateException("The output contract v4 schema cannot be written", e);
        }
    }

    private static Map<String, Object> score() {
        Map<String, Object> score = new LinkedHashMap<>();
        score.put("type", List.of("number", "null"));
        score.put("minimum", 0);
        score.put("maximum", 1);
        return score;
    }
}
