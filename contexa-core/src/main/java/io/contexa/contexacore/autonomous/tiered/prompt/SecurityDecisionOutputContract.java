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
import java.util.stream.Collectors;

/**
 * The output contract v3 of the security decision (dictionary 4 and 5, W4-2): the response fields, the reason codes
 * the model cites with a fact ID, and the schema a provider with structured output enforces. The provider schema, the
 * system text's output block and the parser read this one source.
 */
public final class SecurityDecisionOutputContract {

    public static final List<String> ACTIONS = List.of("ALLOW", "CHALLENGE", "ESCALATE", "BLOCK");
    public static final int MIN_REASON_CODES = 1;
    public static final int MAX_REASON_CODES = 5;
    /** The longest reason; the response processor keeps it, since strict structured output has no length keyword. */
    public static final int MAX_REASON_CHARACTERS = 200;
    /** A fact ID the prompt draws: a block letter (USER BASELINE, SESSION, REQUEST, DECISION FACTS, PAST RECORDS). */
    public static final String FACT_ID_PATTERN = "^[BSRFPU][0-9]{1,2}$";

    /** The groups of dictionary 5. */
    public enum Group {
        MINIMUM_ACTION, POLICY, BUSINESS_RECORDS, DEVIATION, AS_USUAL, SCOPE_AND_PERMISSIONS, DELEGATION, SESSION,
        PAST_RECORDS, BLOCK_GROUNDS, ESCALATION
    }

    /**
     * One reason code: its meaning as the system text states it and the dictionary entries it cites, as
     * {@code BLOCK.Name} (the validity conditions are checked by the response checker, W4-5).
     */
    public record ReasonCode(String code, Group group, String meaning, List<String> citedFacts) {

        public ReasonCode {
            citedFacts = List.copyOf(citedFacts);
        }
    }

    /** One reason the model gave: a code of this contract and the ID of the prompt fact it cites. */
    public record Citation(String code, String fact) {
    }

    /** Dictionary 5: 53 codes since R4-T took the trusted signal and its code out. */
    public static final List<ReasonCode> REASON_CODES = List.of(
            code(Group.MINIMUM_ACTION, "MIN_P1_IDENTITY_DEVIATION",
                    "on a sensitive resource, two or more identity dimensions differ from usual without explanation",
                    List.of("DECISION_FACTS.DeviationsFromBaseline")),
            code(Group.MINIMUM_ACTION, "MIN_P2_NEW_DEVICE_OR_NETWORK_EXPORT",
                    "an export of a sensitive resource from a device or network that differs from usual without explanation",
                    List.of("DECISION_FACTS.DeviationsFromBaseline")),
            code(Group.MINIMUM_ACTION, "MIN_P3_POLICY_NOT_SATISFIED",
                    "no valid record covers what the company policy requires",
                    List.of("DECISION_FACTS.PolicySatisfied")),
            code(Group.POLICY, "POLICY_SATISFIED",
                    "a valid record covers what the company policy requires",
                    List.of("DECISION_FACTS.PolicySatisfied")),
            code(Group.POLICY, "POLICY_UNKNOWN",
                    "no integration gives the policy facts, or none came this time",
                    List.of("DECISION_FACTS.Policy")),
            code(Group.POLICY, "POLICY_NOT_SATISFIED_NO_RECORD",
                    "no record covers the work",
                    List.of("DECISION_FACTS.PolicySatisfied")),
            code(Group.POLICY, "POLICY_NOT_SATISFIED_LATE",
                    "the record was decided after the request",
                    List.of("DECISION_FACTS.PolicySatisfied")),
            code(Group.POLICY, "POLICY_NOT_SATISFIED_EXPIRED",
                    "the request is outside the record's period",
                    List.of("DECISION_FACTS.PolicySatisfied")),
            code(Group.POLICY, "POLICY_NOT_SATISFIED_OTHER_TARGET",
                    "the record covers another target",
                    List.of("DECISION_FACTS.PolicySatisfied")),
            code(Group.POLICY, "POLICY_NOT_SATISFIED_OVER_LIMIT",
                    "this request exceeds the limit",
                    List.of("DECISION_FACTS.PolicySatisfied")),
            code(Group.POLICY, "POLICY_NOT_SATISFIED_CUMULATIVE",
                    "the cumulative use exceeds the limit",
                    List.of("DECISION_FACTS.PolicySatisfied")),
            code(Group.POLICY, "POLICY_NOT_SATISFIED_TICKET_WITHOUT_ON_CALL",
                    "the ticket-while-on-call exception applies but the requester is not on call",
                    List.of("DECISION_FACTS.PolicySatisfied")),
            code(Group.BUSINESS_RECORDS, "APPROVAL_COVERS",
                    "a valid approval covers this work",
                    List.of("DECISION_FACTS.Approval")),
            code(Group.BUSINESS_RECORDS, "TICKET_COVERS",
                    "a valid ticket covers this work",
                    List.of("DECISION_FACTS.Ticket")),
            code(Group.BUSINESS_RECORDS, "TICKET_CLAIM_FALSE",
                    "the ticket the request claims does not exist",
                    List.of("DECISION_FACTS.Ticket")),
            code(Group.BUSINESS_RECORDS, "ASSIGNED_TARGET",
                    "the requester is assigned to the target",
                    List.of("DECISION_FACTS.Assignment")),
            code(Group.BUSINESS_RECORDS, "ON_CALL",
                    "the requester is on call at the request time",
                    List.of("DECISION_FACTS.OnCall")),
            code(Group.BUSINESS_RECORDS, "TRAVEL_EXPLAINS_NETWORK",
                    "a travel record explains the network difference",
                    List.of("DECISION_FACTS.Travel")),
            code(Group.BUSINESS_RECORDS, "BREAK_GLASS",
                    "an emergency access is declared",
                    List.of("DECISION_FACTS.BreakGlass")),
            code(Group.DEVIATION, "DEVIATION_TIME",
                    "the time differs from usual",
                    List.of("DECISION_FACTS.DeviationsFromBaseline")),
            code(Group.DEVIATION, "DEVIATION_DAY",
                    "the day differs from usual",
                    List.of("DECISION_FACTS.DeviationsFromBaseline")),
            code(Group.DEVIATION, "DEVIATION_NETWORK",
                    "the network differs from usual",
                    List.of("DECISION_FACTS.DeviationsFromBaseline")),
            code(Group.DEVIATION, "DEVIATION_DEVICE",
                    "the device differs from usual",
                    List.of("DECISION_FACTS.DeviationsFromBaseline")),
            code(Group.DEVIATION, "DEVIATION_LOGIN_METHOD",
                    "the login method differs from usual",
                    List.of("DECISION_FACTS.DeviationsFromBaseline")),
            code(Group.DEVIATION, "DEVIATION_TARGET",
                    "the target differs from usual",
                    List.of("DECISION_FACTS.DeviationsFromBaseline")),
            code(Group.DEVIATION, "DEVIATION_ACTION",
                    "the action differs from usual",
                    List.of("DECISION_FACTS.DeviationsFromBaseline")),
            code(Group.DEVIATION, "DEVIATION_RESOURCE_CLASS",
                    "the resource class differs from usual",
                    List.of("DECISION_FACTS.DeviationsFromBaseline")),
            code(Group.DEVIATION, "DEVIATION_SIZE",
                    "the size differs from usual",
                    List.of("DECISION_FACTS.DeviationsFromBaseline")),
            code(Group.DEVIATION, "DEVIATION_RATE",
                    "the request rate differs from usual",
                    List.of("DECISION_FACTS.DeviationsFromBaseline")),
            code(Group.DEVIATION, "DEVIATION_MOVEMENT",
                    "an impossible or unusual movement",
                    List.of("DECISION_FACTS.Movement")),
            code(Group.DEVIATION, "SESSION_DEVICE_CHANGE",
                    "the device changed within the session",
                    List.of("DECISION_FACTS.SessionDeviceChange")),
            code(Group.DEVIATION, "SESSION_NETWORK_CHANGE",
                    "the network address changed within the session",
                    List.of("DECISION_FACTS.SessionNetworkChange")),
            code(Group.AS_USUAL, "BASELINE_MATCH",
                    "the compared dimensions are as usual",
                    List.of("DECISION_FACTS.SameAsBaseline")),
            code(Group.AS_USUAL, "BASELINE_NOT_ESTABLISHED",
                    "the personal baseline is not established, so comparison is limited",
                    List.of("USER_BASELINE.BaselineStatus")),
            code(Group.SCOPE_AND_PERMISSIONS, "ROLE_SCOPE_OUTSIDE",
                    "the action or category is outside the scope group's 30-day facts",
                    List.of("DECISION_FACTS.RoleScope")),
            code(Group.SCOPE_AND_PERMISSIONS, "RECENT_PERMISSION_CHANGE",
                    "a recent permission change",
                    List.of("DECISION_FACTS.RecentPermissionChanges")),
            code(Group.SCOPE_AND_PERMISSIONS, "TEMPORARY_ELEVATION",
                    "a temporary elevation is active",
                    List.of("DECISION_FACTS.TemporaryElevation")),
            code(Group.DELEGATION, "DELEGATION_SCOPE_DRIFT",
                    "the delegated run leaves the allowed objective, operations or resources",
                    List.of("DECISION_FACTS.Delegation")),
            code(Group.SESSION, "REPEAT_IN_SESSION",
                    "the same action repeats in the session (a repeat alone is no reason for a stronger action)",
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
            code(Group.PAST_RECORDS, "PAST_RECORD_SAME_TARGET",
                    "an earlier allowed record on the same target",
                    List.of("PAST_RECORDS.PastRecord{i}")),
            code(Group.PAST_RECORDS, "PAST_DENIED_SAME_ACTION",
                    "a recent non-allow decision or refusal of the same action",
                    List.of("PAST_RECORDS.PastDeniedDecision{i}", "SESSION.RecentDenied")),
            code(Group.PAST_RECORDS, "VALIDATED_CASE_MATCH",
                    "a validated case matches",
                    List.of("PAST_RECORDS.ValidatedCases")),
            code(Group.BLOCK_GROUNDS, "CLIENT_SIGNAL_TAMPERING",
                    "a measured client tampering signal",
                    List.of("DECISION_FACTS.ClientSignals")),
            code(Group.BLOCK_GROUNDS, "TENANT_CONFLICT",
                    "a tenant conflict",
                    List.of("DECISION_FACTS.DataConflicts")),
            code(Group.BLOCK_GROUNDS, "AUTHORIZATION_CONFLICT",
                    "an authorization conflict",
                    List.of("DECISION_FACTS.DataConflicts", "DECISION_FACTS.AuthorizationEffect")),
            code(Group.BLOCK_GROUNDS, "DATA_CONFLICT",
                    "a data conflict",
                    List.of("DECISION_FACTS.DataConflicts")),
            code(Group.BLOCK_GROUNDS, "THREAT_MATCH",
                    "a match with threat knowledge",
                    List.of("DECISION_FACTS.ThreatMatch")),
            code(Group.ESCALATION, "MATERIAL_CONTRADICTION",
                    "facts that decide the action contradict each other",
                    List.of("DECISION_FACTS.DataConflicts")),
            code(Group.ESCALATION, "MATERIAL_MISSING_EVIDENCE",
                    "a fact that decides the action is missing",
                    List.of("UNKNOWN.Unknown")));

    private static final List<String> CODES = REASON_CODES.stream().map(ReasonCode::code).toList();
    private static final String PROVIDER_SCHEMA = writeProviderSchema(true);
    private static final String TEXT_SCHEMA = writeProviderSchema(false);
    private static final String OUTPUT_BLOCK = writeOutputBlock();

    private SecurityDecisionOutputContract() {
    }

    public static List<String> codes() {
        return CODES;
    }

    /**
     * The strict JSON schema of dictionary 4 for a provider with structured output: every field required, no other
     * keys, the audit fields nullable. Only keywords strict structured output supports (P4-CHANGE-2).
     */
    public static String providerSchema() {
        return PROVIDER_SCHEMA;
    }

    /**
     * The output block of the v20 system text (dictionary 1.1 block 2, W4-2): the fields, how a code cites a fact and
     * the meaning of every code. The same text whether or not the provider enforces the schema.
     */
    /**
     * The output contract v3 schema as text for a provider without structured output (dictionary 4): the provider
     * schema without the code meanings, which the output block of the system prompt states.
     */
    public static String textSchema() {
        return TEXT_SCHEMA;
    }

    public static String systemOutputBlock() {
        return OUTPUT_BLOCK;
    }

    private static String writeOutputBlock() {
        StringBuilder block = new StringBuilder();
        block.append("=== OUTPUT ===\n\n");
        block.append("Return one JSON object with exactly these keys: action, reasonCodes, reason, riskScore, confidence, mitre.\n");
        block.append("action: ALLOW, CHALLENGE, ESCALATE or BLOCK.\n");
        block.append("reasonCodes: ").append(MIN_REASON_CODES).append(" to ").append(MAX_REASON_CODES)
                .append(" objects {\"code\": ..., \"fact\": ...}, the facts that decide the action first. code is one of"
                        + " the codes below; fact is the ID at the start of the line the code cites (F1, B2, S3, R1, P1)."
                        + " MATERIAL_MISSING_EVIDENCE cites the ID the UNKNOWN line gives the missing fact (U1).\n");
        block.append("reason: one sentence of at most 30 words that states, in your own words, the facts behind the codes.\n");
        block.append("riskScore and confidence: numbers from 0 to 1, or null. mitre: a list of MITRE ATT&CK technique IDs,"
                + " or null. These three are kept for audit and decide nothing.\n");
        block.append("Reason codes (code: meaning; the line it cites):\n");
        for (ReasonCode code : REASON_CODES) {
            block.append("- ").append(code.code()).append(": ").append(code.meaning()).append("; ")
                    .append(String.join(", ", code.citedFacts().stream()
                            .map(fact -> fact.substring(fact.indexOf('.') + 1).replace("{i}", "")).toList()))
                    .append('\n');
        }
        return block.toString();
    }

    private static ReasonCode code(Group group, String code, String meaning, List<String> citedFacts) {
        return new ReasonCode(code, group, meaning, citedFacts);
    }

    /** The output contract v3 schema; with structured output the code enum carries every code's meaning (dictionary 5). */
    private static String writeProviderSchema(boolean withCodeMeanings) {
        Map<String, Object> fact = new LinkedHashMap<>();
        fact.put("type", "string");
        fact.put("pattern", FACT_ID_PATTERN);
        Map<String, Object> code = new LinkedHashMap<>();
        code.put("type", "string");
        code.put("enum", CODES);
        if (withCodeMeanings) {
            code.put("description", REASON_CODES.stream().map(reason -> reason.code() + ": " + reason.meaning())
                    .collect(Collectors.joining("\n")));
        }
        Map<String, Object> itemProperties = new LinkedHashMap<>();
        itemProperties.put("code", code);
        itemProperties.put("fact", fact);
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
        // An ordered map: the schema text is the same on every run (a Map.of iterates in a per-JVM order).
        Map<String, Object> action = new LinkedHashMap<>();
        action.put("type", "string");
        action.put("enum", ACTIONS);
        properties.put("action", action);
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
            throw new IllegalStateException("The output contract schema cannot be written", e);
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
