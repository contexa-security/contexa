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
package io.contexa.contexacore.std.components.prompt;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

public final class SecurityPromptSectionCatalog {

    public static final String SYSTEM_INSTRUCTION = "SYSTEM_INSTRUCTION";
    public static final String DECISION_CONTRACT = "DECISION_CONTRACT";
    public static final String CURRENT_REQUEST_AND_EVENT = "CURRENT_REQUEST_AND_EVENT";
    public static final String BRIDGE_AND_COVERAGE = "BRIDGE_AND_COVERAGE";
    public static final String IDENTITY_AND_ROLE = "IDENTITY_AND_ROLE";
    public static final String DEVICE_CONTEXT = "DEVICE_CONTEXT";
    public static final String LOCATION_CONTEXT = "LOCATION_CONTEXT";
    public static final String INTENT_SIGNAL_CONTEXT = "INTENT_SIGNAL_CONTEXT";
    public static final String RESOURCE_AND_ACTION = "RESOURCE_AND_ACTION";
    public static final String SESSION_NARRATIVE = "SESSION_NARRATIVE";
    public static final String OBSERVED_AND_PERSONAL_WORK_PATTERN = "OBSERVED_AND_PERSONAL_WORK_PATTERN";
    public static final String RAG_EVIDENCE_CONTEXT = "RAG_EVIDENCE_CONTEXT";
    public static final String SUPPORTING_LEARNING_CONTEXT = "SUPPORTING_LEARNING_CONTEXT";
    public static final String ROLE_SCOPE = "ROLE_SCOPE";
    public static final String FRICTION_AND_APPROVAL = "FRICTION_AND_APPROVAL";
    public static final String DELEGATED_OBJECTIVE = "DELEGATED_OBJECTIVE";
    public static final String THREAT_LEARNING_AND_MEMORY = "THREAT_LEARNING_AND_MEMORY";
    public static final String EXPLICIT_MISSING_KNOWLEDGE = "EXPLICIT_MISSING_KNOWLEDGE";

    public static final String HEADER_CURRENT_REQUEST_AND_EVENT = "=== CURRENT REQUEST AND EVENT ===";
    public static final String HEADER_BRIDGE_RESOLUTION_CONTEXT = "=== BRIDGE RESOLUTION CONTEXT ===";
    public static final String HEADER_CONTEXT_COVERAGE = "=== CONTEXT COVERAGE ===";
    public static final String HEADER_IDENTITY_AND_ROLE_CONTEXT = "=== IDENTITY AND ROLE CONTEXT ===";
    public static final String HEADER_AUTHENTICATION_AND_ASSURANCE_CONTEXT = "=== AUTHENTICATION AND ASSURANCE CONTEXT ===";
    public static final String HEADER_DEVICE_CONTEXT = "=== DEVICE CONTEXT ===";
    public static final String HEADER_LOCATION_CONTEXT = "=== LOCATION CONTEXT ===";
    public static final String HEADER_REQUEST_INTENT_SIGNAL_CONTEXT = "=== REQUEST INTENT SIGNAL CONTEXT ===";
    public static final String HEADER_RESOURCE_AND_ACTION_CONTEXT = "=== RESOURCE AND ACTION CONTEXT ===";
    public static final String HEADER_SESSION_NARRATIVE_CONTEXT = "=== SESSION NARRATIVE CONTEXT ===";
    public static final String HEADER_OBSERVED_WORK_PATTERN_CONTEXT = "=== OBSERVED WORK PATTERN CONTEXT ===";
    public static final String HEADER_PERSONAL_WORK_PROFILE = "=== PERSONAL WORK PROFILE ===";
    public static final String HEADER_RAG_EVIDENCE_CONTEXT = "=== RAG EVIDENCE ===";
    public static final String HEADER_SUPPORTING_LEARNING_CONTEXT = "=== SUPPORTING LEARNING CONTEXT ===";
    public static final String HEADER_ROLE_AND_WORK_SCOPE_CONTEXT = "=== ROLE AND WORK SCOPE CONTEXT ===";
    public static final String HEADER_PEER_COHORT_DELTA = "=== PEER COHORT DELTA ===";
    public static final String HEADER_FRICTION_AND_APPROVAL_HISTORY = "=== FRICTION AND APPROVAL HISTORY ===";
    public static final String HEADER_DELEGATED_OBJECTIVE_CONTEXT = "=== DELEGATED OBJECTIVE CONTEXT ===";
    public static final String HEADER_OUTCOME_AND_REASONING_MEMORY = "=== OUTCOME AND REASONING MEMORY ===";
    public static final String HEADER_EXPLICIT_MISSING_KNOWLEDGE = "=== EXPLICIT MISSING KNOWLEDGE ===";

    private static final Map<String, List<String>> SECTION_HEADERS;

    static {
        Map<String, List<String>> headers = new LinkedHashMap<>();
        headers.put(SYSTEM_INSTRUCTION, List.of("You are a Zero Trust security analyst AI."));
        headers.put(DECISION_CONTRACT, List.of("=== DECISION ===", "<output_format>"));
        headers.put(CURRENT_REQUEST_AND_EVENT, List.of(HEADER_CURRENT_REQUEST_AND_EVENT));
        headers.put(BRIDGE_AND_COVERAGE, List.of(HEADER_BRIDGE_RESOLUTION_CONTEXT, HEADER_CONTEXT_COVERAGE));
        headers.put(IDENTITY_AND_ROLE, List.of(HEADER_IDENTITY_AND_ROLE_CONTEXT, HEADER_AUTHENTICATION_AND_ASSURANCE_CONTEXT));
        headers.put(DEVICE_CONTEXT, List.of(HEADER_DEVICE_CONTEXT));
        headers.put(LOCATION_CONTEXT, List.of(HEADER_LOCATION_CONTEXT));
        headers.put(INTENT_SIGNAL_CONTEXT, List.of(HEADER_REQUEST_INTENT_SIGNAL_CONTEXT));
        headers.put(RESOURCE_AND_ACTION, List.of(HEADER_RESOURCE_AND_ACTION_CONTEXT));
        headers.put(SESSION_NARRATIVE, List.of(HEADER_SESSION_NARRATIVE_CONTEXT));
        headers.put(OBSERVED_AND_PERSONAL_WORK_PATTERN, List.of(HEADER_OBSERVED_WORK_PATTERN_CONTEXT, HEADER_PERSONAL_WORK_PROFILE));
        headers.put(RAG_EVIDENCE_CONTEXT, List.of(HEADER_RAG_EVIDENCE_CONTEXT));
        headers.put(SUPPORTING_LEARNING_CONTEXT, List.of(HEADER_SUPPORTING_LEARNING_CONTEXT));
        headers.put(ROLE_SCOPE, List.of(HEADER_ROLE_AND_WORK_SCOPE_CONTEXT, HEADER_PEER_COHORT_DELTA));
        headers.put(FRICTION_AND_APPROVAL, List.of(HEADER_FRICTION_AND_APPROVAL_HISTORY));
        headers.put(DELEGATED_OBJECTIVE, List.of(HEADER_DELEGATED_OBJECTIVE_CONTEXT));
        headers.put(THREAT_LEARNING_AND_MEMORY, List.of(HEADER_OUTCOME_AND_REASONING_MEMORY));
        headers.put(EXPLICIT_MISSING_KNOWLEDGE, List.of(HEADER_EXPLICIT_MISSING_KNOWLEDGE));
        SECTION_HEADERS = Map.copyOf(headers);
    }

    private SecurityPromptSectionCatalog() {
    }

    public static List<String> headersFor(String sectionKey) {
        return SECTION_HEADERS.getOrDefault(sectionKey, List.of());
    }
}
