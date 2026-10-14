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
package io.contexa.contexacore.autonomous.context.policy;

import java.util.List;

/**
 * The instructions the context producers write with their facts: the clause after a fact ({@code "<fact>; <clause>."})
 * and the notes written as sentences of their own. The v19 sections draw them as written. The v20 fact lines draw the
 * facts only: the v20 system text states the evidence rules these clauses repeat, and the notes say how to use a
 * profile or a seed, not what it holds.
 */
public final class ContextEvidenceGuidance {

    // Trust profile warnings: the clause after the fact.
    public static final String PATTERN_CLAIMS_PROVISIONAL =
            "treat pattern claims as provisional until more allowed observations accumulate";
    public static final String NOT_AN_INTENT_INDICATOR = "do not treat it as a standalone indicator of user intent";
    public static final String EXPECTED_SCOPE_PROVISIONAL =
            "treat expected scope as provisional until more authorized observations accumulate";
    public static final String CONFIRM_INTENT_WITH_LINEAGE = "confirm intent with approval lineage or delegated objective";
    public static final String NOT_A_REASONING_ANCHOR = "do not use it as a standalone reasoning anchor";

    // Trust profile notes and scope limitations: sentences of their own.
    public static final String WORK_PROFILE_NOTE = "This profile describes enacted post-auth access behavior, not approved "
            + "business intent, approval lineage, or delegated objective.";
    public static final String ROLE_SCOPE_NOTE = "This profile describes enacted or denied authorization scope after "
            + "authentication, not the full tenant policy graph or business objective by itself.";
    public static final String WORK_PROFILE_USE = "Use this profile to understand enacted work patterns after authorization, "
            + "not to infer business objective by itself.";
    public static final String WORK_PROFILE_PURPOSE_SOURCES = "Approval lineage, delegated intent, and human purpose require "
            + "friction, delegation, or enterprise memory context.";
    public static final String ROLE_SCOPE_USE = "Use this profile to understand role-scoped reach and recent permission-change "
            + "evidence after authorization, not to infer human purpose by itself.";
    public static final String ROLE_SCOPE_PURPOSE_SOURCES = "Approval lineage, delegated objective, and business intent still "
            + "require friction, delegation, or enterprise memory context.";

    // Coverage warnings: the clause after the fact that the v20 system text's evidence rules state.
    public static final String ACTOR_REASONING_CONSERVATIVE = "continuity and user-specific reasoning should remain conservative";
    public static final String PRIVILEGE_CONSERVATIVE = "privilege conclusions should remain conservative";
    public static final String NO_PERMISSIONS_BEYOND_EFFECT =
            "do not infer permissions beyond the current request authorization effect";
    public static final String PRIVILEGE_AND_SCOPE_CONSERVATIVE = "privilege and scope conclusions should remain conservative";
    public static final String CLIENT_ANOMALY_CONSERVATIVE = "client anomaly reasoning should remain conservative";
    public static final String NOT_A_PROOF_OF_NORMAL_BEHAVIOR = "do not treat it as a standalone proof of normal behavior";
    public static final String WORK_PATTERN_CONSERVATIVE = "keep work-pattern conclusions conservative";
    public static final String NO_CLAIM_OF_NORMAL_PATTERNS =
            "do not claim the current request matches long-term normal work patterns";
    public static final String BUSINESS_SCOPE_CONSERVATIVE = "keep business-scope conclusions conservative";
    public static final String NOT_A_PROOF_OF_BUSINESS_SCOPE =
            "do not treat it as a standalone proof of authorized business scope";
    public static final String ROLE_SCOPE_CONSERVATIVE = "keep role-scope conclusions conservative";
    public static final String COHORT_DEVIATION_CONSERVATIVE = "cohort-based deviation claims should remain conservative";
    public static final String NO_ASSUMED_FRICTION_PRECEDENT =
            "do not assume prior approval, challenge, or denial precedent exists";
    public static final String NO_ASSUMED_VALIDATED_CASES =
            "avoid assuming prior validated cases or XAI-backed precedents exist";
    public static final String DELEGATED_INTENT_CONSERVATIVE = "delegated-agent intent should remain conservative";
    public static final String DELEGATED_ALLOW_CONSERVATIVE = "delegated-agent ALLOW conclusions should remain conservative";

    // Delegation unknowns: the clause after the unknown.
    public static final String NO_INFERRED_OBJECTIVE_FAMILY = "do not infer objective family";
    public static final String NO_INFERRED_OBJECTIVE_SUMMARY = "do not infer objective summary";
    public static final String NO_INFERRED_BUSINESS_INTENT = "do not infer business intent";

    // Cohort seed: sentences of their own.
    public static final String SEED_IS_SHARED_CONTEXT = "This cohort seed is shared industry or region context.";
    public static final String SEED_DOES_NOT_OVERRIDE =
            "Do NOT override established personal or organization baseline with this seed.";
    public static final String ORGANIZATION_BASELINE_FIRST = "Tenant organization baseline should be used before this seed.";
    public static final String SEED_FOR_MISSING_DIMENSIONS = "Use the seed only for missing dimensions.";
    public static final String SEED_AS_COLD_START_SUPPORT = "Use this seed as low-priority cold-start support only.";

    private static final List<String> CLAUSES = List.of(PATTERN_CLAIMS_PROVISIONAL, NOT_AN_INTENT_INDICATOR,
            EXPECTED_SCOPE_PROVISIONAL, CONFIRM_INTENT_WITH_LINEAGE, NOT_A_REASONING_ANCHOR, ACTOR_REASONING_CONSERVATIVE,
            PRIVILEGE_CONSERVATIVE, NO_PERMISSIONS_BEYOND_EFFECT, PRIVILEGE_AND_SCOPE_CONSERVATIVE,
            CLIENT_ANOMALY_CONSERVATIVE, NOT_A_PROOF_OF_NORMAL_BEHAVIOR, WORK_PATTERN_CONSERVATIVE,
            NO_CLAIM_OF_NORMAL_PATTERNS, BUSINESS_SCOPE_CONSERVATIVE, NOT_A_PROOF_OF_BUSINESS_SCOPE, ROLE_SCOPE_CONSERVATIVE,
            COHORT_DEVIATION_CONSERVATIVE, NO_ASSUMED_FRICTION_PRECEDENT, NO_ASSUMED_VALIDATED_CASES,
            DELEGATED_INTENT_CONSERVATIVE, DELEGATED_ALLOW_CONSERVATIVE, NO_INFERRED_OBJECTIVE_FAMILY,
            NO_INFERRED_OBJECTIVE_SUMMARY, NO_INFERRED_BUSINESS_INTENT);

    private static final List<String> NOTES = List.of(WORK_PROFILE_NOTE, ROLE_SCOPE_NOTE, WORK_PROFILE_USE,
            WORK_PROFILE_PURPOSE_SOURCES, ROLE_SCOPE_USE, ROLE_SCOPE_PURPOSE_SOURCES, SEED_IS_SHARED_CONTEXT,
            SEED_DOES_NOT_OVERRIDE, ORGANIZATION_BASELINE_FIRST, SEED_FOR_MISSING_DIMENSIONS, SEED_AS_COLD_START_SUPPORT);

    private ContextEvidenceGuidance() {
    }

    /**
     * The text with its facts only: the notes are left out and a clause after a fact is cut back to the fact with its
     * full stop. Null when nothing but instructions is left, a label whose text was a note included
     * ({@code "Scope limitation: <note>"}). A text without them is returned trimmed.
     */
    public static String factsOf(String text) {
        if (text == null) {
            return null;
        }
        String facts = text.trim();
        for (String note : NOTES) {
            facts = facts.replace(note, "");
        }
        facts = facts.trim().replaceAll(" {2,}", " ");
        for (String clause : CLAUSES) {
            String tail = "; " + clause + ".";
            if (facts.endsWith(tail)) {
                facts = facts.substring(0, facts.length() - tail.length()) + ".";
                break;
            }
        }
        return facts.isEmpty() || facts.endsWith(":") ? null : facts;
    }
}
