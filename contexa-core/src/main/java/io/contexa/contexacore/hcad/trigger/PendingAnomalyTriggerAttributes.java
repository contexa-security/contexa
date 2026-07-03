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
package io.contexa.contexacore.hcad.trigger;

public final class PendingAnomalyTriggerAttributes {

    public static final String PRE_TRIGGERED = "ctxa.pretrigger.triggered";
    public static final String PRE_TRIGGER_REQUEST_ID = "ctxa.pretrigger.requestId";
    public static final String PRE_TRIGGER_RISK_SIGNATURE = "ctxa.pretrigger.riskSignature";
    public static final String PRE_TRIGGER_STATE_KEY = "ctxa.pretrigger.stateKey";
    public static final String PRE_TRIGGER_EVALUATION_ID = "ctxa.pretrigger.evaluationId";
    public static final String PRE_TRIGGER_MERGE_EVALUATION_ID = "ctxa.pretrigger.mergeEvaluationId";
    public static final String PRE_TRIGGER_DUPLICATE_SUPPRESSED = "ctxa.pretrigger.duplicateSuppressed";
    public static final String PRE_TRIGGER_NEGATIVE_CACHE_HIT = "ctxa.pretrigger.negativeCacheHit";
    public static final String PRE_TRIGGER_MODE = "ctxa.pretrigger.hcadMode";
    public static final String PRE_TRIGGER_DECISION_BOUNDARY_MODE = "ctxa.pretrigger.decisionBoundaryMode";
    public static final String PRE_TRIGGER_EARLY_ANALYSIS_SCORE = "ctxa.pretrigger.earlyAnalysisScore";
    public static final String PRE_TRIGGER_BAND = "ctxa.pretrigger.band";
    public static final String PRE_TRIGGER_EVALUATED = "ctxa.pretrigger.evaluated";
    public static final String PRE_TRIGGER_ESCALATION_EVALUATION = "ctxa.pretrigger.escalationEvaluation";
    public static final String PROTECTABLE_TRIGGER_STARTED = "ctxa.protectable.trigger.started";
    public static final String PROTECTABLE_TRIGGER_SUPPRESSED = "ctxa.protectable.trigger.suppressed";
    public static final String PROTECTABLE_OBSERVED = "ctxa.protectable.observed";
    public static final String PROTECTABLE_RESOURCE_ID = "ctxa.protectable.resourceId";
    public static final String PROTECTABLE_RESOURCE_URL = "ctxa.protectable.resourceUrl";
    public static final String PROTECTABLE_HTTP_METHOD = "ctxa.protectable.httpMethod";
    public static final String PROTECTABLE_LLM_REUSED = "ctxa.protectable.llmReused";

    private PendingAnomalyTriggerAttributes() {
    }
}
