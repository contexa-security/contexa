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
package io.contexa.contexacore.autonomous.access;

import io.contexa.contexacommon.enums.ZeroTrustAction;
import org.springframework.lang.Nullable;

/**
 * docs/agent B4: Contexa's answer to one access evaluation.
 *
 * @param decision     whether the request may go on: only an enforced ALLOW, or any decision while Contexa does not
 *                     enforce (report-only or disabled)
 * @param action       Contexa's decision, or null when nothing was decided (analysis off, or the evaluation is invalid)
 * @param riskScore    the decision's risk score, or null
 * @param reason       the decision's reasoning summary, for the administrator, or null
 * @param requestId    the request ID of the decision record, or null
 * @param enforced     whether Contexa enforces its decisions now
 * @param errorStatus  the HTTP status of an invalid evaluation, or null
 * @param errorMessage what is wrong with an invalid evaluation, or null
 */
public record AccessEvaluation(boolean decision, @Nullable ZeroTrustAction action, @Nullable Double riskScore,
                               @Nullable String reason, @Nullable String requestId, boolean enforced,
                               @Nullable Integer errorStatus, @Nullable String errorMessage) {

    /** An evaluation that could not be made; closed, as AuthZEN defaults a decision. */
    public static AccessEvaluation invalid(int status, String message) {
        return new AccessEvaluation(false, null, null, null, null, false, status, message);
    }

    public boolean failed() {
        return errorStatus != null;
    }
}
