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
package io.contexa.contexaiam.security.xacml.pep;

import org.springframework.expression.EvaluationException;

/**
 * Tells a policy condition that cannot be evaluated (an unknown function, a method on a missing value) from any other
 * failure of a decision. Such a condition decides nothing, so the request it covers is denied instead of failing with a
 * server error; any other failure, as a Zero Trust challenge raised on purpose, is left as it is.
 */
final class PolicyConditionFailure {

    private PolicyConditionFailure() {
    }

    /** Whether the failure is the evaluation of a condition expression, directly or wrapped by Spring Security. */
    static boolean isConditionFailure(Throwable failure) {
        for (Throwable cause = failure; cause != null; cause = cause.getCause()) {
            if (cause instanceof EvaluationException) {
                return true;
            }
            if (cause.getCause() == cause) {
                return false;
            }
        }
        return false;
    }
}
