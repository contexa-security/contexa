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
package io.contexa.contexaiam.security.xacml.pdp.evaluation;

/**
 * Raised when a policy condition expression cannot be parsed or uses a construct that is not
 * permitted in policy expressions.
 */
public class UnsafePolicyExpressionException extends IllegalArgumentException {

    private final String expression;
    private final String reason;
    private final boolean parseFailure;

    public UnsafePolicyExpressionException(String expression, String reason, boolean parseFailure) {
        super("Policy expression rejected: " + reason);
        this.expression = expression;
        this.reason = reason;
        this.parseFailure = parseFailure;
    }

    public String getExpression() {
        return expression;
    }

    public String getReason() {
        return reason;
    }

    public boolean isParseFailure() {
        return parseFailure;
    }

    /**
     * Message key describing the rejection for admin-facing error messages.
     */
    public String getMessageKey() {
        return parseFailure ? "msg.policy.spel.invalid" : "msg.policy.spel.dangerous";
    }
}
