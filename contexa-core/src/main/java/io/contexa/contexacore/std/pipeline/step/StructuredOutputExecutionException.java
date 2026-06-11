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
package io.contexa.contexacore.std.pipeline.step;

public class StructuredOutputExecutionException extends IllegalStateException {

    private final StructuredOutputFailureCategory category;
    private final DecisionExecutionFailure failure;

    public StructuredOutputExecutionException(StructuredOutputFailureCategory category, String message) {
        super(message);
        this.category = category;
        this.failure = new DecisionExecutionFailure(category.toDecisionFailureCategory(), message, null);
    }

    public StructuredOutputExecutionException(StructuredOutputFailureCategory category, String message, Throwable cause) {
        super(message, cause);
        this.category = category;
        this.failure = new DecisionExecutionFailure(category.toDecisionFailureCategory(), message, null);
    }

    public StructuredOutputExecutionException(StructuredOutputFailureCategory category, DecisionExecutionFailure failure) {
        super(failure != null ? failure.message() : null);
        this.category = category;
        this.failure = failure != null
                ? failure
                : new DecisionExecutionFailure(category.toDecisionFailureCategory(), "", null);
    }

    public StructuredOutputExecutionException(StructuredOutputFailureCategory category, DecisionExecutionFailure failure, Throwable cause) {
        super(failure != null ? failure.message() : null, cause);
        this.category = category;
        this.failure = failure != null
                ? failure
                : new DecisionExecutionFailure(category.toDecisionFailureCategory(), "", null);
    }

    public StructuredOutputFailureCategory getCategory() {
        return category;
    }

    public DecisionExecutionFailure getFailure() {
        return failure;
    }
}
