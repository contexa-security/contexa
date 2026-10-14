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
package io.contexa.contexacore.verification.inspection;

import java.util.Objects;

/**
 * One item of a sealed prompt that an inspection points at: which check, the block, entry and fact id of the line,
 * the line number in the user prompt, what was expected and what the prompt says, the sealed source compared with,
 * and why.
 *
 * @param checkCode  the check that found it
 * @param outcome    a mismatch or an item that could not be checked
 * @param block      the block title, or null when the item is not in a block
 * @param entry      the line label, or null when the item is not a line
 * @param factId     the fact id the line carries, or null
 * @param lineNumber the 1-based line number in the user prompt, or null when the item is the whole prompt
 * @param expected   what the line should say (a value, a form or a rule)
 * @param actual     what the line says
 * @param sourceRef  the sealed source the expected value comes from, or null when it comes from the dictionary
 * @param reason     why the item is a finding
 */
public record PromptInspectionFinding(
        String checkCode,
        PromptInspectionOutcome outcome,
        String block,
        String entry,
        String factId,
        Integer lineNumber,
        String expected,
        String actual,
        String sourceRef,
        String reason) {

    public PromptInspectionFinding {
        Objects.requireNonNull(checkCode, "checkCode");
        Objects.requireNonNull(outcome, "outcome");
    }

    public static Builder builder(String checkCode, PromptInspectionOutcome outcome) {
        return new Builder(checkCode, outcome);
    }

    /** Builds a finding field by field. */
    public static final class Builder {

        private final String checkCode;
        private final PromptInspectionOutcome outcome;
        private String block;
        private String entry;
        private String factId;
        private Integer lineNumber;
        private String expected;
        private String actual;
        private String sourceRef;
        private String reason;

        private Builder(String checkCode, PromptInspectionOutcome outcome) {
            this.checkCode = checkCode;
            this.outcome = outcome;
        }

        public Builder block(String block) {
            this.block = block;
            return this;
        }

        public Builder entry(String entry) {
            this.entry = entry;
            return this;
        }

        public Builder factId(String factId) {
            this.factId = factId;
            return this;
        }

        public Builder lineNumber(Integer lineNumber) {
            this.lineNumber = lineNumber;
            return this;
        }

        public Builder expected(String expected) {
            this.expected = expected;
            return this;
        }

        public Builder actual(String actual) {
            this.actual = actual;
            return this;
        }

        public Builder sourceRef(String sourceRef) {
            this.sourceRef = sourceRef;
            return this;
        }

        public Builder reason(String reason) {
            this.reason = reason;
            return this;
        }

        public PromptInspectionFinding build() {
            return new PromptInspectionFinding(checkCode, outcome, block, entry, factId, lineNumber, expected, actual,
                    sourceRef, reason);
        }
    }
}
