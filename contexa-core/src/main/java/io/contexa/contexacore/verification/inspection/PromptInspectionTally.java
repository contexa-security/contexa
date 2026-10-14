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

import java.util.ArrayList;
import java.util.List;
import java.util.Objects;

/**
 * The count of one check over one sealed prompt. A check records each item it looks at once: as matching, as a
 * mismatch with its finding, or as an item it could not check with its finding.
 */
public final class PromptInspectionTally {

    private final String checkCode;
    private final PromptInspectionSubject subject;
    private final List<PromptInspectionFinding> findings = new ArrayList<>();
    private final List<Integer> matchedLines = new ArrayList<>();
    private int matched;
    private int mismatched;
    private int unverifiable;

    PromptInspectionTally(String checkCode, PromptInspectionSubject subject) {
        this.checkCode = Objects.requireNonNull(checkCode, "checkCode");
        this.subject = Objects.requireNonNull(subject, "subject");
    }

    public String checkCode() {
        return checkCode;
    }

    public PromptInspectionSubject subject() {
        return subject;
    }

    public void matched() {
        matched++;
    }

    /** A matching item on a line of the prompt; the line is named so the detail can draw it as matched. */
    public void matched(InspectedPrompt.Line line) {
        matched++;
        if (line != null) {
            matchedLines.add(line.number());
        }
    }

    public void mismatch(PromptInspectionFinding finding) {
        mismatched++;
        findings.add(Objects.requireNonNull(finding, "finding"));
    }

    public void unverifiable(PromptInspectionFinding finding) {
        unverifiable++;
        findings.add(Objects.requireNonNull(finding, "finding"));
    }

    /** A mismatch finding of this check, to fill and pass to {@link #mismatch}. */
    public PromptInspectionFinding.Builder mismatchFinding() {
        return PromptInspectionFinding.builder(checkCode, PromptInspectionOutcome.MISMATCH);
    }

    /** An unverifiable finding of this check, to fill and pass to {@link #unverifiable}. */
    public PromptInspectionFinding.Builder unverifiableFinding() {
        return PromptInspectionFinding.builder(checkCode, PromptInspectionOutcome.UNVERIFIABLE);
    }

    PromptInspectionCheckResult result() {
        return new PromptInspectionCheckResult(checkCode, matched, mismatched, unverifiable, findings, matchedLines);
    }
}
