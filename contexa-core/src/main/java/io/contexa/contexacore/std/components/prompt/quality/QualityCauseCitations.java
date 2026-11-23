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
package io.contexa.contexacore.std.components.prompt.quality;

import java.util.List;

/**
 * What the response check found of the facts an answer cited (quality plan 3.3, 3.6), as the cause classification
 * reads it: how many facts the reason codes cite, how many of them are on a line the prompt drew, how many of those the
 * check named as not saying what the code says, and each finding where they are kept.
 *
 * @param checked  whether the citations were checked against the facts the prompt was drawn from
 * @param cited    how many facts the reason codes cite
 * @param present  how many of them are on a line the prompt drew; null when not checked
 * @param flagged  how many of the present ones the check named; null when not checked
 * @param findings each cited fact with what the check found, where they are kept; empty otherwise
 */
public record QualityCauseCitations(boolean checked, int cited, Integer present, Integer flagged,
                                    List<Finding> findings) {

    /** Citations that were not checked. */
    public static final QualityCauseCitations NOT_CHECKED = new QualityCauseCitations(false, 0, null, null, List.of());

    /** The outcome of a finding whose line does not say what the reason code says. */
    public static final String MISMATCH = "MISMATCH";

    /**
     * One cited fact.
     *
     * @param code    the reason code that cites it
     * @param fact    the fact ID it cites
     * @param outcome what the check found: MATCH, MISMATCH or UNDECIDED
     * @param present whether the fact is on a line the prompt drew
     */
    public record Finding(String code, String fact, String outcome, boolean present) {
    }

    public QualityCauseCitations {
        cited = Math.max(0, cited);
        findings = findings == null ? List.of() : List.copyOf(findings);
    }

    /** Whether the counts the rules read are there: checked, with the present and the flagged ones counted. */
    public boolean counted() {
        return checked && present != null && flagged != null;
    }

    /** How many cited facts are not on a line the prompt drew. */
    public int notInPrompt() {
        return counted() ? Math.max(0, cited - present) : 0;
    }

    /** How many cited facts are on a line that does not say what the reason code says. */
    public int notSayingIt() {
        return counted() ? Math.max(0, flagged) : 0;
    }
}
