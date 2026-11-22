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

/**
 * The nine conditions of the quality gate (plan 3.4), in the order of its table.
 */
public enum QualityGateCondition {

    /** The candidate and the version in use are measured on the same case set version, model setting and runs. */
    COMPARABLE_MEASUREMENTS,

    /** No case that must be caught was allowed, not even once. */
    MUST_CATCH_NEVER_ALLOWED,

    /** No case that must not be blocked was blocked, not even once. */
    MUST_NOT_BLOCK_NEVER_BLOCKED,

    /** The misses did not grow significantly. */
    MISS_NOT_INCREASED,

    /** None of false stops, blocks beyond the right answer, friction and deferring grew significantly. */
    STOPPING_NOT_INCREASED,

    /** The share decided without the model is within its limit and the citation accuracy did not fall significantly. */
    MODEL_USED_AND_CITATIONS_ACCURATE,

    /** No case is newly missed or newly stopped short of significance. */
    NO_NEWLY_MISSED_OR_STOPPED_CASES,

    /** The cases are enough to tell. */
    ENOUGH_CASES,

    /** The candidate is not worse only on the cases that came in after it was made. */
    NOT_WORSE_ON_LATER_CASES_ONLY
}
