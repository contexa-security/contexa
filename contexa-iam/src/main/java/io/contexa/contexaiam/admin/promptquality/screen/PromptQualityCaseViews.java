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
package io.contexa.contexaiam.admin.promptquality.screen;

import com.fasterxml.jackson.databind.JsonNode;
import io.contexa.contexaiam.admin.promptquality.measure.PromptQualityResourceClasses;
import org.springframework.lang.Nullable;

import java.time.Instant;
import java.util.List;

/**
 * What the screen of the labelled cases (quality plan 3.2) reads and sends: the list with the published bundle, how
 * many cases there are against the targets, the cases by resource class beside the decisions of the operation (quality
 * P46) and every case; a case with its answer, a summary of its input, its results and the changes of its answer; and
 * the forms of the changes.
 */
public final class PromptQualityCaseViews {

    private PromptQualityCaseViews() {
    }

    /**
     * The screen of the list.
     *
     * @param twoPerson   whether a case waits for an administrator other than the one who set its answer
     * @param actor       the administrator reading, who cannot confirm an answer of theirs
     * @param bundle      the latest published bundle, or null when nothing is published in the scope
     * @param addedSince  the confirmed cases the scope would publish now that the latest bundle does not hold
     * @param usedVersion the version decisions run now, whose latest measurement gives each case its result
     * @param measureId   that measurement, or null when the version in use has none
     * @param coverage    the cases of the published bundle (else of what the scope would publish) by resource class
     */
    public record ListView(String scope, boolean twoPerson, String actor, @Nullable Bundle bundle, int addedSince,
                           Sufficiency sufficiency, Counts counts, @Nullable String usedVersion,
                           @Nullable Long measureId, PromptQualityResourceClasses.Coverage coverage,
                           List<CaseRow> rows) {
    }

    /** A published bundle: its version (the content hash of its cases), its name and its cases. */
    public record Bundle(long id, String version, String name, int cases, int defaultCases, String publishedBy,
                         Instant publishedAt) {
    }

    /**
     * Quality plan 3.2: whether there are cases enough to tell versions apart, counted by distinct root cases.
     *
     * @param power         the chance to tell a version that misses 10 points less, at the roots there are; null with
     *                      no root to stop
     * @param powerAtTarget the same chance at the target of roots to stop
     * @param baseMiss      the miss rate the chance assumes of the version in use
     */
    public record Sufficiency(int stopRoots, int stopCases, int stopTarget, int passRoots, int passCases,
                              int passTarget, @Nullable Double power, double powerAtTarget, double baseMiss) {
    }

    /** How many cases each view of the list holds. */
    public record Counts(int all, int contexa, int operation, int customer, int pending) {
    }

    /**
     * One case of the list.
     *
     * @param name          what the case asks: the method and the path of its request, with its key
     * @param at            when it came in; null for a case of the default set
     * @param root          the root case it was made from, or null for a root case
     * @param readonly      a case of the default set Contexa ships, changed only by copying it
     * @param pending       its answer waits for confirmation
     * @param resource      the protected resource its input asks for, or null
     * @param resourceName  the method and URL template of the resource, else its name
     * @param resourceClass the class of the resource, as the decision rows of the operation keep it
     * @param now           what the version in use answered on its latest measurement: HIT, MISS, OFF, NONE, or
     *                      PENDING while the answer waits for confirmation
     */
    public record CaseRow(String key, String name, String origin, @Nullable Instant at, @Nullable String root,
                          boolean readonly, boolean pending, @Nullable String labelledBy, @Nullable String resource,
                          @Nullable String resourceName, String resourceClass, String classification, String kind,
                          List<String> allowed, @Nullable String preferred, String grade, String now) {
    }

    /**
     * A case.
     *
     * @param privacy        the case holds a real person's decision (a user, addresses and the person's baselines)
     *                       and outlives the retention of the seals
     * @param canConfirm     the administrator reading may confirm its answer now
     * @param improvedByEdit what the changes of its answer alone did to the results measured on it
     */
    public record Detail(String scope, boolean twoPerson, CaseRow row, boolean privacy, @Nullable String sealedPackageId,
                         @Nullable String submittedBy, @Nullable Instant submittedAt, @Nullable String labelledBy,
                         @Nullable Instant labelledAt, @Nullable String confirmedBy, @Nullable Instant confirmedAt,
                         boolean canConfirm, @Nullable String rationaleKo, @Nullable String rationaleEn,
                         List<String> decidingFacts, InputSummary input, List<ResultRow> results,
                         List<ChangeRow> changes, @Nullable Improved improvedByEdit) {
    }

    /**
     * The decision input of a case in the five views of the screen: the request, the session, how it differs from
     * the usual, the work records and what is not known.
     */
    public record InputSummary(List<InputLine> request, List<InputLine> session, List<InputLine> deviation,
                               List<InputLine> records, List<InputLine> unknown) {
    }

    /**
     * A line of the input.
     *
     * @param name  the code of the value (its words are the screen's), or null for a line of the input's own words
     * @param value the value as the input holds it
     */
    public record InputLine(@Nullable String name, String value) {
    }

    /**
     * A measurement that answered the case: the action of every run on the first answer, and what it came to.
     *
     * @param actions the first answer of each run, null for a run the measurement could not take
     * @param result  HIT, MISS, OFF or NONE (no run scored)
     */
    public record ResultRow(long measureId, String version, Instant measuredAt, String status,
                            List<String> actions, String result) {
    }

    /**
     * An event of the answer: its submission, a change of it, its confirmation.
     *
     * @param kind     SUBMITTED, CHANGED or CONFIRMED
     * @param allowed  the allowed actions after the event; empty for a confirmation
     * @param previous the allowed actions before a change; empty otherwise
     * @param why      the reason the answer gives after the event, in the reader's language when it has one
     */
    public record ChangeRow(String kind, Instant at, String by, List<String> allowed, List<String> previous,
                            @Nullable String grade, @Nullable String previousGrade, @Nullable String why) {
    }

    /**
     * Quality plan 3.2: what changing the answer did, apart from what the versions did: the answers measured on the
     * case, right on the present answer and wrong on the first one (better), and the reverse (worse).
     */
    public record Improved(int measurements, int answers, int better, int worse) {
    }

    /** The input of a case as a copy of it starts with. */
    public record InputDocument(String key, JsonNode input) {
    }

    /** What a change did: the case it made or changed. */
    public record Saved(String key, String status) {
    }

    /** A published bundle and whether it is the one published before (the same cases publish the same bundle). */
    public record Published(Bundle bundle, boolean same) {
    }

    /** A request the screen refuses: 422 with the code the screen names. */
    public record Refused(String code) {
    }
}
