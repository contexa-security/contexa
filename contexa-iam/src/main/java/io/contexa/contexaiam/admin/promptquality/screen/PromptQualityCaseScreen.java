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
import io.contexa.contexacore.autonomous.tiered.prompt.SecurityDecisionPromptDocument;
import io.contexa.contexacore.std.components.prompt.quality.QualityAction;
import io.contexa.contexacore.std.components.prompt.quality.QualityActionBasis;
import io.contexa.contexacore.std.components.prompt.quality.QualityAnswer;
import io.contexa.contexacore.std.components.prompt.quality.QualityCase;
import io.contexa.contexacore.std.components.prompt.quality.QualityCaseClass;
import io.contexa.contexacore.std.components.prompt.quality.QualityCaseDocuments;
import io.contexa.contexacore.std.components.prompt.quality.QualityCaseExpectation;
import io.contexa.contexacore.std.components.prompt.quality.QualityCaseGrade;
import io.contexa.contexacore.std.components.prompt.quality.QualityCaseInput;
import io.contexa.contexacore.std.components.prompt.quality.QualityCaseKind;
import io.contexa.contexacore.std.components.prompt.quality.QualityCaseOrigin;
import io.contexa.contexacore.std.components.prompt.quality.QualityCaseRationale;
import io.contexa.contexacore.std.components.prompt.quality.QualityCaseResource;
import io.contexa.contexacore.std.components.prompt.quality.QualityGateSettings;
import io.contexa.contexacore.std.components.prompt.quality.QualityMetric;
import io.contexa.contexacore.std.components.prompt.quality.QualityRate;
import io.contexa.contexacore.std.components.prompt.version.PromptVersionNames;
import io.contexa.contexacore.verification.evidence.SealedEvidencePackage;
import io.contexa.contexacore.verification.evidence.SealedEvidencePackageRepository;
import io.contexa.contexaiam.admin.promptquality.cases.PromptQualityCases;
import io.contexa.contexaiam.admin.promptquality.cases.QualityCaseResources;
import io.contexa.contexaiam.admin.promptquality.measure.MeasuredQualityGateSource;
import io.contexa.contexaiam.admin.promptquality.measure.PromptQualityMeasurements;
import io.contexa.contexaiam.admin.promptquality.measure.PromptQualityResourceClasses;
import io.contexa.contexaiam.admin.promptquality.screen.PromptQualityCaseViews.Bundle;
import io.contexa.contexaiam.admin.promptquality.screen.PromptQualityCaseViews.CaseRow;
import io.contexa.contexaiam.admin.promptquality.screen.PromptQualityCaseViews.ChangeRow;
import io.contexa.contexaiam.admin.promptquality.screen.PromptQualityCaseViews.Counts;
import io.contexa.contexaiam.admin.promptquality.screen.PromptQualityCaseViews.Detail;
import io.contexa.contexaiam.admin.promptquality.screen.PromptQualityCaseViews.Improved;
import io.contexa.contexaiam.admin.promptquality.screen.PromptQualityCaseViews.InputDocument;
import io.contexa.contexaiam.admin.promptquality.screen.PromptQualityCaseViews.ListView;
import io.contexa.contexaiam.admin.promptquality.screen.PromptQualityCaseViews.Published;
import io.contexa.contexaiam.admin.promptquality.screen.PromptQualityCaseViews.ResultRow;
import io.contexa.contexaiam.admin.promptquality.screen.PromptQualityCaseViews.Saved;
import io.contexa.contexaiam.admin.promptquality.screen.PromptQualityCaseViews.Sufficiency;
import io.contexa.contexaiam.admin.promptquality.version.PromptVersionConsole;
import io.contexa.contexaiam.admin.promptquality.version.PromptVersionService;
import org.springframework.lang.Nullable;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.OptionalInt;
import java.util.Set;
import java.util.function.Supplier;

/**
 * The screen of the labelled cases (quality plan 3.2, quality P46), composed from the services of the cases, the
 * measurements and the resource classes; the changes are theirs (the cases keep the audit of every change). Only the
 * security decision has cases.
 *
 * <ul>
 * <li>The published bundle and the cases added since: the confirmed cases the scope would publish now that the latest
 * published bundle does not hold.</li>
 * <li>Whether there are cases enough: the distinct roots to stop and to pass of the published bundle against the
 * gate's targets, and the chance to tell a better version at the roots there are ({@link QualityCasePower}).</li>
 * <li>The cases of the published bundle by resource class beside the decisions of the operation of the last
 * {@link #OPERATION_PERIOD}, and the resources with the most cases.</li>
 * <li>Every case, newest first, with what the version in use answered on its latest measurement.</li>
 * <li>A case: its answer, its input in five views, the measurements that answered it, the changes of its answer and
 * what those changes alone did to its results.</li>
 * </ul>
 */
public class PromptQualityCaseScreen {

    /** The prompt that has labelled cases. */
    static final String PROMPT = SecurityDecisionPromptDocument.PROMPT;
    /** The period of the decisions of the operation the cases by resource class stand beside (the mockup's week). */
    static final Duration OPERATION_PERIOD = Duration.ofDays(7);
    /** How many measurements of a case its history shows. */
    static final int HISTORY = 20;
    /**
     * The miss rate the chance to tell a better version assumes when the version in use has no measurement: the
     * product version's record on the default bundle (14 of 45, plan 3.2).
     */
    static final double REFERENCE_MISS = 14.0 / 45.0;
    /** The measurements of the version in use looked through for its latest finished one. */
    private static final int RECENT = 20;

    public static final String NOT_SEALED = "NOT_SEALED";
    public static final String INVALID = "INVALID";
    public static final String NOT_FOUND = "NOT_FOUND";

    /** A request the screen refuses, with the code the screen names. */
    public static class RefusedException extends RuntimeException {

        private final String code;

        public RefusedException(String code, String message) {
            super(message);
            this.code = code;
        }

        public String code() {
            return code;
        }
    }

    /**
     * A new answer, as the screen sends it.
     *
     * @param allowedActions the actions that are right (ALLOW, CHALLENGE, ESCALATE, BLOCK)
     * @param preferred      the most desirable of them, or none
     * @param decidingFacts  the facts that decide the case, one a line
     */
    public record AnswerForm(List<String> allowedActions, @Nullable String preferred, String classification,
                             String kind, @Nullable String rationaleKo, @Nullable String rationaleEn,
                             @Nullable List<String> decidingFacts, String grade) {
    }

    private final PromptQualityCases cases;
    private final Supplier<PromptQualityMeasurements> measurements;
    private final Supplier<PromptQualityResourceClasses> classes;
    private final Supplier<PromptVersionConsole> console;
    private final Supplier<SealedEvidencePackageRepository> sealed;
    private final QualityGateSettings gate;
    private final Clock clock;

    /**
     * @param measurements a supplier of null when this application cannot replay decisions
     * @param console      what tells the version decisions run now; a supplier of null without the version screens
     * @param sealed       the sealed decisions a case is promoted from; a supplier of null when there are none
     * @param gate         the gate's settings: the targets of roots and the level of its comparisons
     */
    public PromptQualityCaseScreen(PromptQualityCases cases, @Nullable Supplier<PromptQualityMeasurements> measurements,
                                   @Nullable Supplier<PromptQualityResourceClasses> classes,
                                   @Nullable Supplier<PromptVersionConsole> console,
                                   @Nullable Supplier<SealedEvidencePackageRepository> sealed,
                                   @Nullable QualityGateSettings gate, @Nullable Clock clock) {
        this.cases = Objects.requireNonNull(cases, "cases");
        this.measurements = measurements != null ? measurements : () -> null;
        this.classes = classes != null ? classes : () -> null;
        this.console = console != null ? console : () -> null;
        this.sealed = sealed != null ? sealed : () -> null;
        this.gate = gate != null ? gate : QualityGateSettings.defaults();
        this.clock = clock != null ? clock : Clock.systemUTC();
    }

    // ----- the list -----

    public ListView list(@Nullable String scope, String actor) {
        String scopeName = scopeOf(scope);
        List<PromptQualityCases.Kept> kept = cases.list(scopeName, PROMPT);
        Optional<PromptQualityCases.PublishedSet> latest = cases.latestPublished(scopeName, PROMPT);
        List<QualityCase> publishable = publishable(kept);
        List<QualityCase> counted = latest.map(set -> cases.read(set).cases().cases()).orElse(publishable);
        int addedSince = latest.isPresent() ? added(publishable, counted) : publishable.size();
        Used used = used(scopeName);

        Map<String, List<QualityAnswer>> answers = new LinkedHashMap<>();
        if (used.measure() != null) {
            for (QualityAnswer answer : measurements.get().answers(used.measure().id())) {
                answers.computeIfAbsent(answer.caseKey(), key -> new ArrayList<>()).add(answer);
            }
        }
        List<CaseRow> rows = new ArrayList<>();
        kept.stream().sorted(Comparator.comparing(PromptQualityCases.Kept::submittedAt).reversed()
                .thenComparing(Comparator.comparingLong(PromptQualityCases.Kept::id).reversed()))
                .forEach(item -> rows.add(row(item.item(), item, answers.get(item.key()), used.measure() != null)));
        cases.defaultSet().cases().forEach(item -> rows.add(row(item, null, answers.get(item.key()),
                used.measure() != null)));

        int pending = (int) kept.stream().filter(item -> !item.confirmed()).count();
        int operation = (int) kept.stream().filter(item -> item.item().origin() == QualityCaseOrigin.OPERATION).count();
        Counts counts = new Counts(rows.size(), cases.defaultSet().cases().size(), operation,
                kept.size() - operation, pending);
        PromptQualityResourceClasses resourceClasses = classes.get();
        Instant now = clock.instant();
        PromptQualityResourceClasses.Coverage coverage = resourceClasses != null
                ? resourceClasses.coverage(scopeName, PROMPT, latest.map(PromptQualityCases.PublishedSet::id).orElse(null),
                now.minus(OPERATION_PERIOD), now) : null;
        return new ListView(scopeName, cases.twoPersonConfirmation(), actorOf(actor),
                latest.map(PromptQualityCaseScreen::bundle).orElse(null), addedSince,
                sufficiency(counted, used.missRate()), counts, used.version(),
                used.measure() != null ? used.measure().id() : null, coverage, List.copyOf(rows));
    }

    /** The cases the scope would publish now: the default set and the confirmed cases kept in it. */
    private List<QualityCase> publishable(List<PromptQualityCases.Kept> kept) {
        List<QualityCase> items = new ArrayList<>(cases.defaultSet().cases());
        kept.stream().filter(PromptQualityCases.Kept::confirmed).forEach(item -> items.add(item.item()));
        return items;
    }

    /** How many cases of the first list, by key and content, the second does not hold. */
    private static int added(List<QualityCase> now, List<QualityCase> published) {
        Set<String> held = new HashSet<>();
        published.forEach(item -> held.add(item.key() + "\u0000" + item.contentHash()));
        return (int) now.stream().filter(item -> !held.contains(item.key() + "\u0000" + item.contentHash())).count();
    }

    private Sufficiency sufficiency(List<QualityCase> counted, @Nullable Double usedMiss) {
        Set<String> stopRoots = new HashSet<>();
        Set<String> passRoots = new HashSet<>();
        int stopCases = 0;
        for (QualityCase item : counted) {
            if (item.shouldStop()) {
                stopRoots.add(item.rootKey());
                stopCases++;
            }
            else {
                passRoots.add(item.rootKey());
            }
        }
        double base = usedMiss != null && usedMiss > QualityCasePower.DIFFERENCE && usedMiss < 1 ? usedMiss
                : REFERENCE_MISS;
        Double power = stopRoots.isEmpty() ? null
                : QualityCasePower.of(stopRoots.size(), base, gate.significance());
        return new Sufficiency(stopRoots.size(), stopCases, gate.minimumStopRoots(), passRoots.size(),
                counted.size() - stopCases, gate.minimumAllowRoots(), power,
                QualityCasePower.of(Math.max(1, gate.minimumStopRoots()), base, gate.significance()), base);
    }

    /** The version decisions run now, its latest finished measurement and its miss rate on the first answer. */
    private record Used(@Nullable String version, @Nullable PromptQualityMeasurements.Measure measure,
                        @Nullable Double missRate) {
    }

    private Used used(String scope) {
        PromptVersionConsole versions = console.get();
        String version = versions != null ? versions.trials(scope, PROMPT).current() : null;
        PromptQualityMeasurements runner = measurements.get();
        OptionalInt number = version != null ? PromptVersionNames.number(version) : OptionalInt.empty();
        if (runner == null || number.isEmpty()) {
            return new Used(version, null, null);
        }
        Optional<PromptQualityMeasurements.Measure> measure = runner.recent(scope, PROMPT, number.getAsInt(), RECENT)
                .stream().filter(found -> PromptQualityMeasurements.DONE.equals(found.status()))
                .filter(found -> found.answered() > 0).findFirst();
        if (measure.isEmpty()) {
            return new Used(version, null, null);
        }
        Double miss = runner.result(measure.get().id()).map(result -> result.firstAnswer().rate(QualityMetric.MISS))
                .filter(QualityRate::defined).map(QualityRate::value).orElse(null);
        return new Used(version, measure.get(), miss);
    }

    private CaseRow row(QualityCase item, @Nullable PromptQualityCases.Kept kept, @Nullable List<QualityAnswer> answers,
                        boolean measured) {
        QualityCaseResource resource = QualityCaseResources.of(item);
        QualityCaseExpectation expectation = item.expectation();
        boolean pending = kept != null && !kept.confirmed();
        String now = pending ? "PENDING" : measured ? result(item, answers) : "NONE";
        return new CaseRow(item.key(), MeasuredQualityGateSource.caseName(item), item.origin().name(), kept != null ? kept.submittedAt() : item.addedAt(),
                item.rootCaseKey(), kept == null, pending, kept != null ? kept.labelledBy() : null, resource.resource(),
                resourceName(resource), resource.group(), expectation.classification().name(),
                expectation.kind().name(), expectation.allowedActions().stream().map(Enum::name).toList(),
                expectation.preferredAction() != null ? expectation.preferredAction().name() : null,
                item.grade().name(), now);
    }

    /**
     * What a case's answers came to on the first answer: MISS when a case to stop was allowed in a run, HIT when every
     * run is a right action, OFF otherwise, NONE when no run was scored.
     */
    static String result(QualityCase item, @Nullable List<QualityAnswer> answers) {
        return result(item.expectation(), item.shouldStop(), answers);
    }

    private static String result(QualityCaseExpectation expectation, boolean shouldStop,
                                 @Nullable List<QualityAnswer> answers) {
        List<QualityAction> actions = new ArrayList<>();
        for (QualityAnswer answer : answers != null ? answers : List.<QualityAnswer>of()) {
            QualityAction action = QualityActionBasis.FIRST_ANSWER.of(answer);
            if (!answer.measurementFailed() && action != null) {
                actions.add(action);
            }
        }
        if (actions.isEmpty()) {
            return "NONE";
        }
        if (shouldStop && actions.contains(QualityAction.ALLOW)) {
            return "MISS";
        }
        return actions.stream().allMatch(expectation::allows) ? "HIT" : "OFF";
    }

    @Nullable
    static String resourceName(QualityCaseResource resource) {
        if (resource.urlTemplate() != null) {
            return (resource.httpMethod() != null ? resource.httpMethod() + " " : "") + resource.urlTemplate();
        }
        String name = resource.resource();
        if (name == null) {
            return null;
        }
        int dot = name.lastIndexOf('.');
        return dot >= 0 && dot < name.length() - 1 ? name.substring(dot + 1) : name;
    }

    private static Bundle bundle(PromptQualityCases.PublishedSet set) {
        return new Bundle(set.id(), set.version(), set.name(), set.caseCount(), set.defaultCaseCount(),
                set.publishedBy(), set.publishedAt());
    }

    // ----- a case -----

    public Optional<Detail> detail(@Nullable String scope, String key, String actor, Locale locale) {
        String scopeName = scopeOf(scope);
        Optional<QualityCase> found = cases.find(scopeName, PROMPT, key);
        if (found.isEmpty()) {
            return Optional.empty();
        }
        QualityCase item = found.get();
        Optional<PromptQualityCases.Kept> kept = cases.kept(scopeName, PROMPT, item.key());
        if (cases.defaultSet().find(item.key()).isPresent()) {
            kept = Optional.empty();
        }
        List<PromptQualityMeasurements.CaseHistory> history = measurements.get() != null
                ? measurements.get().caseHistory(scopeName, PROMPT, item.key(), HISTORY) : List.of();
        List<ResultRow> results = new ArrayList<>();
        for (PromptQualityMeasurements.CaseHistory measured : history) {
            List<String> actions = new ArrayList<>();
            measured.answers().forEach(answer -> {
                QualityAction action = QualityActionBasis.FIRST_ANSWER.of(answer);
                actions.add(answer.measurementFailed() || action == null ? null : action.name());
            });
            results.add(new ResultRow(measured.measure().id(), measured.measure().versionName(),
                    measured.measure().createdAt(), measured.measure().status(), actions,
                    result(item, measured.answers())));
        }
        List<PromptQualityCases.AnswerChange> answerChanges = kept.isPresent()
                ? cases.answerChanges(scopeName, PROMPT, item.key()) : List.of();
        CaseRow row = row(item, kept.orElse(null), null, false);
        String who = actorOf(actor);
        QualityCaseExpectation expectation = item.expectation();
        return Optional.of(new Detail(scopeName, cases.twoPersonConfirmation(), row,
                kept.map(PromptQualityCaseScreen::personal).orElse(false),
                kept.map(PromptQualityCases.Kept::sealedPackageId).orElse(null),
                kept.map(PromptQualityCases.Kept::submittedBy).orElse(null),
                kept.map(PromptQualityCases.Kept::submittedAt).orElse(null),
                kept.map(PromptQualityCases.Kept::labelledBy).orElse(null),
                kept.map(PromptQualityCases.Kept::labelledAt).orElse(null),
                kept.map(PromptQualityCases.Kept::confirmedBy).orElse(null),
                kept.map(PromptQualityCases.Kept::confirmedAt).orElse(null),
                kept.isPresent() && !kept.get().confirmed() && !who.equals(kept.get().labelledBy()),
                expectation.rationale().korean(), expectation.rationale().english(), expectation.decidingFacts(),
                QualityCaseInputSummary.of(item.input()), List.copyOf(results),
                changes(kept.orElse(null), answerChanges, locale),
                improved(item, answerChanges, history)));
    }

    /**
     * Quality plan 3.2: whether a kept case holds a real person's decision: one promoted from the operation, or copied
     * from one (it names the sealed package it came from). A copy of a case of the default set holds the showcase's.
     */
    static boolean personal(PromptQualityCases.Kept kept) {
        return kept.item().origin() == QualityCaseOrigin.OPERATION || kept.sealedPackageId() != null;
    }

    /** The events of the answer: its submission, every change and its confirmation, the oldest first. */
    private static List<ChangeRow> changes(@Nullable PromptQualityCases.Kept kept,
                                           List<PromptQualityCases.AnswerChange> changes, Locale locale) {
        if (kept == null) {
            return List.of();
        }
        List<ChangeRow> rows = new ArrayList<>();
        QualityCaseExpectation first = changes.isEmpty() ? kept.item().expectation() : changes.get(0).previous();
        QualityCaseGrade firstGrade = changes.isEmpty() ? kept.item().grade() : changes.get(0).previousGrade();
        rows.add(new ChangeRow("SUBMITTED", kept.submittedAt(), kept.submittedBy(), names(first), List.of(),
                firstGrade.name(), null, why(first, locale)));
        for (PromptQualityCases.AnswerChange change : changes) {
            rows.add(new ChangeRow("CHANGED", change.changedAt(), change.changedBy(), names(change.next()),
                    names(change.previous()), change.newGrade().name(), change.previousGrade().name(),
                    why(change.next(), locale)));
        }
        if (kept.confirmed() && kept.confirmedAt() != null) {
            rows.add(new ChangeRow("CONFIRMED", kept.confirmedAt(), kept.confirmedBy(), List.of(), List.of(), null,
                    null, null));
        }
        rows.sort(Comparator.comparing(ChangeRow::at));
        return List.copyOf(rows);
    }

    private static List<String> names(QualityCaseExpectation expectation) {
        return expectation.allowedActions().stream().map(Enum::name).toList();
    }

    @Nullable
    private static String why(QualityCaseExpectation expectation, Locale locale) {
        QualityCaseRationale rationale = expectation.rationale();
        boolean korean = locale != null && "ko".equals(locale.getLanguage());
        return korean ? (rationale.korean() != null ? rationale.korean() : rationale.english())
                : (rationale.english() != null ? rationale.english() : rationale.korean());
    }

    /**
     * Quality plan 3.2: the answers measured on the case that are right on its present answer and were wrong on the
     * answer it was submitted with (better), and the reverse (worse); null when the answer never changed.
     */
    @Nullable
    static Improved improved(QualityCase item, List<PromptQualityCases.AnswerChange> changes,
                             List<PromptQualityMeasurements.CaseHistory> history) {
        if (changes.isEmpty()) {
            return null;
        }
        QualityCaseExpectation first = changes.get(0).previous();
        QualityCaseExpectation present = item.expectation();
        int answers = 0;
        int better = 0;
        int worse = 0;
        for (PromptQualityMeasurements.CaseHistory measured : history) {
            for (QualityAnswer answer : measured.answers()) {
                QualityAction action = QualityActionBasis.FIRST_ANSWER.of(answer);
                if (answer.measurementFailed() || action == null) {
                    continue;
                }
                answers++;
                boolean rightBefore = first.allows(action);
                boolean rightNow = present.allows(action);
                if (rightNow && !rightBefore) {
                    better++;
                }
                else if (rightBefore && !rightNow) {
                    worse++;
                }
            }
        }
        return new Improved(history.size(), answers, better, worse);
    }

    /** The input of a case, as a copy of it starts with. */
    public Optional<InputDocument> input(@Nullable String scope, String key) {
        return cases.find(scopeOf(scope), PROMPT, key).map(item -> new InputDocument(item.key(),
                QualityCaseDocuments.writeInput(item.input())));
    }

    // ----- the changes -----

    /**
     * Quality plan 3.2: a case of the customer copied from another case, its input changed or as it is, with an answer
     * of its own.
     *
     * @param input the input of the copy, or null for the source's
     * @throws RefusedException            when the input or the answer cannot be read
     * @throws PromptQualityCases.RefusedException when there is no such source, or the copy cannot be a case
     */
    public Saved create(@Nullable String scope, String sourceKey, @Nullable JsonNode input, AnswerForm answer,
                        String actor) {
        if (sourceKey == null || sourceKey.isBlank()) {
            throw new RefusedException(INVALID, "The case to copy is required");
        }
        QualityCaseInput changed = null;
        if (input != null && !input.isNull() && !input.isMissingNode()) {
            try {
                changed = QualityCaseDocuments.readInput(input);
            }
            catch (RuntimeException unreadable) {
                throw new RefusedException(INVALID, "The input of the copy cannot be read: " + unreadable.getMessage());
            }
        }
        Answer parsed = parse(answer);
        PromptQualityCases.Kept kept = cases.copy(scopeOf(scope), PROMPT, sourceKey.trim(), changed,
                parsed.expectation(), parsed.grade(), actor);
        return new Saved(kept.key(), kept.status());
    }

    /**
     * Quality plan 3.2: a sealed decision as a case of the operation, with the answer the administrator gives.
     *
     * @throws RefusedException with {@link #NOT_SEALED} when no decision of the id is sealed, or its package was kept
     *                          without its seal (the sealing failed): K199, a decision that is not sealed is no case
     */
    public Saved promote(@Nullable String scope, String packageId, AnswerForm answer, String actor) {
        if (packageId == null || packageId.isBlank()) {
            throw new RefusedException(INVALID, "The id of the sealed decision is required");
        }
        SealedEvidencePackageRepository repository = sealed.get();
        Optional<SealedEvidencePackage> found = repository != null
                ? repository.findByPackageId(packageId.trim()) : Optional.empty();
        if (found.isEmpty()) {
            throw new RefusedException(NOT_SEALED, "No decision of the id " + packageId.trim() + " is sealed");
        }
        if (!found.get().hasSealedState()) {
            throw new RefusedException(NOT_SEALED, "The decision of the id " + packageId.trim()
                    + " was kept without its seal (" + found.get().getSealState() + ")");
        }
        Answer parsed = parse(answer);
        PromptQualityCases.Kept kept = cases.promote(scopeOf(scope), PROMPT, found.get(), null, null,
                parsed.expectation(), parsed.grade(), actor);
        return new Saved(kept.key(), kept.status());
    }

    public Saved changeAnswer(@Nullable String scope, String key, AnswerForm answer, String actor) {
        Answer parsed = parse(answer);
        PromptQualityCases.Kept kept = cases.changeAnswer(scopeOf(scope), PROMPT, key, parsed.expectation(),
                parsed.grade(), actor);
        return new Saved(kept.key(), kept.status());
    }

    public Saved confirm(@Nullable String scope, String key, String actor) {
        PromptQualityCases.Kept kept = cases.confirm(scopeOf(scope), PROMPT, key, actor);
        return new Saved(kept.key(), kept.status());
    }

    /** @throws RefusedException with {@link #NOT_FOUND} when there is no such kept case */
    public Saved delete(@Nullable String scope, String key, String actor) {
        if (!cases.delete(scopeOf(scope), PROMPT, key, actor)) {
            throw new RefusedException(NOT_FOUND, "There is no case " + key);
        }
        return new Saved(key, "DELETED");
    }

    public Published publish(@Nullable String scope, String actor) {
        String scopeName = scopeOf(scope);
        Optional<PromptQualityCases.PublishedSet> before = cases.latestPublished(scopeName, PROMPT);
        PromptQualityCases.PublishedSet set = cases.publish(scopeName, PROMPT, actor);
        return new Published(bundle(set), before.isPresent() && before.get().id() == set.id());
    }

    record Answer(QualityCaseExpectation expectation, QualityCaseGrade grade) {
    }

    /** The answer of the form; a value it cannot be is refused as {@link #INVALID}. */
    static Answer parse(AnswerForm form) {
        if (form == null) {
            throw new RefusedException(INVALID, "The answer is required");
        }
        try {
            Set<QualityAction> allowed = new HashSet<>();
            for (String name : form.allowedActions() != null ? form.allowedActions() : List.<String>of()) {
                allowed.add(QualityAction.valueOf(name.trim()));
            }
            QualityAction preferred = form.preferred() == null || form.preferred().isBlank() ? null
                    : QualityAction.valueOf(form.preferred().trim());
            List<String> facts = new ArrayList<>();
            for (String fact : form.decidingFacts() != null ? form.decidingFacts() : List.<String>of()) {
                if (fact != null && !fact.isBlank()) {
                    facts.add(fact.trim());
                }
            }
            QualityCaseExpectation expectation = new QualityCaseExpectation(allowed, preferred,
                    QualityCaseClass.valueOf(form.classification().trim()), QualityCaseKind.valueOf(form.kind().trim()),
                    new QualityCaseRationale(form.rationaleKo(), form.rationaleEn()), facts);
            return new Answer(expectation, QualityCaseGrade.valueOf(form.grade().trim()));
        }
        catch (IllegalArgumentException | NullPointerException invalid) {
            throw new RefusedException(INVALID, "The answer cannot be read: " + invalid.getMessage());
        }
    }

    static String scopeOf(@Nullable String scope) {
        return scope != null && !scope.isBlank() ? scope.trim() : PromptVersionService.PLATFORM_SCOPE;
    }

    static String actorOf(@Nullable String actor) {
        return actor != null && !actor.isBlank() ? actor.trim() : "system";
    }
}
