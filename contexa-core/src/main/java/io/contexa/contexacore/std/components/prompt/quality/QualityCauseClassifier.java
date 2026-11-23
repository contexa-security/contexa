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

import com.fasterxml.jackson.databind.JsonNode;

import java.util.ArrayList;
import java.util.Collection;
import java.util.Comparator;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Optional;
import java.util.Set;
import java.util.stream.Collectors;

/**
 * The cause classification (quality plan 3.5): a wrong answer of a measurement, or a decision an administrator rated
 * inadequate, is put down to a cause by deterministic rules, which an administrator may correct. The same record gives
 * the same cause; no model is asked (plan 3.1, 7).
 * <p>
 * Each of the seven rules comes to one of three states for an answer: the cause applies, it does not apply, or it could
 * not be computed because what it reads is not there. The answer is put down to the first cause that applies in the
 * order of {@link QualityCause#RULED}, which says why that order. A rule computes only what its record states:
 * <ul>
 *     <li>Input shortage: a deciding fact on the prompt's list of unknown facts is known only for a case that lists its
 *     deciding facts, so for any other case, and for every decision, the rule applies only through a low context and is
 *     not computed otherwise. A deciding fact is on the list when it, or a part of its path before {@code =}, is the
 *     name of an unknown fact. The context is low below {@code SCOPE_AWARE} ({@link #LOW_CONTEXT_LEVELS}), where the
 *     authorization scope of the request is partial or unknown.</li>
 *     <li>Input error is a decision's only, and only where the evidence audit compared its sealed facts with the host's
 *     records; a measured case's input is the input it was labelled on.</li>
 *     <li>Unstable needs two runs of the case or more.</li>
 *     <li>A model call over the time limit is judged by the limit of the decisions (the first layer's model call limit
 *     the caller gives), not by the replay's own, longer limit.</li>
 *     <li>A citation is wrong when the fact it cites is not on a line the prompt drew, or the check named its line as
 *     not saying what the reason code says (MISMATCH); a citation the facts could not decide (UNDECIDED) is not.</li>
 * </ul>
 */
public final class QualityCauseClassifier {

    /** The context coverage levels read as low: the authorization scope of the request is partial or unknown. */
    public static final Set<String> LOW_CONTEXT_LEVELS = Set.of("ENVIRONMENT_ONLY", "IDENTITY_AWARE");

    // Format and model.
    public static final String NO_ANSWER = "NO_ANSWER";
    public static final String MODEL_ANSWER_UNUSABLE = "MODEL_ANSWER_UNUSABLE";
    public static final String SECOND_PASS_UNUSABLE = "SECOND_PASS_UNUSABLE";
    public static final String OVER_TIME_LIMIT = "OVER_TIME_LIMIT";
    public static final String MODEL_LESS = "MODEL_LESS";
    public static final String TECHNICAL_FALLBACK = "TECHNICAL_FALLBACK";
    public static final String RESPONSE_FORMAT = "RESPONSE_FORMAT";
    public static final String MODEL_UNAVAILABLE = "MODEL_UNAVAILABLE";
    public static final String MODEL_ANSWER_USED = "MODEL_ANSWER_USED";
    public static final String TIME_LIMIT_UNKNOWN = "TIME_LIMIT_UNKNOWN";
    public static final String CALL_TIME_UNKNOWN = "CALL_TIME_UNKNOWN";
    public static final String NO_DECISION_SOURCE = "NO_DECISION_SOURCE";
    // Engine changed.
    public static final String MODEL_ACTION_CHANGED = "MODEL_ACTION_CHANGED";
    public static final String MODEL_ACTION_WRONG = "MODEL_ACTION_WRONG";
    public static final String MODEL_ACTION_STOOD = "MODEL_ACTION_STOOD";
    public static final String ACTION_NOT_CHANGED = "ACTION_NOT_CHANGED";
    public static final String NO_MODEL_ACTION = "NO_MODEL_ACTION";
    // Input error.
    public static final String SOURCE_MISMATCH = "SOURCE_MISMATCH";
    public static final String SOURCE_MATCHED = "SOURCE_MATCHED";
    public static final String NOT_SEALED = "NOT_SEALED";
    public static final String NOT_INSPECTED = "NOT_INSPECTED";
    public static final String NOT_COMPARED = "NOT_COMPARED";
    public static final String DECISIONS_ONLY = "DECISIONS_ONLY";
    // Input shortage.
    public static final String DECIDING_FACT_UNKNOWN = "DECIDING_FACT_UNKNOWN";
    public static final String CONTEXT_LEVEL_LOW = "CONTEXT_LEVEL_LOW";
    public static final String DECIDING_FACTS_KNOWN = "DECIDING_FACTS_KNOWN";
    public static final String NO_DECIDING_FACTS = "NO_DECIDING_FACTS";
    public static final String NO_CONTEXT_LEVEL = "NO_CONTEXT_LEVEL";
    // Grounding error.
    public static final String CITATION_NOT_IN_PROMPT = "CITATION_NOT_IN_PROMPT";
    public static final String CITATION_DOES_NOT_SAY_IT = "CITATION_DOES_NOT_SAY_IT";
    public static final String CITATIONS_RIGHT = "CITATIONS_RIGHT";
    public static final String NO_CITATION = "NO_CITATION";
    public static final String CITATIONS_NOT_CHECKED = "CITATIONS_NOT_CHECKED";
    // Unstable.
    public static final String ACTIONS_DIFFER = "ACTIONS_DIFFER";
    public static final String SAME_ACTION_EVERY_RUN = "SAME_ACTION_EVERY_RUN";
    public static final String ONE_RUN = "ONE_RUN";
    public static final String ONE_DECISION = "ONE_DECISION";
    // Judgement error.
    public static final String ACTION_OUTSIDE_ANSWER = "ACTION_OUTSIDE_ANSWER";
    public static final String RATED_INADEQUATE = "RATED_INADEQUATE";
    public static final String CITATION_WRONG = "CITATION_WRONG";
    public static final String NO_ACTION = "NO_ACTION";

    private QualityCauseClassifier() {
    }

    // ----- measured answers -----

    /**
     * Which action of the answer is outside the case's answer, or empty when the answer is right on both bases or
     * says nothing about the prompt (its measurement failed). An answer that gave none of the four actions is wrong on
     * its first answer: no answer.
     */
    public static Optional<QualityCauseBasis> wrongOn(QualityCase item, QualityCauseAnswer answer) {
        if (answer.measurementFailed()) {
            return Optional.empty();
        }
        QualityCaseExpectation expectation = item.expectation();
        boolean first = answer.firstAction() == null || !expectation.allows(answer.firstAction());
        boolean last = answer.finalAction() != null && !expectation.allows(answer.finalAction());
        if (!first && !last) {
            return Optional.empty();
        }
        return Optional.of(first && last ? QualityCauseBasis.BOTH
                : first ? QualityCauseBasis.FIRST_ANSWER : QualityCauseBasis.FINAL);
    }

    /**
     * The cause of a wrong answer of a measurement.
     *
     * @param item            the case
     * @param answer          the wrong answer
     * @param runs            the answers of the same case in the same measurement, this one among them
     * @param timeLimitMillis the time limit of a first-layer model call of the decisions; 0 or less when unknown
     * @throws IllegalArgumentException when the answer is not wrong
     */
    public static QualityCauseResult measured(QualityCase item, QualityCauseAnswer answer,
                                              Collection<QualityCauseAnswer> runs, long timeLimitMillis) {
        QualityCauseBasis basis = wrongOn(item, answer).orElseThrow(() -> new IllegalArgumentException(
                "The answer of run " + answer.run() + " of the case " + item.key() + " is not wrong"));
        QualityAction judged = answer.action(basis.firstAnswer());
        QualityCauseCheck grounding = grounding(answer.citations());
        List<QualityCauseCheck> checks = List.of(
                formatAndModel(answer, basis, timeLimitMillis),
                engineChanged(item.expectation(), answer, judged),
                new QualityCauseCheck(QualityCause.INPUT_ERROR, QualityCauseCheck.State.CLEAR, DECISIONS_ONLY,
                        List.of()),
                inputShortage(item.expectation().decidingFacts(), unknownFacts(item), contextLevel(item)),
                grounding,
                unstable(item, runs, basis),
                judgement(grounding, judged, item.expectation()));
        return result(basis, checks);
    }

    /** The facts the prompt of the case names unknown: the unknown decision facts of its canonical context. */
    public static List<String> unknownFacts(QualityCase item) {
        JsonNode unknown = item.input().canonicalContext().path("decisionFacts").path("unknown");
        List<String> names = new ArrayList<>();
        unknown.forEach(name -> {
            if (name.isTextual() && !name.asText().isBlank()) {
                names.add(name.asText().trim());
            }
        });
        return names;
    }

    /** The context coverage level the case's prompt is drawn at, or null when its context states none. */
    public static String contextLevel(QualityCase item) {
        JsonNode level = item.input().canonicalContext().path("coverage").path("level");
        return level.isTextual() && !level.asText().isBlank() ? level.asText().trim() : null;
    }

    private static QualityCauseCheck formatAndModel(QualityCauseAnswer answer, QualityCauseBasis basis,
                                                    long timeLimitMillis) {
        List<String> found = new ArrayList<>();
        List<String> values = new ArrayList<>();
        if (answer.firstAction() == null) {
            found.add(NO_ANSWER);
        }
        if (answer.decidedWithoutModel()) {
            found.add(MODEL_ANSWER_UNUSABLE);
        }
        if (basis.finalAction() && answer.secondPassUnusable()) {
            found.add(SECOND_PASS_UNUSABLE);
        }
        String timeUnknown = null;
        if (timeLimitMillis <= 0) {
            timeUnknown = TIME_LIMIT_UNKNOWN;
        }
        else {
            boolean unmeasured = answer.firstPassCallMillis().isEmpty();
            for (int index = 0; index < answer.firstPassCallMillis().size(); index++) {
                Long took = answer.firstPassCallMillis().get(index);
                if (took == null) {
                    unmeasured = true;
                }
                else if (took > timeLimitMillis) {
                    if (!found.contains(OVER_TIME_LIMIT)) {
                        found.add(OVER_TIME_LIMIT);
                    }
                    values.add("call" + (index + 1) + "Ms=" + took);
                }
            }
            // The replay as a whole within the limit: none of its calls ran over it.
            if (unmeasured && (answer.decisionMillis() == null || answer.decisionMillis() > timeLimitMillis)) {
                timeUnknown = CALL_TIME_UNKNOWN;
            }
        }
        if (timeLimitMillis > 0) {
            values.add("limitMs=" + timeLimitMillis);
        }
        if (!found.isEmpty()) {
            return applies(QualityCause.FORMAT_AND_MODEL, found, values);
        }
        if (timeUnknown != null) {
            return new QualityCauseCheck(QualityCause.FORMAT_AND_MODEL, QualityCauseCheck.State.NOT_COMPUTED,
                    timeUnknown, timeLimitMillis > 0 ? List.of("limitMs=" + timeLimitMillis) : List.of());
        }
        return new QualityCauseCheck(QualityCause.FORMAT_AND_MODEL, QualityCauseCheck.State.CLEAR, MODEL_ANSWER_USED,
                values);
    }

    private static QualityCauseCheck engineChanged(QualityCaseExpectation expectation, QualityCauseAnswer answer,
                                                   QualityAction judged) {
        QualityAction model = answer.modelAction();
        if (model == null) {
            return new QualityCauseCheck(QualityCause.ENGINE_CHANGED, QualityCauseCheck.State.NOT_COMPUTED,
                    NO_MODEL_ACTION, List.of());
        }
        if (!expectation.allows(model)) {
            return new QualityCauseCheck(QualityCause.ENGINE_CHANGED, QualityCauseCheck.State.CLEAR,
                    MODEL_ACTION_WRONG, List.of("model=" + model));
        }
        if (judged == model) {
            return new QualityCauseCheck(QualityCause.ENGINE_CHANGED, QualityCauseCheck.State.CLEAR,
                    ACTION_NOT_CHANGED, List.of("model=" + model));
        }
        return new QualityCauseCheck(QualityCause.ENGINE_CHANGED, QualityCauseCheck.State.APPLIES,
                MODEL_ACTION_CHANGED, List.of("model=" + model, "action=" + name(judged)));
    }

    private static QualityCauseCheck unstable(QualityCase item, Collection<QualityCauseAnswer> runs,
                                              QualityCauseBasis basis) {
        List<QualityCauseAnswer> scored = (runs == null ? List.<QualityCauseAnswer>of() : runs).stream()
                .filter(run -> run.caseKey().equals(item.key()) && !run.measurementFailed()
                        && run.action(basis.firstAnswer()) != null)
                .sorted(Comparator.comparingInt(QualityCauseAnswer::run))
                .toList();
        if (scored.size() < 2) {
            return new QualityCauseCheck(QualityCause.UNSTABLE, QualityCauseCheck.State.NOT_COMPUTED, ONE_RUN,
                    List.of("runs=" + scored.size()));
        }
        List<String> actions = scored.stream()
                .map(run -> "run" + run.run() + "=" + run.action(basis.firstAnswer()))
                .toList();
        long distinct = scored.stream().map(run -> run.action(basis.firstAnswer())).distinct().count();
        return distinct > 1
                ? new QualityCauseCheck(QualityCause.UNSTABLE, QualityCauseCheck.State.APPLIES, ACTIONS_DIFFER, actions)
                : new QualityCauseCheck(QualityCause.UNSTABLE, QualityCauseCheck.State.CLEAR, SAME_ACTION_EVERY_RUN,
                        actions);
    }

    private static QualityCauseCheck judgement(QualityCauseCheck grounding, QualityAction judged,
                                               QualityCaseExpectation expectation) {
        if (judged == null) {
            return new QualityCauseCheck(QualityCause.JUDGEMENT_ERROR, QualityCauseCheck.State.CLEAR, NO_ACTION,
                    List.of());
        }
        return switch (grounding.state()) {
            case NOT_COMPUTED -> new QualityCauseCheck(QualityCause.JUDGEMENT_ERROR,
                    QualityCauseCheck.State.NOT_COMPUTED, CITATIONS_NOT_CHECKED, List.of());
            case APPLIES -> new QualityCauseCheck(QualityCause.JUDGEMENT_ERROR, QualityCauseCheck.State.CLEAR,
                    CITATION_WRONG, List.of());
            case CLEAR -> new QualityCauseCheck(QualityCause.JUDGEMENT_ERROR, QualityCauseCheck.State.APPLIES,
                    ACTION_OUTSIDE_ANSWER, List.of("action=" + judged, "allowed=" + expectation.allowedActions()
                    .stream().map(Enum::name).collect(Collectors.joining("|"))));
        };
    }

    // ----- rated decisions -----

    /** The cause of a decision an administrator rated inadequate. */
    public static QualityCauseResult rated(QualityCauseDecision decision) {
        QualityCauseCheck grounding = grounding(decision.citations());
        List<QualityCauseCheck> checks = List.of(
                formatAndModel(decision),
                engineChanged(decision),
                inputError(decision.sourceTruth()),
                inputShortage(List.of(), decision.unknownFacts(), decision.contextLevel()),
                grounding,
                new QualityCauseCheck(QualityCause.UNSTABLE, QualityCauseCheck.State.NOT_COMPUTED, ONE_DECISION,
                        List.of()),
                judgement(grounding, decision));
        return result(null, checks);
    }

    private static QualityCauseCheck formatAndModel(QualityCauseDecision decision) {
        List<String> found = new ArrayList<>();
        if (QualityCauseDecision.SOURCE_MODEL_LESS.equals(decision.decisionSource())) {
            found.add(MODEL_LESS);
        }
        if (Boolean.FALSE.equals(decision.modelDecisionPresent())) {
            found.add(NO_ANSWER);
        }
        if (decision.timedOut()) {
            found.add(OVER_TIME_LIMIT);
        }
        if (decision.technicalFallback()) {
            found.add(TECHNICAL_FALLBACK);
        }
        if (decision.parserFailure()) {
            found.add(RESPONSE_FORMAT);
        }
        if (decision.modelUnavailable()) {
            found.add(MODEL_UNAVAILABLE);
        }
        if (!found.isEmpty()) {
            return applies(QualityCause.FORMAT_AND_MODEL, found, causeOf(decision));
        }
        if (decision.decisionSource() == null) {
            return new QualityCauseCheck(QualityCause.FORMAT_AND_MODEL, QualityCauseCheck.State.NOT_COMPUTED,
                    NO_DECISION_SOURCE, List.of());
        }
        return new QualityCauseCheck(QualityCause.FORMAT_AND_MODEL, QualityCauseCheck.State.CLEAR, MODEL_ANSWER_USED,
                List.of());
    }

    /**
     * A decision has no labelled answer: the model's proposal counts as the right one when the action the
     * administrator rated inadequate is not the model's but the one a rule of the engine changed it to.
     */
    private static QualityCauseCheck engineChanged(QualityCauseDecision decision) {
        String source = decision.decisionSource();
        if (source == null) {
            return new QualityCauseCheck(QualityCause.ENGINE_CHANGED, QualityCauseCheck.State.NOT_COMPUTED,
                    NO_DECISION_SOURCE, List.of());
        }
        if (!QualityCauseDecision.SOURCE_ENGINE_CHANGED.equals(source)) {
            return new QualityCauseCheck(QualityCause.ENGINE_CHANGED, QualityCauseCheck.State.CLEAR,
                    QualityCauseDecision.SOURCE_MODEL_LESS.equals(source) ? MODEL_LESS : MODEL_ACTION_STOOD,
                    List.of("source=" + source));
        }
        if (decision.proposedAction() == null) {
            return new QualityCauseCheck(QualityCause.ENGINE_CHANGED, QualityCauseCheck.State.NOT_COMPUTED,
                    NO_MODEL_ACTION, causeOf(decision));
        }
        if (decision.proposedAction() == decision.finalAction()) {
            return new QualityCauseCheck(QualityCause.ENGINE_CHANGED, QualityCauseCheck.State.CLEAR,
                    ACTION_NOT_CHANGED, List.of("model=" + decision.proposedAction()));
        }
        List<String> details = new ArrayList<>(List.of("model=" + decision.proposedAction(),
                "action=" + name(decision.finalAction())));
        details.addAll(causeOf(decision));
        return new QualityCauseCheck(QualityCause.ENGINE_CHANGED, QualityCauseCheck.State.APPLIES,
                MODEL_ACTION_CHANGED, details);
    }

    private static QualityCauseCheck inputError(QualityCauseDecision.SourceTruth truth) {
        return switch (truth.state()) {
            case NOT_SEALED -> new QualityCauseCheck(QualityCause.INPUT_ERROR, QualityCauseCheck.State.NOT_COMPUTED,
                    NOT_SEALED, List.of());
            case NOT_INSPECTED -> new QualityCauseCheck(QualityCause.INPUT_ERROR,
                    QualityCauseCheck.State.NOT_COMPUTED, NOT_INSPECTED, List.of());
            case INSPECTED -> {
                List<String> counts = List.of("matched=" + truth.matched(), "mismatched=" + truth.mismatched(),
                        "unverifiable=" + truth.unverifiable());
                if (truth.mismatched() > 0) {
                    yield new QualityCauseCheck(QualityCause.INPUT_ERROR, QualityCauseCheck.State.APPLIES,
                            SOURCE_MISMATCH, counts);
                }
                yield truth.matched() > 0
                        ? new QualityCauseCheck(QualityCause.INPUT_ERROR, QualityCauseCheck.State.CLEAR,
                        SOURCE_MATCHED, counts)
                        : new QualityCauseCheck(QualityCause.INPUT_ERROR, QualityCauseCheck.State.NOT_COMPUTED,
                        NOT_COMPARED, counts);
            }
        };
    }

    private static QualityCauseCheck judgement(QualityCauseCheck grounding, QualityCauseDecision decision) {
        return switch (grounding.state()) {
            case NOT_COMPUTED -> new QualityCauseCheck(QualityCause.JUDGEMENT_ERROR,
                    QualityCauseCheck.State.NOT_COMPUTED, CITATIONS_NOT_CHECKED, List.of());
            case APPLIES -> new QualityCauseCheck(QualityCause.JUDGEMENT_ERROR, QualityCauseCheck.State.CLEAR,
                    CITATION_WRONG, List.of());
            case CLEAR -> {
                List<String> details = new ArrayList<>(List.of("action=" + name(decision.finalAction())));
                if (decision.evaluationReason() != null) {
                    details.add("reason=" + decision.evaluationReason());
                }
                yield new QualityCauseCheck(QualityCause.JUDGEMENT_ERROR, QualityCauseCheck.State.APPLIES,
                        RATED_INADEQUATE, details);
            }
        };
    }

    // ----- rules both read -----

    /**
     * Input shortage: a deciding fact on the list of unknown facts, or a low context. Where no deciding fact is
     * listed, only the low context can be read, so the rule applies through it and is not computed otherwise.
     */
    private static QualityCauseCheck inputShortage(List<String> decidingFacts, List<String> unknownFacts,
                                                   String contextLevel) {
        boolean low = contextLevel != null && LOW_CONTEXT_LEVELS.contains(contextLevel.toUpperCase(Locale.ROOT));
        Set<String> unknown = unknownFacts.stream().map(QualityCauseClassifier::folded)
                .collect(Collectors.toCollection(LinkedHashSet::new));
        List<String> unknownDeciding = decidingFacts.stream()
                .filter(fact -> fact != null && namesUnknown(fact, unknown))
                .map(String::trim)
                .toList();
        List<String> details = new ArrayList<>();
        unknownDeciding.forEach(fact -> details.add("fact=" + fact));
        if (contextLevel != null) {
            details.add("level=" + contextLevel);
        }
        unknownFacts.forEach(fact -> details.add("unknown=" + fact));
        if (!unknownDeciding.isEmpty()) {
            return new QualityCauseCheck(QualityCause.INPUT_SHORTAGE, QualityCauseCheck.State.APPLIES,
                    DECIDING_FACT_UNKNOWN, details);
        }
        if (low) {
            return new QualityCauseCheck(QualityCause.INPUT_SHORTAGE, QualityCauseCheck.State.APPLIES,
                    CONTEXT_LEVEL_LOW, details);
        }
        if (decidingFacts.isEmpty()) {
            return new QualityCauseCheck(QualityCause.INPUT_SHORTAGE, QualityCauseCheck.State.NOT_COMPUTED,
                    NO_DECIDING_FACTS, details);
        }
        if (contextLevel == null) {
            return new QualityCauseCheck(QualityCause.INPUT_SHORTAGE, QualityCauseCheck.State.NOT_COMPUTED,
                    NO_CONTEXT_LEVEL, details);
        }
        return new QualityCauseCheck(QualityCause.INPUT_SHORTAGE, QualityCauseCheck.State.CLEAR,
                DECIDING_FACTS_KNOWN, details);
    }

    private static QualityCauseCheck grounding(QualityCauseCitations citations) {
        if (!citations.counted()) {
            return new QualityCauseCheck(QualityCause.GROUNDING_ERROR, QualityCauseCheck.State.NOT_COMPUTED,
                    CITATIONS_NOT_CHECKED, List.of());
        }
        if (citations.cited() == 0) {
            return new QualityCauseCheck(QualityCause.GROUNDING_ERROR, QualityCauseCheck.State.CLEAR, NO_CITATION,
                    List.of("cited=0"));
        }
        List<String> details = new ArrayList<>(List.of("cited=" + citations.cited(),
                "notInPrompt=" + citations.notInPrompt(), "doesNotSayIt=" + citations.notSayingIt()));
        for (QualityCauseCitations.Finding finding : citations.findings()) {
            if (!finding.present()) {
                details.add("notInPromptFact=" + finding.fact());
            }
            else if (QualityCauseCitations.MISMATCH.equals(finding.outcome())) {
                details.add("doesNotSayItFact=" + finding.fact());
            }
        }
        if (citations.notInPrompt() > 0) {
            return new QualityCauseCheck(QualityCause.GROUNDING_ERROR, QualityCauseCheck.State.APPLIES,
                    CITATION_NOT_IN_PROMPT, details);
        }
        if (citations.notSayingIt() > 0) {
            return new QualityCauseCheck(QualityCause.GROUNDING_ERROR, QualityCauseCheck.State.APPLIES,
                    CITATION_DOES_NOT_SAY_IT, details);
        }
        return new QualityCauseCheck(QualityCause.GROUNDING_ERROR, QualityCauseCheck.State.CLEAR, CITATIONS_RIGHT,
                details);
    }

    private static QualityCauseResult result(QualityCauseBasis basis, List<QualityCauseCheck> checks) {
        QualityCause cause = checks.stream().filter(QualityCauseCheck::applies).map(QualityCauseCheck::cause)
                .findFirst().orElse(QualityCause.UNCLASSIFIED);
        return new QualityCauseResult(cause, basis, checks);
    }

    /**
     * A check that applies: its reason is the first that was found, and its details name every reason found, then the
     * values read.
     */
    private static QualityCauseCheck applies(QualityCause cause, List<String> found, List<String> values) {
        List<String> details = new ArrayList<>();
        found.forEach(reason -> details.add("reason=" + reason));
        details.addAll(values);
        return new QualityCauseCheck(cause, QualityCauseCheck.State.APPLIES, found.get(0), details);
    }

    private static List<String> causeOf(QualityCauseDecision decision) {
        return decision.changeCause() != null ? List.of("cause=" + decision.changeCause()) : List.of();
    }

    /**
     * Whether the deciding fact names a fact of the unknown ones: the fact itself, or a part of its path before
     * {@code =}, is that fact's name, ignoring case. {@code OnCall} and {@code frictionProfile.onCall.onCall=false}
     * both name the unknown fact {@code OnCall}.
     */
    private static boolean namesUnknown(String decidingFact, Set<String> unknown) {
        String fact = decidingFact.trim();
        int equals = fact.indexOf('=');
        String path = equals < 0 ? fact : fact.substring(0, equals).trim();
        if (unknown.contains(folded(path))) {
            return true;
        }
        for (String part : path.split("\\.")) {
            if (!part.isBlank() && unknown.contains(folded(part))) {
                return true;
            }
        }
        return false;
    }

    private static String folded(String fact) {
        return fact.trim().toLowerCase(Locale.ROOT);
    }

    private static String name(QualityAction action) {
        return action != null ? action.name() : "NONE";
    }
}
