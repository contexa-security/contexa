package io.contexa.showcase.portal.journey;

import io.contexa.showcase.portal.journey.JourneyStore.State;
import io.contexa.showcase.portal.journey.JourneyStore.VisitorRun;
import io.contexa.showcase.portal.scenario.ScenarioCatalog;
import io.contexa.showcase.portal.scenario.ScenarioDefinition;
import io.contexa.showcase.portal.scoring.RunScores;
import io.contexa.showcase.portal.scoring.RunScores.RunScore;
import io.contexa.showcase.portal.scoring.Scoring.BusinessResult;
import io.contexa.showcase.portal.scoring.Scoring.CaseScore;

import java.time.Clock;
import java.time.Instant;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;
import java.util.TreeSet;
import java.util.regex.Pattern;

/**
 * The visitor's journey (work 14 of docs/showcase/화면설계서-v2-구현계획.md): where the visitor is, kept on the server
 * so a reload or another tab returns to the same place, and "what you did" built from the visitor's own runs. The
 * visitor's calls are scored against the case's ground truth and the visitor's own run by the server.
 */
public class JourneyViews {

    /** The case each experience sends (decision 2). */
    static final Map<String, String> EXPERIENCE_CASES = Map.of("E1", "A3", "E2", "A3T");
    static final Set<String> ROUTES = Set.of("DEFAULT", "INTRO");
    static final Set<String> ENGINE_CALLS = Set.of("ALLOW", "CHALLENGE", "ESCALATE", "BLOCK");
    static final Set<String> EXISTING_CALLS = Set.of("ALL", "SOME", "NONE");
    static final Set<String> NUMBER_RULE_CALLS = Set.of("STOP", "PASS");
    static final Pattern STEP = Pattern.compile("[a-z0-9-]{1,40}");
    static final List<String> EXISTING_CONTROLS = List.of("A", "B", "C1", "C2");

    /** A change of the journey; absent fields stay as they were. */
    public record Update(String route, Integer act, String step, Integer difference, Prediction prediction) {
    }

    /**
     * The visitor's call before sending an experience.
     *
     * @param engine     what Contexa should do: ALLOW, CHALLENGE, ESCALATE or BLOCK
     * @param existing   whether the four existing approaches stop it: ALL, SOME or NONE
     * @param numberRule whether the number rule stops it (experience 2): STOP or PASS
     */
    public record Prediction(String experience, String engine, String existing, String numberRule) {
    }

    /**
     * One line of "what you did": a run the visitor sent, with every approach's business result as recorded.
     *
     * @param engineAction   the first decision Contexa made in the run; null when it made none
     * @param correct        whether Contexa's result is right by the case's ground truth; null when it is neither
     * @param requestedItems the items the case's first step asks for, as its definition says; null without a count
     * @param steps          the number of requests the case sends, as its definition says; 0 when it is unknown
     * @param startedAt      when the run started, as recorded (the source mark's recorded time)
     */
    public record RecapLine(String runId, String scenarioKey, String classification, String status, boolean lab,
                            Map<String, String> business, String engineAction, long exposedItems, Boolean correct,
                            Integer requestedItems, int steps, Instant startedAt) {
    }

    /**
     * The visitor's call against the record.
     *
     * @param engineRight      whether the engine call is one the case's ground truth counts as right
     * @param existingActual   how many of the four existing approaches stopped the visitor's latest run of the case
     *                         (ALL, SOME, NONE); null before the visitor sent it
     * @param numberRuleActual whether the number rule stopped that run (STOP, PASS); null before
     */
    public record PredictionScore(String experience, String caseKey, Prediction call, Boolean engineRight,
                                  String existingActual, String numberRuleActual, String runId) {
    }

    public record View(State state, List<RecapLine> runs, List<PredictionScore> predictions) {
    }

    /**
     * A question of the understanding check (quiz). The answer stays on the server.
     *
     * @param revisit the difference (1 to 6) whose screen a wrong answer leads back to
     */
    record Question(String id, List<String> options, String answer, int revisit) {
    }

    /** The questions as a visitor sees them: the options without the answer. */
    public record QuestionView(String id, List<String> options) {
    }

    public record QuizAnswer(String question, String answer, boolean right, String correct, int revisit) {
    }

    /** @param counted whether these answers entered the anonymous counts (a visitor's first answers only) */
    public record QuizResult(List<QuizAnswer> answers, int right, int total, boolean counted) {
    }

    /** The three questions of the quiz screen (7.4 of the plan): what it judges by, why work 2 went, which timing. */
    static final List<Question> QUESTIONS = List.of(
            new Question("Q1", List.of("CREDENTIALS", "USUAL_AND_COMPANY", "ATTACK_STRING"), "USUAL_AND_COMPANY", 2),
            new Question("Q2", List.of("SAME_AS_USUAL", "COMPANY_APPROVAL", "PASSWORD"), "COMPANY_APPROVAL", 3),
            new Question("Q3", List.of("ASYNC", "SYNC"), "SYNC", 1));

    private final JourneyStore store;
    private final RunScores scores;
    private final ScenarioCatalog scenarios;
    private final AnonymousTally tally;
    private final Clock clock;

    public JourneyViews(JourneyStore store, RunScores scores, ScenarioCatalog scenarios, AnonymousTally tally,
                        Clock clock) {
        this.store = store;
        this.scores = scores;
        this.scenarios = scenarios;
        this.tally = tally;
        this.clock = clock;
    }

    public List<QuestionView> questions() {
        return QUESTIONS.stream().map(question -> new QuestionView(question.id(), question.options())).toList();
    }

    /**
     * Scores the visitor's answers on the server. A visitor's first answers are counted anonymously, one count per
     * answered question, with no visitor in the count (ADR-35); empty when an answer is not one of the options.
     */
    public synchronized Optional<QuizResult> answer(String visitor, Map<String, String> answers) {
        if (answers == null || answers.isEmpty()) {
            return Optional.empty();
        }
        List<QuizAnswer> scored = new ArrayList<>();
        for (Question question : QUESTIONS) {
            String answer = answers.get(question.id());
            if (answer == null) {
                continue;
            }
            if (!question.options().contains(answer)) {
                return Optional.empty();
            }
            scored.add(new QuizAnswer(question.id(), answer, question.answer().equals(answer), question.answer(),
                    question.revisit()));
        }
        if (scored.isEmpty() || answers.size() != scored.size()) {
            return Optional.empty();
        }
        State current = store.state(visitor).orElse(initial());
        boolean counted = !current.quizAnswered();
        if (counted) {
            scored.forEach(answer -> tally.count(AnonymousTally.QUIZ, answer.question(),
                    answer.right() ? "RIGHT" : "WRONG"));
            store.save(visitor, new State(current.route(), current.act(), current.step(), current.differences(),
                    current.predictions(), current.actsReached(), true, clock.instant()));
        }
        int right = (int) scored.stream().filter(QuizAnswer::right).count();
        return Optional.of(new QuizResult(scored, right, scored.size(), counted));
    }

    public View view(String visitor) {
        State state = store.state(visitor).orElse(initial());
        List<VisitorRun> runs = store.runs(visitor);
        Map<String, RunScore> scored = new HashMap<>();
        scores.scoreAll(runs.stream().map(VisitorRun::runId).toList())
                .forEach(score -> scored.put(score.runId(), score));
        List<RecapLine> lines = new ArrayList<>();
        for (VisitorRun run : runs) {
            RunScore score = scored.get(run.runId());
            if (score != null) {
                lines.add(line(run, score));
            }
        }
        List<PredictionScore> predictions = new ArrayList<>();
        state.predictions().forEach((experience, call) -> predictions.add(score(experience, call, runs, scored)));
        return new View(state, lines, predictions);
    }

    /**
     * Applies a change; empty when it is invalid, so nothing is stored. The first time the visitor reaches an act it is
     * counted anonymously (ADR-35).
     */
    public synchronized Optional<View> update(String visitor, Update update) {
        if (update == null || !valid(update)) {
            return Optional.empty();
        }
        State current = store.state(visitor).orElse(initial());
        TreeSet<Integer> differences = new TreeSet<>(current.differences());
        if (update.difference() != null) {
            differences.add(update.difference());
        }
        Map<String, Map<String, String>> predictions = new LinkedHashMap<>(current.predictions());
        if (update.prediction() != null) {
            Map<String, String> call = new LinkedHashMap<>();
            putIfPresent(call, "engine", update.prediction().engine());
            putIfPresent(call, "existing", update.prediction().existing());
            putIfPresent(call, "numberRule", update.prediction().numberRule());
            predictions.put(update.prediction().experience(), call);
        }
        TreeSet<Integer> acts = new TreeSet<>(current.actsReached());
        if (update.act() != null && update.act() > 0 && acts.add(update.act())) {
            tally.count(AnonymousTally.ACT_REACHED, String.valueOf(update.act()), "-");
        }
        store.save(visitor, new State(update.route() == null ? current.route() : update.route(),
                update.act() == null ? current.act() : update.act(),
                update.step() == null ? current.step() : update.step(), List.copyOf(differences), predictions,
                List.copyOf(acts), current.quizAnswered(), clock.instant()));
        return Optional.of(view(visitor));
    }

    static boolean valid(Update update) {
        if (update.route() != null && !ROUTES.contains(update.route())) {
            return false;
        }
        if (update.act() != null && (update.act() < 0 || update.act() > 4)) {
            return false;
        }
        if (update.step() != null && !STEP.matcher(update.step()).matches()) {
            return false;
        }
        if (update.difference() != null && (update.difference() < 1 || update.difference() > 6)) {
            return false;
        }
        Prediction prediction = update.prediction();
        if (prediction == null) {
            return true;
        }
        return EXPERIENCE_CASES.containsKey(prediction.experience())
                && (prediction.engine() == null || ENGINE_CALLS.contains(prediction.engine()))
                && (prediction.existing() == null || EXISTING_CALLS.contains(prediction.existing()))
                && (prediction.numberRule() == null || NUMBER_RULE_CALLS.contains(prediction.numberRule()));
    }

    private State initial() {
        return new State("DEFAULT", 0, "start", List.of(), Map.of(), List.of(), false, clock.instant());
    }

    private RecapLine line(VisitorRun run, RunScore score) {
        Map<String, String> business = new LinkedHashMap<>();
        score.business().forEach((control, result) -> business.put(control, result.result().name()));
        CaseScore engine = score.business().get("D");
        String action = score.verdicts().stream().map(verdict -> verdict.score().finalAction())
                .filter(Objects::nonNull).findFirst().orElse(null);
        Optional<ScenarioDefinition> definition = scenarios.find(run.scenarioKey());
        Integer requested = definition.filter(found -> !found.steps().isEmpty())
                .map(found -> found.steps().get(0).items()).orElse(null);
        return new RecapLine(run.runId(), run.scenarioKey(), score.truth().classification(), run.status(), run.lab(),
                business, action, engine == null ? 0 : engine.exposedItems(), score.correct().get("D"), requested,
                definition.map(found -> found.steps().size()).orElse(0), run.startedAt());
    }

    private PredictionScore score(String experience, Map<String, String> call, List<VisitorRun> runs,
                                  Map<String, RunScore> scored) {
        String caseKey = EXPERIENCE_CASES.get(experience);
        Prediction prediction = new Prediction(experience, call.get("engine"), call.get("existing"),
                call.get("numberRule"));
        Boolean engineRight = prediction.engine() == null ? null : scenarios.find(caseKey)
                .map(ScenarioDefinition::oracle)
                .map(oracle -> oracle.allowedEngineActions().contains(prediction.engine())).orElse(null);
        RunScore latest = null;
        for (VisitorRun run : runs) {
            if (run.scenarioKey().equals(caseKey) && !run.lab() && scored.containsKey(run.runId())) {
                latest = scored.get(run.runId());
            }
        }
        if (latest == null) {
            return new PredictionScore(experience, caseKey, prediction, engineRight, null, null, null);
        }
        int stopping = 0;
        for (String control : EXISTING_CONTROLS) {
            if (stopped(latest.business().get(control))) {
                stopping++;
            }
        }
        String existing = stopping == EXISTING_CONTROLS.size() ? "ALL" : stopping == 0 ? "NONE" : "SOME";
        String numberRule = stopped(latest.business().get("C1")) ? "STOP" : "PASS";
        return new PredictionScore(experience, caseKey, prediction, engineRight, existing, numberRule,
                latest.runId());
    }

    /** An approach stopped the request: the attack or the work did not go through. */
    static boolean stopped(CaseScore result) {
        return result != null && (result.result() == BusinessResult.STOPPED
                || result.result() == BusinessResult.PARTLY_STOPPED || result.result() == BusinessResult.HALTED);
    }

    private static void putIfPresent(Map<String, String> map, String key, String value) {
        if (value != null) {
            map.put(key, value);
        }
    }
}
