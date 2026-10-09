package io.contexa.showcase.portal.hook;

import io.contexa.showcase.portal.hook.HookStore.Designated;
import io.contexa.showcase.portal.hook.HookStore.RunFacts;
import io.contexa.showcase.portal.hook.HookStore.Slot;
import io.contexa.showcase.portal.replay.ReplayView;
import io.contexa.showcase.portal.replay.ReplayViews;
import io.contexa.showcase.portal.scoring.RunScores;
import io.contexa.showcase.portal.scoring.RunScores.RunScore;
import io.contexa.showcase.portal.scoring.Scoring.BusinessResult;
import io.contexa.showcase.portal.scoring.Scoring.CaseScore;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.TreeMap;

/**
 * The first screen's replay (work 17 of docs/showcase/화면설계서-v2-구현계획.md): the designated representative run of
 * each case with every approach's recorded result, and the same measurement's runs of the case counted by the server,
 * so the line under each column ("the same in all three", "one of three went on after the check") is a count.
 */
public class HookViews {

    /** The request the columns replay; both cases have one. */
    static final int STEP = 1;

    /**
     * @param results          control D's business result over the measurement's runs of the case, by result name
     * @param sameResult       runs whose control D result is the representative run's
     * @param passedAfterCheck runs whose work went on after the additional check was answered
     */
    public record Measurement(String protocolId, int runs, int sameResult, int passedAfterCheck,
                              Map<String, Long> results) {
    }

    /**
     * @param business control D's business result of the representative run
     * @param correct  whether each approach answered the case right by the one scoring rule; an approach left out is
     *                 neither
     * @param check    the additional check control D asked for at the replayed request; null without one
     */
    public record Column(String caseKey, String runId, Instant startedAt, ReplayView.StepResult result,
                         String business, Map<String, Boolean> correct, RunScores.Check check,
                         Measurement measurement) {
    }

    /**
     * @param distinguished  every measured attacker run was stopped and every measured real-employee run went through:
     *                       the condition of the screen's sentence that the two were told apart without a rule
     *                       written for them (section 8 of the plan)
     * @param textsKeptUntil when the first of the two runs' model call texts reaches the retention period
     */
    public record View(Column attacker, Column owner, boolean distinguished, Instant textsKeptUntil) {
    }

    /** Why a designation was refused; nothing is stored then. */
    public record Refusal(String slot, String reason) {
    }

    private final HookStore store;
    private final ReplayViews replays;
    private final RunScores scores;
    private final Duration textRetention;
    private final Clock clock;

    public HookViews(HookStore store, ReplayViews replays, RunScores scores, Duration textRetention, Clock clock) {
        this.store = store;
        this.replays = replays;
        this.scores = scores;
        this.textRetention = textRetention;
        this.clock = clock;
    }

    /** The replay of the designated runs; empty until both are designated. */
    public Optional<View> view() {
        Map<Slot, Designated> designated = store.designated();
        if (!designated.containsKey(Slot.ATTACKER) || !designated.containsKey(Slot.OWNER)) {
            return Optional.empty();
        }
        Optional<RunFacts> attacker = store.facts(designated.get(Slot.ATTACKER).runId());
        Optional<RunFacts> owner = store.facts(designated.get(Slot.OWNER).runId());
        if (attacker.isEmpty() || owner.isEmpty()) {
            return Optional.empty();
        }
        Column attackerColumn = column(Slot.ATTACKER, attacker.get());
        Column ownerColumn = column(Slot.OWNER, owner.get());
        return Optional.of(new View(attackerColumn, ownerColumn, distinguished(attackerColumn, ownerColumn),
                keptUntil(attacker.get(), owner.get())));
    }

    static boolean distinguished(Column attacker, Column owner) {
        return !attacker.measurement().results().isEmpty() && !owner.measurement().results().isEmpty()
                && attacker.measurement().results().keySet().stream()
                .allMatch(result -> result.equals(BusinessResult.STOPPED.name()))
                && owner.measurement().results().keySet().stream()
                .allMatch(result -> result.equals(BusinessResult.PASSED.name())
                        || result.equals(BusinessResult.PASSED_AFTER_CHECK.name()));
    }

    /**
     * Designates the two representative runs together: measured, completed, unforced runs of the slots' cases in the
     * same measurement, whose model call texts are still kept.
     */
    public Optional<Refusal> designate(String attackerRunId, String ownerRunId) {
        Optional<RunFacts> attacker = attackerRunId == null ? Optional.empty() : store.facts(attackerRunId);
        Optional<RunFacts> owner = ownerRunId == null ? Optional.empty() : store.facts(ownerRunId);
        Optional<Refusal> refused = check(Slot.ATTACKER, attacker).or(() -> check(Slot.OWNER, owner));
        if (refused.isPresent()) {
            return refused;
        }
        if (!attacker.get().protocolId().equals(owner.get().protocolId())) {
            return Optional.of(new Refusal(Slot.OWNER.name(), "DIFFERENT_MEASUREMENT"));
        }
        Instant now = clock.instant();
        store.designate(Slot.ATTACKER, attackerRunId, now);
        store.designate(Slot.OWNER, ownerRunId, now);
        return Optional.empty();
    }

    Optional<Refusal> check(Slot slot, Optional<RunFacts> facts) {
        if (facts.isEmpty()) {
            return Optional.of(new Refusal(slot.name(), "UNKNOWN_RUN"));
        }
        RunFacts run = facts.get();
        String reason;
        if (!slot.caseKey().equals(run.scenarioKey())) {
            reason = "WRONG_CASE";
        } else if (!"COMPLETED".equals(run.status())) {
            reason = "NOT_COMPLETED";
        } else if (run.forcedAction() != null) {
            reason = "FORCED";
        } else if (run.protocolId() == null) {
            reason = "NOT_MEASURED";
        } else if (run.firstTextAt() == null || !clock.instant().isBefore(run.firstTextAt().plus(textRetention))) {
            reason = "TEXTS_GONE";
        } else {
            return Optional.empty();
        }
        return Optional.of(new Refusal(slot.name(), reason));
    }

    private Column column(Slot slot, RunFacts run) {
        List<RunScore> scored = scores.scoreAll(store.measurementRuns(run.protocolId(), slot.caseKey()));
        RunScore representative = scores.score(run.runId()).orElseThrow();
        String business = businessOf(representative);
        Map<String, Long> results = new TreeMap<>();
        int same = 0;
        int afterCheck = 0;
        for (RunScore score : scored) {
            String result = businessOf(score);
            results.merge(result == null ? "NONE" : result, 1L, Long::sum);
            if (result != null && result.equals(business)) {
                same++;
            }
            if (BusinessResult.PASSED_AFTER_CHECK.name().equals(result)) {
                afterCheck++;
            }
        }
        RunScores.Check check = representative.checks().stream().filter(candidate -> candidate.stepNo() == STEP)
                .findFirst().orElse(null);
        return new Column(slot.caseKey(), run.runId(), run.startedAt(), replays.step(run.runId(), STEP), business,
                representative.correct(), check,
                new Measurement(run.protocolId(), scored.size(), same, afterCheck, results));
    }

    private static String businessOf(RunScore score) {
        CaseScore result = score.business().get("D");
        return result == null ? null : result.result().name();
    }

    private Instant keptUntil(RunFacts attacker, RunFacts owner) {
        Instant first = attacker.firstTextAt();
        if (first == null || (owner.firstTextAt() != null && owner.firstTextAt().isBefore(first))) {
            first = owner.firstTextAt();
        }
        return first == null ? null : first.plus(textRetention);
    }
}
