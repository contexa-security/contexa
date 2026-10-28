package io.contexa.showcase.portal.scenario;

import java.util.ArrayList;
import java.util.List;

/**
 * docs/agent Agent중심-화면 AS-13, AC-7b: the live burst. The case {@link #BURST_CASE} sends the same request from many workers
 * at once (sixty in the stored measurement); a visitor may send it live only up to {@link #LIVE_MOST} workers, and the
 * portal refuses more. The number is set in a copy of the case: the case itself, which the stored measurement ran, and
 * every other run are not touched.
 */
public final class BurstChoice {

    /** The case a visitor may send a burst of. */
    public static final String BURST_CASE = "M41A";

    /** The most workers a live burst has. */
    public static final int LIVE_MOST = 10;

    private BurstChoice() {
    }

    /** Whether the case sends workers beside the agent (a burst of requests at once). */
    public static boolean isBurst(ScenarioDefinition scenario) {
        return scenario.task() != null && scenario.task().parallel() != null && !scenario.task().parallel().isEmpty();
    }

    /**
     * The case with its workers set to the number: a copy. No number gives the case itself.
     *
     * @throws IllegalArgumentException for a number outside 1 to {@link #LIVE_MOST}, or on a case that is not the burst case
     */
    public static ScenarioDefinition apply(ScenarioDefinition scenario, Integer copies) {
        if (copies == null) {
            return scenario;
        }
        if (!BURST_CASE.equals(scenario.key()) || !isBurst(scenario)) {
            throw new IllegalArgumentException("The case " + scenario.key() + " takes no number of workers");
        }
        if (copies < 1 || copies > LIVE_MOST) {
            throw new IllegalArgumentException("A live burst has 1 to " + LIVE_MOST + " requests at once: " + copies);
        }
        List<ScenarioDefinition.AgentTask.ParallelWork> workers = new ArrayList<>();
        for (ScenarioDefinition.AgentTask.ParallelWork work : scenario.task().parallel()) {
            workers.add(new ScenarioDefinition.AgentTask.ParallelWork(work.startAfterToolCalls(), copies, work.runtime(),
                    work.requests()));
        }
        return new ScenarioDefinition(scenario.key(), scenario.version(), scenario.title(), scenario.protagonist(),
                scenario.template(), scenario.timeSlot(), scenario.device(), scenario.pace(), scenario.facts(),
                scenario.steps(), scenario.oracle(), scenario.network(), scenario.frozenOn(), scenario.suite(),
                scenario.agent(), scenario.task().withParallel(workers));
    }
}
