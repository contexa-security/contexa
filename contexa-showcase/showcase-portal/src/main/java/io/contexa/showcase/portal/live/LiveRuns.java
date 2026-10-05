package io.contexa.showcase.portal.live;

import io.contexa.showcase.portal.orchestrator.ChallengeResponder;
import io.contexa.showcase.portal.orchestrator.RunListener;
import io.contexa.showcase.portal.orchestrator.RunOrchestrator.RunSummary;
import io.contexa.showcase.portal.scenario.ScenarioDefinition;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.security.SecureRandom;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Deque;
import java.util.HashMap;
import java.util.HexFormat;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.function.Consumer;

/**
 * Visitor spaces of live runs (deck p.27, docs/showcase/P4-설계.md 2절): each visitor has one space with at most one
 * live run, up to {@code maxConcurrent} runs go at once and the next visitors wait in a queue that tells them their
 * place. A space ends after its lifetime or when its visitor has been inactive; a run still waiting then leaves the
 * queue. Every run takes a fresh run principal that the orchestrator cleans afterwards, so nothing of one visitor
 * reaches another.
 */
public class LiveRuns implements AutoCloseable {

    private static final Logger log = LoggerFactory.getLogger(LiveRuns.class);

    /**
     * @param scenarioKeys scenarios offered on the "try it yourself" page; cells of the grid are always offered
     * @param forcedAction development-only forced decision (approval Q-23), null for the engine's own decisions
     */
    public record Settings(int maxConcurrent, int maxQueue, Duration lifetime, Duration inactivity,
                           List<String> scenarioKeys, String forcedAction) {
    }

    /** No live run can start or wait now: the queue is full. */
    public static final class Busy extends RuntimeException {
        Busy() {
            super("The live runs and their queue are full");
        }
    }

    private static final class Space {
        private final Instant created;
        private Instant lastActive;
        private LiveRun current;

        private Space(Instant now) {
            this.created = now;
            this.lastActive = now;
        }
    }

    private record Pending(LiveRun run, ScenarioDefinition scenario, Consumer<RunSummary> onFinish) {
    }

    /** Runs one scenario with the visitor answering control D's check; the orchestrator in production. */
    @FunctionalInterface
    public interface Runner {
        RunSummary run(ScenarioDefinition scenario, String forcedAction, ChallengeResponder responder,
                       RunListener listener);
    }

    private final Runner runner;
    private final Settings settings;
    private final Clock clock;
    private final SecureRandom random = new SecureRandom();
    private final ExecutorService executor = Executors.newCachedThreadPool(runnable -> {
        Thread thread = new Thread(runnable, "showcase-live-run");
        thread.setDaemon(true);
        return thread;
    });
    private final Map<String, Space> spaces = new HashMap<>();
    private final Deque<Pending> waiting = new ArrayDeque<>();
    private int running;

    public LiveRuns(Runner runner, Settings settings, Clock clock) {
        this.runner = runner;
        this.settings = settings;
        this.clock = clock;
    }

    public Settings settings() {
        return settings;
    }

    /**
     * Starts the visitor's live run, or puts it in the queue. A visitor whose run is still going gets that run back.
     *
     * @param onFinish hears the finished run, for example to keep it as a combination record
     */
    public synchronized LiveRun start(String visitor, ScenarioDefinition scenario, Consumer<RunSummary> onFinish) {
        Space space = touch(visitor);
        if (space.current != null && space.current.active()) {
            return space.current;
        }
        if (running >= settings.maxConcurrent() && waiting.size() >= settings.maxQueue()) {
            throw new Busy();
        }
        LiveRun run = new LiveRun("live-" + HexFormat.of().formatHex(bytes()), visitor, scenario.key(), clock);
        space.current = run;
        Pending pending = new Pending(run, scenario, onFinish);
        if (running < settings.maxConcurrent()) {
            launch(pending);
        } else {
            waiting.add(pending);
            renumber();
        }
        return run;
    }

    /** The visitor's live run; another visitor's run is never shown. Reading it keeps the space alive. */
    public synchronized Optional<LiveRun> current(String visitor) {
        Space space = spaces.get(visitor);
        if (space == null) {
            return Optional.empty();
        }
        space.lastActive = clock.instant();
        return Optional.ofNullable(space.current);
    }

    public synchronized boolean hasRoom() {
        return running < settings.maxConcurrent() || waiting.size() < settings.maxQueue();
    }

    public synchronized int running() {
        return running;
    }

    public synchronized int waiting() {
        return waiting.size();
    }

    public synchronized int spaces() {
        return spaces.size();
    }

    /** Ends spaces past their lifetime or inactive too long; their queued runs leave the queue. */
    public synchronized int sweep() {
        Instant now = clock.instant();
        int removed = 0;
        Iterator<Map.Entry<String, Space>> entries = spaces.entrySet().iterator();
        while (entries.hasNext()) {
            Space space = entries.next().getValue();
            boolean over = space.created.plus(settings.lifetime()).isBefore(now)
                    || space.lastActive.plus(settings.inactivity()).isBefore(now);
            if (!over) {
                continue;
            }
            LiveRun current = space.current;
            if (current != null && current.status() == LiveRun.Status.QUEUED) {
                waiting.removeIf(pending -> pending.run() == current);
                current.expire();
            } else if (current != null && current.active()) {
                // A run in progress finishes on its own; its space goes once it is done.
                continue;
            }
            entries.remove();
            removed++;
        }
        renumber();
        return removed;
    }

    @Override
    public void close() {
        executor.shutdownNow();
    }

    private Space touch(String visitor) {
        Space space = spaces.computeIfAbsent(visitor, key -> new Space(clock.instant()));
        space.lastActive = clock.instant();
        return space;
    }

    private void launch(Pending pending) {
        running++;
        pending.run().starting();
        executor.execute(() -> {
            RunSummary summary = null;
            try {
                summary = runner.run(pending.scenario(), settings.forcedAction(), pending.run(), pending.run());
                pending.run().finish(summary);
            } catch (RuntimeException e) {
                log.error("Live run failed: scenario={}", pending.scenario().key(), e);
                pending.run().fail(e.getClass().getSimpleName());
            } finally {
                released();
            }
            if (summary != null) {
                try {
                    pending.onFinish().accept(summary);
                } catch (RuntimeException e) {
                    log.error("Live run follow-up failed: run={}", summary.runId(), e);
                }
            }
        });
    }

    private synchronized void released() {
        running--;
        Pending next = waiting.poll();
        if (next != null) {
            launch(next);
        }
        renumber();
    }

    private void renumber() {
        List<Pending> queue = new ArrayList<>(waiting);
        for (int i = 0; i < queue.size(); i++) {
            queue.get(i).run().queued(i + 1);
        }
    }

    private byte[] bytes() {
        byte[] bytes = new byte[6];
        random.nextBytes(bytes);
        return bytes;
    }
}
