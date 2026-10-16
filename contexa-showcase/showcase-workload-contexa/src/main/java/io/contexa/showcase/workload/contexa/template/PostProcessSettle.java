package io.contexa.showcase.workload.contexa.template;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.time.Duration;
import java.util.concurrent.Executor;
import java.util.concurrent.ThreadPoolExecutor;

/**
 * Waits until the engine's learning post process executor has no queued or running task (N-RUNLEARN-1). The engine
 * stores the decision document of a request there once its decision is enforced (W5-3), with an embedding call, so the
 * documents of a run's last requests can be stored after the run's last decision is read, and a snapshot taken at once
 * would miss them. The executor counts as idle once it stays so for the quiet time, which also covers a task handed
 * over a moment after the decision is recorded. An executor whose work cannot be seen is not waited for.
 */
final class PostProcessSettle {

    private static final Logger log = LoggerFactory.getLogger(PostProcessSettle.class);
    private static final long POLL_MS = 50L;

    private final Executor executor;
    private final Duration limit;
    private final Duration quiet;

    PostProcessSettle(Executor executor, Duration limit, Duration quiet) {
        this.executor = executor;
        this.limit = limit;
        this.quiet = quiet;
    }

    /** True once the executor stayed idle for the quiet time; false when the limit passed first. */
    boolean await() {
        if (!(executor instanceof ThreadPoolExecutor pool)) {
            return true;
        }
        long deadline = System.nanoTime() + limit.toNanos();
        long idleSince = -1L;
        while (true) {
            long now = System.nanoTime();
            if (pool.getActiveCount() == 0 && pool.getQueue().isEmpty()) {
                if (idleSince < 0L) {
                    idleSince = now;
                }
                if (now - idleSince >= quiet.toNanos()) {
                    return true;
                }
            }
            else {
                idleSince = -1L;
            }
            if (now - deadline >= 0L) {
                log.error("The engine's learning post process did not settle within {} ms; the snapshot is taken as it is",
                        limit.toMillis());
                return false;
            }
            try {
                Thread.sleep(POLL_MS);
            }
            catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                return false;
            }
        }
    }
}
