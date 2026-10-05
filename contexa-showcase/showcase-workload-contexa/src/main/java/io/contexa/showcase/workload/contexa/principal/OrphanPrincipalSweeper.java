package io.contexa.showcase.workload.contexa.principal;

import io.contexa.contexacore.autonomous.service.UserEngineStatePurger;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.scheduling.annotation.Scheduled;

import java.time.Clock;
import java.time.Instant;
import java.util.Set;
import java.util.TreeSet;
import java.util.concurrent.atomic.AtomicLong;
import java.util.concurrent.atomic.AtomicReference;

/**
 * Purges the engine state of run principals whose account no longer exists. The engine stores the memory document
 * of a decision on a separate executor after it has written the decision record
 * (SecurityLearningService.postProcessDecision), so a run that is cleaned up right after its last decision can see
 * that document written after the purge. The security bridge's mirror user of a run principal is found the same way
 * (a bridge-managed user whose external subject is a run principal without an account). Run principal names are never
 * reused, so a principal without an account is always a finished run and purging it again is safe (P1-BE-09 T8,
 * retention in docs/showcase).
 */
public class OrphanPrincipalSweeper {

    private static final Logger log = LoggerFactory.getLogger(OrphanPrincipalSweeper.class);

    /** Run and template principals: "v" + 12 hex characters + "-" + employee key. */
    public static final String PRINCIPAL_PATTERN = "^v[0-9a-f]{12}-[a-z]{2,3}-[a-z0-9]{1,3}$";

    public record SweepState(long sweeps, long purgedPrincipals, Instant lastSweepAt) {
    }

    private final JdbcTemplate vectorDatabase;
    private final JdbcTemplate engine;
    private final UserEngineStatePurger purger;
    private final Clock clock;
    private final AtomicLong sweeps = new AtomicLong();
    private final AtomicLong purged = new AtomicLong();
    private final AtomicReference<Instant> lastSweepAt = new AtomicReference<>();

    public OrphanPrincipalSweeper(JdbcTemplate vectorDatabase, JdbcTemplate engine, UserEngineStatePurger purger,
                                  Clock clock) {
        this.vectorDatabase = vectorDatabase;
        this.engine = engine;
        this.purger = purger;
        this.clock = clock;
    }

    @Scheduled(initialDelay = 60_000, fixedDelay = 60_000)
    public void sweep() {
        try {
            Set<String> owners = new TreeSet<>(vectorDatabase.queryForList("""
                    select distinct metadata::jsonb ->> 'userId' from vector_store
                     where metadata::jsonb ->> 'userId' ~ ?""", String.class, PRINCIPAL_PATTERN));
            owners.addAll(engine.queryForList("""
                    select distinct external_subject_id from users
                     where bridge_managed and external_subject_id ~ ?""", String.class, PRINCIPAL_PATTERN));
            for (String owner : owners) {
                Integer accounts = engine.queryForObject("select count(*) from users where username = ?",
                        Integer.class, owner);
                if (accounts != null && accounts == 0) {
                    purger.purge(owner);
                    purged.incrementAndGet();
                }
            }
            sweeps.incrementAndGet();
            lastSweepAt.set(clock.instant());
        } catch (RuntimeException e) {
            log.error("Orphan run principal sweep failed", e);
        }
    }

    public SweepState state() {
        return new SweepState(sweeps.get(), purged.get(), lastSweepAt.get());
    }
}
